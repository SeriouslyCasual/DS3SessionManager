//! The relay wrapper's header, and the link-layer frames it arrives in.
//!
//! In E2 mode, some relayed players' packets reach this PC wrapped by a
//! nearby Steam relay in a pre-TURN message in the RFC 3489 style (as in
//! libjingle's GTURN): a **data indication** (type `0x0115`) with a relay
//! cookie (`0x000F`), the **source address** (`0x0012`) and the original
//! packet in a DATA attribute (`0x0013`).
//!
//! `0x0012` is the other player's public IP:port as the relay sees it,
//! unencrypted and not XOR-ed. Checked against packet captures on the LAN
//! (E2/E3) and online (2026-11-15: all 16 addresses seen were players, none a
//! relay; one equalled the IP Steam itself reported for that player, another
//! kept the player's LAN port).
//!
//! Only this header is parsed. The DATA attribute (the game's own payload)
//! is never read or kept.

use std::net::{Ipv4Addr, SocketAddrV4};

/// Message type of a relay data indication (relay to this PC).
pub const DATA_INDICATION: u16 = 0x0115;
const ATTR_SOURCE: u16 = 0x0012;
const ATTR_DATA: u16 = 0x0013;
const ATTR_COOKIE: u16 = 0x000F;
const HEADER: usize = 20;

/// The other player's address from a wrapped packet's UDP payload, or `None`
/// unless it is a well-formed data indication.
///
/// Strict, like `analysis/e2_validate.py`'s `unwrap_gturn`: exact length
/// field, attributes that tile the body, and a relay cookie, a DATA attribute
/// and an IPv4 source address all present. Steam doesn't pad the last
/// attribute to 4 bytes, so it may end unpadded.
pub fn source_address(p: &[u8]) -> Option<SocketAddrV4> {
    if p.len() < HEADER || be16(p, 0)? != DATA_INDICATION {
        return None;
    }
    if usize::from(be16(p, 2)?) + HEADER != p.len() {
        return None;
    }
    let (mut i, mut cookie, mut data, mut src) = (HEADER, false, false, None);
    while i < p.len() {
        let at = be16(p, i)?;
        let len = usize::from(be16(p, i + 2)?);
        let end = i + 4 + len;
        if end > p.len() {
            return None;
        }
        match at {
            ATTR_COOKIE => cookie = true,
            ATTR_DATA => data = true,
            // [reserved, family 1 = IPv4, port, address], big-endian.
            ATTR_SOURCE if len == 8 && p[i + 5] == 1 => {
                let port = be16(p, i + 6)?;
                let ip = Ipv4Addr::new(p[i + 8], p[i + 9], p[i + 10], p[i + 11]);
                src = Some(SocketAddrV4::new(ip, port));
            }
            _ => {}
        }
        i = if end == p.len() {
            end
        } else {
            i + 4 + ((len + 3) & !3)
        };
    }
    (i == p.len() && cookie && data).then_some(src).flatten()
}

/// One IPv4 UDP datagram found in a captured frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Udp<'a> {
    pub src: SocketAddrV4,
    pub dst: SocketAddrV4,
    pub payload: &'a [u8],
}

/// The IPv4 UDP datagram in a link-layer frame, if any. Handles Ethernet
/// (with or without one VLAN tag), 802.11 data frames with an LLC/SNAP
/// header, and bare IPv4. Only the first fragment of an IP packet carries
/// the UDP header, so later fragments are skipped.
pub fn frame_udp(f: &[u8]) -> Option<Udp<'_>> {
    ipv4_udp(&f[l3_offset(f)?..])
}

/// Where the IPv4 header starts in a frame.
fn l3_offset(f: &[u8]) -> Option<usize> {
    // Ethernet II: ethertype at 12, possibly behind an 802.1Q tag.
    match be16(f, 12)? {
        0x0800 => return Some(14),
        0x8100 if be16(f, 16)? == 0x0800 => return Some(18),
        _ => {}
    }
    // 802.11 + LLC/SNAP for IPv4: AA AA 03 00 00 00 08 00, after a MAC
    // header of 24 to 32 bytes.
    const SNAP: [u8; 8] = [0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00];
    if let Some(i) = (24..=34).find(|&i| f.get(i..i + 8) == Some(&SNAP[..])) {
        return Some(i + 8);
    }
    // Bare IPv4 (some tunnel adapters).
    (f.first()? >> 4 == 4).then_some(0)
}

fn ipv4_udp(ip: &[u8]) -> Option<Udp<'_>> {
    let ihl = usize::from(ip.first()? & 0x0F) * 4;
    if ip[0] >> 4 != 4 || ihl < 20 || *ip.get(9)? != 17 {
        return None;
    }
    // Fragment offset must be 0 (first or only fragment).
    if be16(ip, 6)? & 0x1FFF != 0 {
        return None;
    }
    let total = usize::from(be16(ip, 2)?).min(ip.len());
    let u = ip.get(ihl..total)?;
    let ulen = usize::from(be16(u, 4)?);
    let addr = |o: usize| Ipv4Addr::new(ip[o], ip[o + 1], ip[o + 2], ip[o + 3]);
    Some(Udp {
        src: SocketAddrV4::new(addr(12), be16(u, 0)?),
        dst: SocketAddrV4::new(addr(16), be16(u, 2)?),
        // A captured fragment can stop early; take what is there.
        payload: u.get(8..ulen.clamp(8, u.len()))?,
    })
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn attr(t: u16, v: &[u8], pad: bool) -> Vec<u8> {
        let mut a = [t.to_be_bytes(), (v.len() as u16).to_be_bytes()].concat();
        a.extend_from_slice(v);
        while pad && a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    /// A data indication as Steam's relay sends it (last attribute unpadded).
    pub(crate) fn indication(src: SocketAddrV4, data: &[u8]) -> Vec<u8> {
        let mut addr = vec![0, 1];
        addr.extend_from_slice(&src.port().to_be_bytes());
        addr.extend_from_slice(&src.ip().octets());
        let body = [
            attr(ATTR_COOKIE, &[0x72, 0xC6, 0x4B, 0xC6], true),
            attr(ATTR_SOURCE, &addr, true),
            attr(ATTR_DATA, data, false),
        ]
        .concat();
        let mut p = [
            DATA_INDICATION.to_be_bytes(),
            (body.len() as u16).to_be_bytes(),
        ]
        .concat();
        p.extend_from_slice(&[7u8; 16]);
        p.extend_from_slice(&body);
        p
    }

    /// An Ethernet II frame with an IPv4 UDP packet.
    pub(crate) fn ether(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        f.extend_from_slice(&ip_udp(src, dst, payload));
        f
    }

    fn ip_udp(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let ulen = 8 + payload.len();
        let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        ip[2..4].copy_from_slice(&((20 + ulen) as u16).to_be_bytes());
        ip.extend_from_slice(&src.ip().octets());
        ip.extend_from_slice(&dst.ip().octets());
        ip.extend_from_slice(&src.port().to_be_bytes());
        ip.extend_from_slice(&dst.port().to_be_bytes());
        ip.extend_from_slice(&(ulen as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0]);
        ip.extend_from_slice(payload);
        ip
    }

    fn player() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 20), 39246)
    }

    #[test]
    fn reads_the_players_address() {
        let p = indication(player(), &[1u8; 85]);
        assert_eq!(p.len(), 129, "the common wrapped size in the captures");
        assert_eq!(source_address(&p), Some(player()));
    }

    #[test]
    fn rejects_other_messages_and_damage() {
        let p = indication(player(), &[1u8; 85]);
        // A send request (0x0004) or STUN binding (0x0001) isn't an indication.
        for t in [0x0004u16, 0x0001] {
            let mut q = p.clone();
            q[..2].copy_from_slice(&t.to_be_bytes());
            assert_eq!(source_address(&q), None);
        }
        // Wrong length field, truncation, missing cookie.
        let mut q = p.clone();
        q[3] ^= 1;
        assert_eq!(source_address(&q), None);
        assert_eq!(source_address(&p[..p.len() - 1]), None);
        let mut q = p.clone();
        q[20..22].copy_from_slice(&0x0099u16.to_be_bytes());
        assert_eq!(source_address(&q), None);
        // An IPv6 family byte gives no IPv4 address.
        let mut q = p.clone();
        q[33] = 2;
        assert_eq!(source_address(&q), None);
        assert_eq!(source_address(&[0u8; 10]), None);
    }

    #[test]
    fn finds_udp_in_ethernet_vlan_wifi_and_bare_frames() {
        let relay = SocketAddrV4::new(Ipv4Addr::new(205, 196, 6, 1), 4380);
        let me = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 27036);
        let p = indication(player(), &[1u8; 40]);
        let want = Udp {
            src: relay,
            dst: me,
            payload: &p,
        };
        let eth = ether(relay, me, &p);
        assert_eq!(frame_udp(&eth), Some(want));
        let mut vlan = eth[..12].to_vec();
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x05]);
        vlan.extend_from_slice(&eth[12..]);
        assert_eq!(frame_udp(&vlan).map(|u| u.src), Some(relay));
        let mut wifi = vec![0x08u8; 24];
        wifi.extend_from_slice(&[0xAA, 0xAA, 0x03, 0, 0, 0, 0x08, 0x00]);
        wifi.extend_from_slice(&eth[14..]);
        assert_eq!(frame_udp(&wifi).map(|u| u.payload.len()), Some(p.len()));
        assert_eq!(frame_udp(&eth[14..]).map(|u| u.dst), Some(me));
        // A later IP fragment has no UDP header.
        let mut frag = eth.clone();
        frag[14 + 6] = 0x00;
        frag[14 + 7] = 0x10;
        assert_eq!(frame_udp(&frag), None);
        // TCP and junk aren't UDP.
        let mut tcp = eth.clone();
        tcp[14 + 9] = 6;
        assert_eq!(frame_udp(&tcp), None);
        assert_eq!(frame_udp(&[0u8; 8]), None);
    }
}
