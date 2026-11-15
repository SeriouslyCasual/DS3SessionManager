//! Windows' own TCP statistics for one connection (TCP ESTATS), used for
//! RTT on Steam's TCP fallback. Windows only; enabling needs admin.
//!
//! # Why
//!
//! On the TCP fallback, kernel ETW send events are stamped when the data is
//! acknowledged, not when it leaves (E3-T3), so the UDP method of timing a
//! check against its reply doesn't work. But the TCP stack measures RTT on
//! every connection itself, from its segments and their ACKs. Windows
//! exposes those measurements per connection through
//! `GetPerTcpConnectionEStats` ("extended statistics", RFC 4898), once
//! collection has been switched on for that connection with
//! `SetPerTcpConnectionEStats`. The "path" set has the latest RTT sample,
//! the smoothed RTT, the minimum and maximum, a running sum and count of
//! samples, and the retransmission counters.
//!
//! What it means: TCP's RTT, in **whole milliseconds**, measured from a
//! segment's departure to its ACK. When the peer delays its ACKs, samples
//! include that delay, so the interval mean can read above the network
//! RTT; the minimum and the smoothed value are less affected. It is a
//! different measurement from the UDP checks, labelled as such
//! (`tcp_estats`).
//!
//! Switching collection on only affects the one connection (Steam's link
//! to the peer) and ends with it.
//!
//! # The Rust idea
//!
//! Thin `unsafe` wrappers around three Win32 calls. The structs are plain
//! C data, so they're passed as byte slices of their own size.

use std::net::{Ipv4Addr, SocketAddrV4};

use windows::Win32::NetworkManagement::IpHelper::{
    GetPerTcpConnectionEStats, GetTcpTable2, MIB_TCP_STATE_ESTAB, MIB_TCPROW_LH, MIB_TCPROW2,
    MIB_TCPTABLE2, SetPerTcpConnectionEStats, TCP_ESTATS_PATH_ROD_v0, TCP_ESTATS_PATH_RW_v0,
    TcpConnectionEstatsPath,
};

/// One reading of a connection's path statistics (milliseconds; counters
/// are running totals since collection was enabled).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PathStats {
    pub sample_rtt: u32,
    pub smoothed_rtt: u32,
    pub rtt_var: u32,
    pub min_rtt: u32,
    pub max_rtt: u32,
    pub sum_rtt: u32,
    pub count_rtt: u32,
    pub pkts_retrans: u32,
    pub timeouts: u32,
}

impl PathStats {
    /// Mean of the RTT samples taken since `prev`, ms, or `None` if TCP
    /// took no new sample in between.
    pub fn interval_mean(&self, prev: &PathStats) -> Option<f64> {
        let n = self.count_rtt.wrapping_sub(prev.count_rtt);
        (n > 0 && n < u32::MAX / 2)
            .then(|| self.sum_rtt.wrapping_sub(prev.sum_rtt) as f64 / n as f64)
    }
}

/// Steam's established TCP connection to `remote`, owned by `pid`, as the
/// row the ESTATS calls take.
pub fn find_connection(remote: SocketAddrV4, pid: u32) -> Option<MIB_TCPROW_LH> {
    rows()
        .into_iter()
        .find(|r| {
            r.dwOwningPid == pid
                && r.dwState == MIB_TCP_STATE_ESTAB.0 as u32
                && addr_of(r.dwRemoteAddr, r.dwRemotePort) == remote
        })
        .map(|r| {
            let mut row = MIB_TCPROW_LH {
                dwLocalAddr: r.dwLocalAddr,
                dwLocalPort: r.dwLocalPort,
                dwRemoteAddr: r.dwRemoteAddr,
                dwRemotePort: r.dwRemotePort,
                ..Default::default()
            };
            row.Anonymous.dwState = r.dwState;
            row
        })
}

/// Turn on path-statistics collection for the connection.
pub fn enable(row: &MIB_TCPROW_LH) -> Result<(), u32> {
    let rw = TCP_ESTATS_PATH_RW_v0 {
        EnableCollection: true,
    };
    // SAFETY: `rw` is a plain C struct; the slice covers exactly its bytes.
    let err =
        unsafe { SetPerTcpConnectionEStats(row, TcpConnectionEstatsPath, as_bytes(&rw), 0, 0) };
    if err == 0 { Ok(()) } else { Err(err) }
}

/// Read the connection's path statistics.
pub fn read(row: &MIB_TCPROW_LH) -> Result<PathStats, u32> {
    let mut rod = TCP_ESTATS_PATH_ROD_v0::default();
    // SAFETY: `rod` is a plain C struct the call fills; the slice covers
    // exactly its bytes and outlives the call.
    let err = unsafe {
        GetPerTcpConnectionEStats(
            row,
            TcpConnectionEstatsPath,
            None,
            0,
            None,
            0,
            Some(as_bytes_mut(&mut rod)),
            0,
        )
    };
    if err != 0 {
        return Err(err);
    }
    Ok(PathStats {
        sample_rtt: rod.SampleRtt,
        smoothed_rtt: rod.SmoothedRtt,
        rtt_var: rod.RttVar,
        min_rtt: rod.MinRtt,
        max_rtt: rod.MaxRtt,
        sum_rtt: rod.SumRtt,
        count_rtt: rod.CountRtt,
        pkts_retrans: rod.PktsRetrans,
        timeouts: rod.Timeouts,
    })
}

/// The IPv4 TCP table with owning PIDs (empty on error).
fn rows() -> Vec<MIB_TCPROW2> {
    let mut size: u32 = 0;
    // SAFETY: a null table asks only for the needed size.
    unsafe {
        let _ = GetTcpTable2(None, &mut size, false);
    }
    for _ in 0..3 {
        // u32 words keep the buffer aligned for the table's u32 fields.
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 64];
        let mut len = (buf.len() * 4) as u32;
        let table = buf.as_mut_ptr() as *mut MIB_TCPTABLE2;
        // SAFETY: `buf` is at least `len` bytes and aligned for the table.
        let err = unsafe { GetTcpTable2(Some(table), &mut len, false) };
        if err == 0 {
            // SAFETY: on success the buffer holds `dwNumEntries` rows.
            return unsafe {
                let n = (*table).dwNumEntries as usize;
                std::slice::from_raw_parts((*table).table.as_ptr(), n).to_vec()
            };
        }
        size = len;
    }
    Vec::new()
}

/// A table address and port (network byte order in memory) as an endpoint.
fn addr_of(addr: u32, port: u32) -> SocketAddrV4 {
    SocketAddrV4::new(
        Ipv4Addr::from(addr.to_ne_bytes()),
        u16::from_be(port as u16),
    )
}

fn as_bytes<T: Copy>(v: &T) -> &[u8] {
    // SAFETY: any initialised `Copy` C struct can be viewed as bytes.
    unsafe { std::slice::from_raw_parts(v as *const T as *const u8, size_of::<T>()) }
}

fn as_bytes_mut<T: Copy>(v: &mut T) -> &mut [u8] {
    // SAFETY: as above; the callee writes plain data of the same layout.
    unsafe { std::slice::from_raw_parts_mut(v as *mut T as *mut u8, size_of::<T>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_addresses_are_network_order() {
        // 192.0.2.15:49202 as GetTcpTable2 stores it on a little-endian PC.
        let addr = u32::from_ne_bytes([192, 0, 2, 15]);
        let port = 49202u16.to_be() as u32;
        assert_eq!(
            addr_of(addr, port),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 15), 49202)
        );
    }

    #[test]
    fn interval_mean_uses_new_samples_only() {
        let a = PathStats {
            sum_rtt: 100,
            count_rtt: 10,
            ..Default::default()
        };
        let b = PathStats {
            sum_rtt: 160,
            count_rtt: 13,
            ..Default::default()
        };
        assert_eq!(b.interval_mean(&a), Some(20.0));
        assert_eq!(a.interval_mean(&a), None);
    }

    /// The table call works without admin rights and returns rows with
    /// sane ports (this PC always has some TCP connections or listeners).
    #[test]
    fn the_tcp_table_can_be_read() {
        let r = rows();
        assert!(r.iter().all(|x| x.dwLocalPort <= 0xFFFF));
    }
}
