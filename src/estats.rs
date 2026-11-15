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
//! include that delay: in E3-T4 on the LAN (true RTT 0.23 ms) the samples
//! ran 0–65 ms and their mean and the smoothed RTT sat near 30 ms. Samples
//! whose ACK came straight back (e.g. on the peer's immediate reply to a
//! check) are close to the true RTT, so the **minimum over a short window**
//! filters the delayed-ACK inflation out. [`MinRtt`] keeps the individual
//! samples, read often enough (every ~10 ms, about 30 samples/s on the
//! fallback) that most reads see one new sample, and reports their 10 s
//! minimum. It is a different measurement from the UDP checks, labelled as
//! such (`tcp_estats`).
//!
//! (The send events' `startime`/`endtime` fields were checked too: they
//! count 10 ms ticks, too coarse for RTT.)
//!
//! Switching collection on only affects the one connection (Steam's link
//! to the peer) and ends with it.
//!
//! # The Rust idea
//!
//! Thin `unsafe` wrappers around three Win32 calls. The structs are plain
//! C data, so they're passed as byte slices of their own size.

use std::collections::VecDeque;
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

/// Window over which the TCP RTT minimum is taken.
pub const MIN_RTT_WINDOW_NS: i128 = 10_000_000_000;

/// Rolling minimum of a connection's TCP RTT samples (see the module
/// docs). Fed successive [`PathStats`] readings; a reading that adds one
/// sample gives it exactly (ΔSumRtt), one that adds several gives their
/// mean, which is never below their minimum, so the window minimum stays
/// an upper bound on the best sample seen.
#[derive(Default, Debug)]
pub struct MinRtt {
    last: Option<PathStats>,
    samples: VecDeque<(i128, f64)>,
}

impl MinRtt {
    pub fn update(&mut self, s: PathStats, t_ns: i128) {
        if let Some(v) = self.last.and_then(|p| s.interval_mean(&p)) {
            self.samples.push_back((t_ns, v));
        }
        self.last = Some(s);
        while self
            .samples
            .front()
            .is_some_and(|&(t0, _)| t_ns - t0 > MIN_RTT_WINDOW_NS)
        {
            self.samples.pop_front();
        }
    }

    /// The minimum sample in the window, ms, or `None` if there is none.
    pub fn min(&self) -> Option<f64> {
        self.samples.iter().map(|&(_, v)| v).reduce(f64::min)
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

    /// Delayed-ACK samples (tens of ms) don't hide the quick ones; old
    /// samples leave the window.
    #[test]
    fn min_rtt_keeps_the_quick_samples_over_the_window() {
        let s = 1_000_000_000i128;
        let mut m = MinRtt::default();
        let (mut sum, mut count) = (0u32, 0u32);
        let mut feed = |m: &mut MinRtt, rtt: u32, t: i128| {
            sum += rtt;
            count += 1;
            m.update(
                PathStats {
                    sum_rtt: sum,
                    count_rtt: count,
                    ..Default::default()
                },
                t,
            );
        };
        feed(&mut m, 40, 0);
        assert_eq!(m.min(), None); // first reading only sets the baseline
        for (i, rtt) in [45, 52, 21, 38, 47].into_iter().enumerate() {
            feed(&mut m, rtt, (i as i128 + 1) * s / 10);
        }
        assert_eq!(m.min(), Some(21.0));
        // 12 s later, only newer samples count.
        feed(&mut m, 30, 12 * s);
        feed(&mut m, 33, 12 * s + s / 10);
        assert_eq!(m.min(), Some(30.0));
    }

    /// The table call works without admin rights and returns rows with
    /// sane ports (this PC always has some TCP connections or listeners).
    #[test]
    fn the_tcp_table_can_be_read() {
        let r = rows();
        assert!(r.iter().all(|x| x.dwLocalPort <= 0xFFFF));
    }
}
