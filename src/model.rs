//! Shared data types.
//!
//! Every value shown to the user or written to disk carries a [`Provenance`]
//! so measured facts, estimates and unknowns are never confused.

use std::fmt;
use std::net::SocketAddrV4;

/// A 64-bit Steam ID (SteamID64).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SteamId(pub u64);

impl fmt::Display for SteamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Where a value came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provenance {
    /// Directly observed (an API value, or a timed packet exchange).
    Measured,
    /// Derived from a model or a database (GeoIP, fiber lower bound, ...).
    Estimated,
    /// Not available for this connection.
    Unknown,
}

impl Provenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Measured => "measured",
            Provenance::Estimated => "estimated",
            Provenance::Unknown => "unknown",
        }
    }
}

/// Snapshot of Steam's view of one P2P session (`P2PSessionState_t`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2PState {
    pub active: bool,
    pub connecting: bool,
    /// `EP2PSessionError` value; 0 means no error.
    pub error: u8,
    pub using_relay: bool,
    pub bytes_queued: i32,
    pub packets_queued: i32,
    /// Remote endpoint as reported by Steam. When `using_relay` is true this
    /// may be a relay address rather than the peer (Valve ISteamNetworking docs).
    pub remote: Option<SocketAddrV4>,
}

/// Where an RTT sample came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RttSource {
    /// Kernel ETW UDP send/receive timing of STUN-sized packets.
    EtwStun,
}

impl RttSource {
    pub fn as_str(self) -> &'static str {
        match self {
            RttSource::EtwStun => "etw_stun",
        }
    }
}

/// One round-trip-time sample.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RttSample {
    /// Time the reply was received, Unix epoch nanoseconds.
    pub t_ns: i128,
    pub rtt_ms: f64,
    pub source: RttSource,
}
