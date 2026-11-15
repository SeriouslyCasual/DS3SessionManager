//! Shared data types used across the program.
//!
//! Keeping the core types in one module means every other module agrees on
//! what a "Steam ID", a "P2P state" or an "RTT sample" is.
//!
//! Design rule: every value shown to the user or written to disk can be
//! labelled with a [`Provenance`], so measured facts, estimates and unknowns
//! are never confused.

use std::fmt;
use std::net::SocketAddrV4;

// ---------------------------------------------------------------------------
// SteamId: the "newtype" pattern
// ---------------------------------------------------------------------------

/// A 64-bit Steam ID (SteamID64), e.g. `76561197960287930`.
///
/// Why wrap a plain `u64` in a struct? This is the *newtype* pattern. At run
/// time it costs nothing (it's still just a `u64`), but the compiler now treats
/// `SteamId` as its own type. You can't accidentally pass a timestamp, byte
/// count or port number where a Steam ID is expected.
///
/// `pub u64` makes the inner value public, so other modules can read it as
/// `id.0`.
///
/// The `derive` list asks the compiler to generate standard behaviour:
/// - `Clone, Copy`: duplicate it freely, like an integer;
/// - `Debug`: print with `{:?}`;
/// - `PartialEq, Eq`: compare with `==`;
/// - `Hash`: use as a `HashMap` key;
/// - `PartialOrd, Ord`: sort it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SteamId(pub u64);

// Implementing the `Display` trait defines how `{}` formats the value.
// Bonus: any type that implements `Display` automatically gets `.to_string()`.
impl fmt::Display for SteamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `write!` is like `format!`, but writes into the formatter `f`.
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Provenance: where a value came from
// ---------------------------------------------------------------------------

/// Where a value came from.
///
/// An `enum` lists every possible case. When code `match`es on it, the
/// compiler insists every variant is handled. Add a variant later and the
/// compiler points to every place that needs updating.
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
    /// A short label for display.
    ///
    /// `&'static str` is a string slice that lives for the whole program
    /// (string literals are baked into the executable), so returning it costs
    /// no allocation.
    pub fn as_str(self) -> &'static str {
        match self {
            Provenance::Measured => "measured",
            Provenance::Estimated => "estimated",
            Provenance::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// P2PState: Steam's view of one connection
// ---------------------------------------------------------------------------

/// Snapshot of Steam's view of one P2P session.
///
/// This mirrors Steam's C struct `P2PSessionState_t`, translated into friendly
/// Rust types (`bool` instead of `u8` flags, `Option` instead of a zero IP).
/// It derives `PartialEq` so the monitor can cheaply ask "did anything change
/// since last time?" and only log changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P2PState {
    /// A connection is established.
    pub active: bool,
    /// Steam is still trying to connect (NAT traversal in progress).
    pub connecting: bool,
    /// Steam's `EP2PSessionError` value; 0 means no error.
    pub error: u8,
    /// Steam says traffic goes through a Valve relay server, not directly.
    pub using_relay: bool,
    /// Bytes waiting in Steam's send queue (a congestion hint).
    pub bytes_queued: i32,
    /// Packets waiting in Steam's send queue.
    pub packets_queued: i32,
    /// Remote endpoint (IPv4 address and UDP port) as reported by Steam.
    ///
    /// `Option` because Steam may not know it (it reports 0). When
    /// `using_relay` is true this may be a relay's address, not the peer's
    /// (Valve's ISteamNetworking documentation says so).
    pub remote: Option<SocketAddrV4>,
}

// ---------------------------------------------------------------------------
// RTT samples
// ---------------------------------------------------------------------------

/// Which measurement method produced an RTT sample. Only one exists today;
/// the enum leaves room for others (e.g. packet-capture-based pairing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RttSource {
    /// Kernel ETW UDP send/receive timing of STUN-sized packets.
    EtwStun,
}

impl RttSource {
    /// Label stored in the database's `source` column.
    pub fn as_str(self) -> &'static str {
        match self {
            RttSource::EtwStun => "etw_stun",
        }
    }
}

/// One round-trip-time measurement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RttSample {
    /// Time the reply was received, in nanoseconds since the Unix epoch.
    /// `i128` so subtracting two timestamps can never overflow.
    pub t_ns: i128,
    /// The round-trip time in milliseconds.
    pub rtt_ms: f64,
    /// How it was measured.
    pub source: RttSource,
}
