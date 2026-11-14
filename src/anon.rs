//! Anonymization for exported data.
//!
//! Raw Steam IDs and IP addresses stay in the local per-run SQLite database
//! (git-ignored, never shared). The `export` command replaces them with:
//! - a **salted SHA-256 pseudonym** for each Steam ID. The same salt always
//!   gives the same pseudonym, so one peer can be followed across runs without
//!   revealing who they are. Without the salt, the pseudonym can't be reversed
//!   or recomputed from a known Steam ID.
//! - the **/24 network** for each IPv4 address (the last number is dropped),
//!   which keeps "same ISP neighbourhood" information but not a household.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

/// Stable pseudonym: the first 12 hex digits of SHA-256(salt ‖ steam_id).
///
/// - `salt: &str` borrows a string slice; the caller keeps ownership.
/// - The return type is an owned `String`, because a new string is built here.
pub fn pseudonym(salt: &str, steam_id: u64) -> String {
    // Step 1: create a hasher and feed it the salt bytes, then the ID's 8
    // bytes. `to_le_bytes()` gives the little-endian byte representation, so
    // the result is the same on every machine.
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(steam_id.to_le_bytes());

    // Step 2: finish hashing, which gives 32 bytes.
    let digest = h.finalize();

    // Step 3: keep the first 6 bytes and print each as two lowercase hex
    // digits (`{b:02x}` = hex, zero-padded to width 2). That's 12 characters.
    // `collect()` joins an iterator of `String`s into one `String`.
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Truncate an IPv4 address to its /24 network, e.g. `203.0.113.77` becomes
/// `203.0.113.0/24`.
pub fn ip_prefix24(ip: Ipv4Addr) -> String {
    // `octets()` returns the four numbers of the address as `[u8; 4]`.
    let o = ip.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------
// `#[cfg(test)]` means this module only exists when running `cargo test`.
// `use super::*;` imports everything from the parent module (this file).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonym_is_stable_and_salted() {
        let a = pseudonym("s1", 76561197960287930);
        // Same inputs → same output (stable).
        assert_eq!(a, pseudonym("s1", 76561197960287930));
        // Different salt → different output (salted).
        assert_ne!(a, pseudonym("s2", 76561197960287930));
        assert_eq!(a.len(), 12);
    }

    #[test]
    fn prefix24() {
        assert_eq!(
            ip_prefix24(Ipv4Addr::new(203, 0, 113, 77)),
            "203.0.113.0/24"
        );
    }
}
