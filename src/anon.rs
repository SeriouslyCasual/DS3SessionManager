//! Anonymization for exported data.
//!
//! Raw Steam IDs and IP addresses stay in the local per-run SQLite database
//! (git-ignored). Exports replace them with:
//! - a salted SHA-256 pseudonym for Steam IDs, so one peer can be followed
//!   across runs that share a salt without revealing who they are;
//! - the /24 network for IPv4 addresses.

use sha2::{Digest, Sha256};
use std::net::Ipv4Addr;

/// Stable pseudonym: first 12 hex digits of SHA-256(salt || steam_id).
pub fn pseudonym(salt: &str, steam_id: u64) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update(steam_id.to_le_bytes());
    let digest = h.finalize();
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// Truncate an IPv4 address to its /24 network, e.g. `203.0.113.0/24`.
pub fn ip_prefix24(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.0/24", o[0], o[1], o[2])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonym_is_stable_and_salted() {
        let a = pseudonym("s1", 76561197960287930);
        assert_eq!(a, pseudonym("s1", 76561197960287930));
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
