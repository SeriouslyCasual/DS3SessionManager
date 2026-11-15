//! Offline IP geolocation and the latency lower bound implied by geography.
//!
//! # Geolocation
//!
//! Lookups use a local MMDB file (DB-IP "IP to City Lite", CC BY 4.0) read by
//! the `maxminddb` crate. Because the file is on disk, peer IPs are never sent
//! to a web service. IP geolocation is approximate (often city-level, sometimes
//! only the ISP's hub city), so these values are always labelled *estimated*.
//!
//! # The speed-of-light bound
//!
//! Light in optical fiber travels at roughly 2/3 of c (glass has a refractive
//! index of about 1.47–1.5). A round trip over a great-circle path of `d` km
//! therefore takes at least `2d / (2/3 · c)`, which is about **10 ms per
//! 1000 km**.
//!
//! Real paths are longer than great circles and add queuing and processing
//! delay. So `observed RTT / bound` (the *inflation ratio*) is always ≥ 1 when
//! the location is right. Typical values are around 2–4. A ratio below 1 means
//! the location estimate is wrong; a much higher one hints at a detour (bad
//! route, relay, VPN).

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::Path;

// `const` items are compile-time constants. The convention is UPPER_SNAKE_CASE.
// Underscores in numbers are only for readability.

/// Speed of light in vacuum, km/s (exact, by definition of the metre).
pub const C_KM_S: f64 = 299_792.458;
/// Assumed fraction of c for light in fiber.
pub const FIBER_FRACTION: f64 = 2.0 / 3.0;
/// Mean Earth radius, km (IUGG value).
pub const EARTH_RADIUS_KM: f64 = 6_371.008_8;

/// A point on Earth in decimal degrees (north and east are positive).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

/// Great-circle ("as the crow flies") distance in km, using the haversine
/// formula on a spherical Earth (error ≲ 0.5%, which is plenty here).
pub fn great_circle_km(a: LatLon, b: LatLon) -> f64 {
    // Step 1: trig functions work in radians, so convert from degrees.
    // `let (x, y) = (..., ...)` destructures a tuple into two variables.
    let (p1, p2) = (a.lat.to_radians(), b.lat.to_radians());
    let dp = p2 - p1;
    let dl = (b.lon - a.lon).to_radians();

    // Step 2: the haversine of the central angle.
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);

    // Step 3: central angle × radius = arc length. `.min(1.0)` guards against
    // floating-point rounding pushing the value just above 1, which would
    // make `asin` return NaN.
    2.0 * EARTH_RADIUS_KM * h.sqrt().min(1.0).asin()
}

/// Minimum possible RTT in milliseconds over fiber along the great circle:
/// there and back (`2 ×`), at 2/3 c, seconds → ms (`× 1000`).
pub fn fiber_rtt_lower_bound_ms(distance_km: f64) -> f64 {
    2.0 * distance_km / (C_KM_S * FIBER_FRACTION) * 1000.0
}

/// What the database knows about one IP. Every field is `Option` because any
/// of them can be missing for a given address range.
#[derive(Clone, Debug, PartialEq)]
pub struct GeoInfo {
    /// ISO country code, e.g. "CA".
    pub country: Option<String>,
    /// City name in English.
    pub city: Option<String>,
    pub location: Option<LatLon>,
    /// The database's own uncertainty radius, when it provides one.
    pub accuracy_km: Option<u16>,
}

/// An open GeoIP database.
///
/// `Reader<Vec<u8>>` means the reader owns the whole file loaded into memory
/// (a `Vec<u8>` of bytes), so lookups never touch the disk.
pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    /// Load the database file.
    ///
    /// `.with_context(|| ...)` attaches a human explanation to any error. The
    /// closure only runs if there *is* an error, so the `format!` costs
    /// nothing on success. `?` then returns the error to the caller.
    pub fn open(path: &Path) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path)
            .with_context(|| format!("opening GeoIP database {}", path.display()))?;
        Ok(Self { reader })
    }

    /// Look up one IP. Returns `None` if the IP isn't in the database or the
    /// record can't be decoded.
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // `.ok()` turns `Result<T, E>` into `Option<T>`, discarding the error;
        // `?` on an `Option` returns `None` from this function early.
        let res = self.reader.lookup(ip).ok()?;

        // `decode()` returns `Result<Option<City>, Error>`: two layers.
        // `.ok()??` peels both: an error becomes `None`, "no record" becomes
        // `None`.
        let city: maxminddb::geoip2::City = res.decode().ok()??;

        // Only build a location if *both* coordinates are present.
        // Matching on a tuple of Options is a neat way to require both.
        let location = match (city.location.latitude, city.location.longitude) {
            (Some(lat), Some(lon)) => Some(LatLon { lat, lon }),
            _ => None,
        };

        // The decoded record borrows strings from the database (`&str`);
        // `.map(str::to_owned)` copies them into owned `String`s so `GeoInfo`
        // doesn't depend on the reader's lifetime.
        Some(GeoInfo {
            country: city.country.iso_code.map(str::to_owned),
            city: city.city.names.english.map(str::to_owned),
            location,
            accuracy_km: city.location.accuracy_radius,
        })
    }
}

/// An open ASN database (DB-IP "IP to ASN Lite", CC BY 4.0): which network
/// (autonomous system) an address belongs to. Optional; ds3sm uses it to
/// recognise Valve relays (detector **A** in `relay.rs`) and to name the
/// owners of other endpoints the game talks to.
pub struct AsnDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl AsnDb {
    pub fn open(path: &Path) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path)
            .with_context(|| format!("opening ASN database {}", path.display()))?;
        Ok(Self { reader })
    }

    /// The AS number and organisation name for `ip`, if the database has it.
    pub fn lookup(&self, ip: IpAddr) -> Option<(u32, Option<String>)> {
        let res = self.reader.lookup(ip).ok()?;
        let asn: maxminddb::geoip2::Asn = res.decode().ok()??;
        Some((
            asn.autonomous_system_number?,
            asn.autonomous_system_organization.map(str::to_owned),
        ))
    }
}

/// True for addresses GeoIP can't place: private LAN ranges, loopback,
/// link-local, carrier-grade NAT, and so on. Your own PCs on the same home
/// network fall in here.
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() // 10/8, 172.16/12, 192.168/16
                || v4.is_loopback() // 127/8
                || v4.is_link_local() // 169.254/16
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
                // 100.64.0.0/10: carrier-grade NAT. Check the first 10 bits:
                // first byte 100, top two bits of the second byte = 01.
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

// ---------------------------------------------------------------------------
// Unit tests, checked against well-known distances.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distance_new_york_london() {
        // Commonly cited great-circle distance: ~5570 km.
        let nyc = LatLon {
            lat: 40.7128,
            lon: -74.0060,
        };
        let lon = LatLon {
            lat: 51.5074,
            lon: -0.1278,
        };
        let d = great_circle_km(nyc, lon);
        assert!((d - 5570.0).abs() < 15.0, "{d}");
    }

    #[test]
    fn zero_distance() {
        let p = LatLon {
            lat: 35.6762,
            lon: 139.6503,
        };
        assert!(great_circle_km(p, p) < 1e-9);
    }

    #[test]
    fn fiber_bound() {
        // 1000 km one way at 2/3 c: about 10.0 ms round trip.
        let b = fiber_rtt_lower_bound_ms(1000.0);
        assert!((b - 10.007).abs() < 0.01, "{b}");
    }

    #[test]
    fn non_public_ranges() {
        for s in [
            "10.1.2.3",
            "192.168.0.5",
            "127.0.0.1",
            "100.64.1.1",
            "169.254.3.3",
        ] {
            assert!(is_non_public(s.parse().unwrap()), "{s}");
        }
        assert!(!is_non_public("8.8.8.8".parse().unwrap()));
    }
}
