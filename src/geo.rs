//! Offline IP geolocation and the latency lower bound implied by geography.
//!
//! Lookups use a local MMDB file (DB-IP "IP to City Lite", CC BY 4.0), so
//! peer IPs are never sent to a web service. GeoIP locations are approximate:
//! they are always labelled `Estimated`, never `Measured`.
//!
//! Lower bound: light in optical fiber travels at roughly 2/3 of c
//! (refractive index ~1.47-1.5). A round trip over a great-circle path of
//! d km therefore takes at least 2d / (2/3 * c). Real paths are longer than
//! great circles and add queuing and processing delay, so observed RTT
//! divided by this bound (the "inflation ratio") is always >= 1 for correct
//! locations. That makes it a sanity check on geolocation as well.

use anyhow::{Context, Result};
use std::net::IpAddr;
use std::path::Path;

/// Speed of light in vacuum, km/s.
pub const C_KM_S: f64 = 299_792.458;
/// Assumed fraction of c for light in fiber.
pub const FIBER_FRACTION: f64 = 2.0 / 3.0;
/// Mean Earth radius, km (IUGG).
pub const EARTH_RADIUS_KM: f64 = 6_371.008_8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LatLon {
    pub lat: f64,
    pub lon: f64,
}

/// Great-circle distance in km (haversine formula).
pub fn great_circle_km(a: LatLon, b: LatLon) -> f64 {
    let (p1, p2) = (a.lat.to_radians(), b.lat.to_radians());
    let dp = p2 - p1;
    let dl = (b.lon - a.lon).to_radians();
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_KM * h.sqrt().min(1.0).asin()
}

/// Minimum possible RTT in ms over fiber along the great circle.
pub fn fiber_rtt_lower_bound_ms(distance_km: f64) -> f64 {
    2.0 * distance_km / (C_KM_S * FIBER_FRACTION) * 1000.0
}

#[derive(Clone, Debug, PartialEq)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub location: Option<LatLon>,
    /// The database's own uncertainty radius, when it provides one.
    pub accuracy_km: Option<u16>,
}

pub struct GeoDb {
    reader: maxminddb::Reader<Vec<u8>>,
}

impl GeoDb {
    pub fn open(path: &Path) -> Result<Self> {
        let reader = maxminddb::Reader::open_readfile(path)
            .with_context(|| format!("opening GeoIP database {}", path.display()))?;
        Ok(Self { reader })
    }

    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let res = self.reader.lookup(ip).ok()?;
        let city: maxminddb::geoip2::City = res.decode().ok()??;
        let location = match (city.location.latitude, city.location.longitude) {
            (Some(lat), Some(lon)) => Some(LatLon { lat, lon }),
            _ => None,
        };
        Some(GeoInfo {
            country: city.country.iso_code.map(str::to_owned),
            city: city.city.names.english.map(str::to_owned),
            location,
            accuracy_km: city.location.accuracy_radius,
        })
    }
}

/// True for addresses GeoIP can't place: private, loopback, CGNAT and so on.
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // 100.64.0.0/10 CGNAT
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified(),
    }
}

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
