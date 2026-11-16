//! `ds3sm geo-compare`: look up every player address in a run with two
//! GeoIP databases (e.g. DB-IP City Lite and MaxMind GeoLite2 City) and show
//! how far apart their answers are.
//!
//! IP geolocation is approximate, and a database rarely says how wrong it
//! might be (DB-IP Lite gives no accuracy radius; GeoLite2 does). When two
//! independent databases disagree by `d` km, at least one is off by `d / 2`
//! or more, so the disagreement is an honest, simple uncertainty measure for
//! the distance and the fiber bound (0.01 ms per km).
//!
//! Only players' own addresses are compared: relay addresses and private LAN
//! addresses are skipped. Players are shown as pseudonyms (salted with a
//! random value per invocation), and their addresses only in the developer
//! build.

use crate::anon;
use crate::geo::{self, GeoDb, GeoInfo, LatLon};
use crate::valve;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

/// Every distinct (player, public address) Steam reported in a run, minus
/// relay and local addresses.
pub fn player_addresses(conn: &Connection) -> Result<Vec<(u64, Ipv4Addr)>> {
    let mut q = conn.prepare(
        "SELECT DISTINCT steam_id, remote_ip FROM p2p_state
         WHERE remote_ip IS NOT NULL ORDER BY steam_id, remote_ip",
    )?;
    let rows = q.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (sid, ip) = row?;
        let Ok(ip) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        if geo::is_non_public(IpAddr::V4(ip)) || valve::is_relay_address(ip) {
            continue;
        }
        out.push((sid as u64, ip));
    }
    Ok(out)
}

/// One row of the comparison.
pub struct Row {
    pub steam_id: u64,
    pub ip: Ipv4Addr,
    pub a: Option<GeoInfo>,
    pub b: Option<GeoInfo>,
}

impl Row {
    pub fn disagreement_km(&self) -> Option<f64> {
        geo::disagreement_km(self.a.as_ref()?, self.b.as_ref()?)
    }
}

fn dist(home: Option<LatLon>, g: Option<&GeoInfo>) -> Option<f64> {
    Some(geo::great_circle_km(home?, g?.location?))
}

pub fn run(db: &Path, a: &Path, b: &Path, home: Option<LatLon>, show_ips: bool) -> Result<()> {
    let conn = Connection::open_with_flags(db, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("opening run database {}", db.display()))?;
    let (da, dbb) = (GeoDb::open(a)?, GeoDb::open(b)?);
    let rows: Vec<Row> = player_addresses(&conn)?
        .into_iter()
        .map(|(steam_id, ip)| Row {
            steam_id,
            ip,
            a: da.lookup(IpAddr::V4(ip)),
            b: dbb.lookup(IpAddr::V4(ip)),
        })
        .collect();
    let salt = format!("{:x}", std::process::id() as u64 ^ crate_time_salt());
    let name = |r: &Row| anon::pseudonym(&salt, r.steam_id);
    let fname = |p: &Path| {
        p.file_name()
            .map_or_else(String::new, |f| f.to_string_lossy().into_owned())
    };
    println!("A = {}\nB = {}\n", fname(a), fname(b));
    println!(
        "{:<12} {}{:<24} {:<24} {:>8} {:>7} {:>8} {:>8}",
        "player",
        if show_ips {
            format!("{:<15} ", "ip")
        } else {
            String::new()
        },
        "A place",
        "B place",
        "A-B km",
        "B rad",
        "A km",
        "B km"
    );
    let mut diffs = Vec::new();
    for r in &rows {
        let place = |g: &Option<GeoInfo>| {
            g.as_ref()
                .map_or_else(|| "-".into(), |g| geo::place_label(g, show_ips))
        };
        let f0 = |x: Option<f64>| x.map_or_else(|| "-".into(), |v| format!("{v:.0}"));
        let d = r.disagreement_km();
        if let Some(d) = d {
            diffs.push(d);
        }
        println!(
            "{:<12} {}{:<24} {:<24} {:>8} {:>7} {:>8} {:>8}",
            name(r),
            if show_ips {
                format!("{:<15} ", r.ip)
            } else {
                String::new()
            },
            place(&r.a),
            place(&r.b),
            f0(d),
            r.b.as_ref()
                .and_then(|g| g.accuracy_km)
                .map_or_else(|| "-".into(), |v| v.to_string()),
            f0(dist(home, r.a.as_ref())),
            f0(dist(home, r.b.as_ref())),
        );
    }
    diffs.sort_by(f64::total_cmp);
    if diffs.is_empty() {
        println!("\nno player address located by both databases");
    } else {
        let med = diffs[diffs.len() / 2];
        println!(
            "\n{} addresses located by both: A-B disagreement median {med:.0} km, max {:.0} km \
             (each 100 km moves the fiber bound by 1 ms)",
            diffs.len(),
            diffs[diffs.len() - 1]
        );
    }
    Ok(())
}

/// Some per-run randomness for the pseudonym salt, without a new dependency.
fn crate_time_salt() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_public_player_addresses() {
        let c = Connection::open_in_memory().unwrap();
        // A Seattle relay address (Valve's), built like valve.rs's tests.
        let relay = Ipv4Addr::new(205, 196, 6, 1);
        c.execute_batch(&format!(
            "CREATE TABLE p2p_state (t_ns INTEGER, steam_id INTEGER, remote_ip TEXT);
             INSERT INTO p2p_state VALUES (1, 7, '198.51.100.20');
             INSERT INTO p2p_state VALUES (2, 7, '198.51.100.20');
             INSERT INTO p2p_state VALUES (3, 8, '192.168.1.15');
             INSERT INTO p2p_state VALUES (4, 9, '{relay}');
             INSERT INTO p2p_state VALUES (5, 9, NULL);
             INSERT INTO p2p_state VALUES (6, 10, 'not an ip');"
        ))
        .unwrap();
        let v = player_addresses(&c).unwrap();
        assert_eq!(v, vec![(7, "198.51.100.20".parse().unwrap())]);
    }
}
