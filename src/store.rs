//! Per-run SQLite logging and anonymized CSV export.
//!
//! Each `monitor` run writes one database under `runs/` (git-ignored). The
//! database holds raw identifiers because the live tool needs them. Only
//! `export` output (pseudonymized, /24-truncated) belongs in
//! `experiments/data/`.

use crate::anon;
use crate::model::{P2PState, RttSample, SteamId};
use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::net::Ipv4Addr;
use std::path::Path;

const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer (
    steam_id   INTEGER PRIMARY KEY,
    persona    TEXT,
    first_seen_ns INTEGER NOT NULL,
    last_seen_ns  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS p2p_state (
    t_ns INTEGER NOT NULL,
    steam_id INTEGER NOT NULL,
    active INTEGER NOT NULL,
    connecting INTEGER NOT NULL,
    error INTEGER NOT NULL,
    using_relay INTEGER NOT NULL,
    bytes_queued INTEGER NOT NULL,
    packets_queued INTEGER NOT NULL,
    remote_ip TEXT,
    remote_port INTEGER
);
CREATE TABLE IF NOT EXISTS rtt (
    t_ns INTEGER NOT NULL,
    steam_id INTEGER,
    remote_ip TEXT NOT NULL,
    remote_port INTEGER NOT NULL,
    rtt_ms REAL NOT NULL,
    source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS geo (
    steam_id INTEGER PRIMARY KEY,
    country TEXT,
    city TEXT,
    lat REAL,
    lon REAL,
    accuracy_km INTEGER,
    distance_km REAL,
    fiber_bound_ms REAL
);
CREATE TABLE IF NOT EXISTS event (
    t_ns INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS rtt_by_peer ON rtt (steam_id, t_ns);
CREATE INDEX IF NOT EXISTS state_by_peer ON p2p_state (steam_id, t_ns);
"#;

pub struct Store {
    conn: Connection,
}

/// Geographic fields stored for a peer.
pub struct GeoRow<'a> {
    pub country: Option<&'a str>,
    pub city: Option<&'a str>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
    pub accuracy_km: Option<u16>,
    pub distance_km: Option<f64>,
    pub fiber_bound_ms: Option<f64>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening run database {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn })
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn upsert_peer(&self, id: SteamId, persona: Option<&str>, t_ns: i128) -> Result<()> {
        let t = t_ns as i64;
        self.conn.execute(
            "INSERT INTO peer (steam_id, persona, first_seen_ns, last_seen_ns)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(steam_id) DO UPDATE SET
               last_seen_ns = excluded.last_seen_ns,
               persona = COALESCE(excluded.persona, peer.persona)",
            params![id.0 as i64, persona, t],
        )?;
        Ok(())
    }

    pub fn insert_state(&self, t_ns: i128, id: SteamId, s: &P2PState) -> Result<()> {
        self.conn.execute(
            "INSERT INTO p2p_state VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                t_ns as i64,
                id.0 as i64,
                s.active,
                s.connecting,
                s.error,
                s.using_relay,
                s.bytes_queued,
                s.packets_queued,
                s.remote.map(|a| a.ip().to_string()),
                s.remote.map(|a| a.port()),
            ],
        )?;
        Ok(())
    }

    pub fn insert_rtt(
        &self,
        id: Option<SteamId>,
        remote: std::net::SocketAddrV4,
        s: &RttSample,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO rtt VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                s.t_ns as i64,
                id.map(|i| i.0 as i64),
                remote.ip().to_string(),
                remote.port(),
                s.rtt_ms,
                s.source.as_str(),
            ],
        )?;
        Ok(())
    }

    pub fn upsert_geo(&self, id: SteamId, g: &GeoRow<'_>) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO geo VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id.0 as i64,
                g.country,
                g.city,
                g.lat,
                g.lon,
                g.accuracy_km,
                g.distance_km,
                g.fiber_bound_ms
            ],
        )?;
        Ok(())
    }

    pub fn event(&self, t_ns: i128, kind: &str, detail: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO event VALUES (?1, ?2, ?3)",
            params![t_ns as i64, kind, detail],
        )?;
        Ok(())
    }

    /// Write anonymized CSVs (`rtt.csv`, `state.csv`, `peers.csv`) into `out_dir`.
    pub fn export_anonymized(&self, out_dir: &Path, salt: &str, run_label: &str) -> Result<()> {
        std::fs::create_dir_all(out_dir)?;

        let mut w = csv::Writer::from_path(out_dir.join("rtt.csv"))?;
        w.write_record(["run", "t_ns", "peer", "remote_net", "rtt_ms", "source"])?;
        let mut q = self
            .conn
            .prepare("SELECT t_ns, steam_id, remote_ip, rtt_ms, source FROM rtt ORDER BY t_ns")?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let t: i64 = r.get(0)?;
            let sid: Option<i64> = r.get(1)?;
            let ip: String = r.get(2)?;
            let rtt: f64 = r.get(3)?;
            let src: String = r.get(4)?;
            w.write_record([
                run_label.to_string(),
                t.to_string(),
                sid.map(|s| anon::pseudonym(salt, s as u64))
                    .unwrap_or_default(),
                net_of(&ip),
                format!("{rtt:.3}"),
                src,
            ])?;
        }
        w.flush()?;

        let mut w = csv::Writer::from_path(out_dir.join("state.csv"))?;
        w.write_record([
            "run",
            "t_ns",
            "peer",
            "active",
            "connecting",
            "error",
            "using_relay",
            "remote_net",
        ])?;
        let mut q = self.conn.prepare(
            "SELECT t_ns, steam_id, active, connecting, error, using_relay, remote_ip
             FROM p2p_state ORDER BY t_ns",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let t: i64 = r.get(0)?;
            let sid: i64 = r.get(1)?;
            let ip: Option<String> = r.get(6)?;
            w.write_record([
                run_label.to_string(),
                t.to_string(),
                anon::pseudonym(salt, sid as u64),
                r.get::<_, i64>(2)?.to_string(),
                r.get::<_, i64>(3)?.to_string(),
                r.get::<_, i64>(4)?.to_string(),
                r.get::<_, i64>(5)?.to_string(),
                ip.as_deref().map(net_of).unwrap_or_default(),
            ])?;
        }
        w.flush()?;

        // Location is coarsened to country plus distance rounded to 50 km.
        let mut w = csv::Writer::from_path(out_dir.join("peers.csv"))?;
        w.write_record([
            "run",
            "peer",
            "country",
            "distance_km_50",
            "fiber_bound_ms",
            "first_seen_ns",
            "last_seen_ns",
        ])?;
        let mut q = self.conn.prepare(
            "SELECT p.steam_id, g.country, g.distance_km, g.fiber_bound_ms,
                    p.first_seen_ns, p.last_seen_ns
             FROM peer p LEFT JOIN geo g ON g.steam_id = p.steam_id",
        )?;
        let mut rows = q.query([])?;
        while let Some(r) = rows.next()? {
            let sid: i64 = r.get(0)?;
            let country: Option<String> = r.get(1)?;
            let dist: Option<f64> = r.get(2)?;
            let bound: Option<f64> = r.get(3)?;
            w.write_record([
                run_label.to_string(),
                anon::pseudonym(salt, sid as u64),
                country.unwrap_or_default(),
                dist.map(|d| format!("{:.0}", (d / 50.0).round() * 50.0))
                    .unwrap_or_default(),
                bound.map(|b| format!("{b:.2}")).unwrap_or_default(),
                r.get::<_, i64>(4)?.to_string(),
                r.get::<_, i64>(5)?.to_string(),
            ])?;
        }
        w.flush()?;
        Ok(())
    }
}

fn net_of(ip: &str) -> String {
    ip.parse::<Ipv4Addr>()
        .map(anon::ip_prefix24)
        .unwrap_or_else(|_| "?".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RttSource;
    use std::net::SocketAddrV4;

    #[test]
    fn roundtrip_and_export_hides_identifiers() {
        let dir = std::env::temp_dir().join(format!("ds3sm-test-{}", std::process::id()));
        let db = dir.join("run.sqlite");
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::open(&db).unwrap();
        let id = SteamId(76561198000000001);
        let remote = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50000);
        s.upsert_peer(id, Some("Solaire"), 1).unwrap();
        s.insert_state(
            2,
            id,
            &P2PState {
                active: true,
                connecting: false,
                error: 0,
                using_relay: false,
                bytes_queued: 0,
                packets_queued: 0,
                remote: Some(remote),
            },
        )
        .unwrap();
        s.insert_rtt(
            Some(id),
            remote,
            &RttSample {
                t_ns: 3,
                rtt_ms: 41.5,
                source: RttSource::EtwStun,
            },
        )
        .unwrap();
        let out = dir.join("export");
        s.export_anonymized(&out, "salt", "r1").unwrap();
        let all = ["rtt.csv", "state.csv", "peers.csv"]
            .iter()
            .map(|f| std::fs::read_to_string(out.join(f)).unwrap())
            .collect::<String>();
        assert!(all.contains("203.0.113.0/24"));
        assert!(all.contains("41.500"));
        assert!(!all.contains("203.0.113.9"));
        assert!(!all.contains("76561198000000001"));
        assert!(!all.contains("Solaire"));
        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
