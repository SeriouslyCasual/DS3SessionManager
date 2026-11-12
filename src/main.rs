//! DS3SessionManager (`ds3sm`): real-time network telemetry for Dark Souls III
//! Steam P2P sessions.
//!
//! Passive mode (the default) never writes to the game process.

mod anon;
mod geo;
mod model;
mod stats;
mod store;
mod stun;

#[cfg(windows)]
mod etw;
#[cfg(windows)]
mod monitor;
#[cfg(windows)]
mod steam;
#[cfg(windows)]
mod win;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ds3sm",
    version,
    about = "Dark Souls III P2P session telemetry"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args, Clone, Debug)]
pub struct MonitorArgs {
    /// SQLite file for this run (default: runs/<unix-time>.sqlite).
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// GeoIP MMDB file (DB-IP City Lite). Skipped if missing.
    #[arg(long, default_value = "geo/dbip-city-lite.mmdb")]
    pub geo: PathBuf,
    /// Your own latitude, for distance and fiber lower bound.
    #[arg(long, allow_hyphen_values = true)]
    pub home_lat: Option<f64>,
    /// Your own longitude.
    #[arg(long, allow_hyphen_values = true)]
    pub home_lon: Option<f64>,
    /// Steam polling and display interval, ms.
    #[arg(long, default_value_t = 500)]
    pub interval_ms: u64,
    /// RTT samples kept for the rolling statistics.
    #[arg(long, default_value_t = 20)]
    pub window: usize,
    /// Payload size of STUN requests, bytes (validated in experiment E2).
    #[arg(long, default_value_t = 56)]
    pub req_size: u32,
    /// Payload size of STUN replies, bytes.
    #[arg(long, default_value_t = 68)]
    pub reply_size: u32,
    /// Disable ETW (no admin needed, but no RTT).
    #[arg(long)]
    pub no_etw: bool,
    /// Free-text label stored in the run metadata (experiment id, condition...).
    #[arg(long, default_value = "")]
    pub label: String,
    /// Don't redraw the table (log only).
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check the environment: admin rights, game process, Steam, ETW, GeoIP.
    Probe {
        #[arg(long, default_value = "geo/dbip-city-lite.mmdb")]
        geo: PathBuf,
    },
    /// Live monitor of P2P peers; logs everything to SQLite.
    Monitor(MonitorArgs),
    /// Export a run database as anonymized CSV.
    Export {
        /// Run database to export.
        #[arg(long)]
        db: PathBuf,
        /// Output directory (e.g. experiments/data/E1/run-03).
        #[arg(long)]
        out: PathBuf,
        /// Secret salt for pseudonyms. Reuse it to link runs; never publish it.
        #[arg(long)]
        salt: String,
        /// Run label written into every row.
        #[arg(long, default_value = "run")]
        label: String,
    },
}

fn main() -> Result<()> {
    #[cfg(windows)]
    // SAFETY: first statement of main, before any thread is spawned.
    unsafe {
        steam::set_app_id_env(steam::DS3_APP_ID);
    }

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Export {
            db,
            out,
            salt,
            label,
        } => {
            let s = store::Store::open(&db)?;
            s.export_anonymized(&out, &salt, &label)?;
            println!("exported anonymized CSVs to {}", out.display());
            Ok(())
        }
        #[cfg(windows)]
        Cmd::Probe { geo } => monitor::probe(&geo),
        #[cfg(windows)]
        Cmd::Monitor(args) => monitor::run(args),
        #[cfg(not(windows))]
        _ => anyhow::bail!("live capture is only supported on Windows"),
    }
}
