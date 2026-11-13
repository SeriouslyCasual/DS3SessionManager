//! DS3SessionManager (`ds3sm`): real-time network telemetry for Dark Souls III
//! Steam peer-to-peer sessions.
//!
//! # How this file fits in
//!
//! `main.rs` is the *crate root*: the file Cargo compiles first. It does three
//! jobs:
//! 1. Declares every other module (`mod foo;` tells the compiler to load
//!    `src/foo.rs`).
//! 2. Describes the command line (`probe`, `monitor`, `export`) using the
//!    `clap` crate.
//! 3. Runs `main()`, which parses the arguments and hands off to the right
//!    module.
//!
//! Passive mode (the default) never writes to the game process.
//!
//! # Reading guide
//!
//! The comments in this crate are deliberately detailed, to help readers new
//! to Rust. Comments starting with `///` or `//!` are *documentation* comments
//! (`cargo doc` turns them into web pages). Comments starting with `//` are
//! ordinary notes.

// ---------------------------------------------------------------------------
// Module declarations
// ---------------------------------------------------------------------------
// Each `mod name;` line pulls in `src/name.rs`. Modules are private by default;
// items inside them must be marked `pub` to be usable from other modules.
//
// These modules are plain Rust with no Windows-only APIs, so they compile on
// any OS. That also lets their unit tests run anywhere.
mod anon; // anonymization helpers for exported data
mod geo; // distance, speed-of-light bound, GeoIP lookups
mod model; // shared data types (SteamId, P2PState, ...)
mod stats; // rolling median / p95 / jitter
mod store; // SQLite logging and CSV export
mod stun; // pairs STUN request/reply packets into RTT samples

// `#[cfg(windows)]` is *conditional compilation*: the item below it only exists
// when compiling for Windows. These modules use Windows APIs (ETW, Toolhelp)
// or the Windows Steam DLL, so on other systems they are simply left out.
#[cfg(windows)]
mod etw; // kernel packet tracing (Event Tracing for Windows)
#[cfg(windows)]
mod monitor; // the `probe` and `monitor` commands (main loop)
#[cfg(windows)]
mod steam; // talks to the local Steam client
#[cfg(windows)]
mod win; // find the game process, check admin rights

// `use` brings names into scope so we can write `Result` instead of
// `anyhow::Result`.
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Command-line definition
// ---------------------------------------------------------------------------
// `clap`'s *derive* API: we describe the CLI as ordinary structs and enums,
// and `#[derive(Parser)]` generates all the parsing code, `--help` text and
// error messages at compile time. The `///` doc comment on each field becomes
// that field's help text, so those comments are written for end users.

/// Top-level CLI: `ds3sm <COMMAND>`.
#[derive(Parser)]
#[command(
    name = "ds3sm",
    version,
    about = "Dark Souls III P2P session telemetry"
)]
struct Cli {
    // `#[command(subcommand)]` says this field holds whichever subcommand the
    // user typed (one variant of the `Cmd` enum below).
    #[command(subcommand)]
    cmd: Cmd,
}

/// Options for `ds3sm monitor`.
///
/// Kept as a separate struct (instead of fields inside the enum variant) so
/// the whole bundle can be passed to `monitor::run` as one value. It is `pub`
/// because `monitor.rs` needs to read the fields.
#[derive(clap::Args, Clone, Debug)]
pub struct MonitorArgs {
    /// SQLite file for this run (default: runs/UNIX-TIME.sqlite).
    // `Option<PathBuf>`: the flag is optional. clap gives us `None` if absent.
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// GeoIP MMDB file (DB-IP City Lite). Skipped if missing.
    #[arg(long, default_value = "geo/dbip-city-lite.mmdb")]
    pub geo: PathBuf,
    /// Your own latitude, for distance and fiber lower bound.
    // `allow_hyphen_values` lets negative numbers like `-0.1` through
    // (otherwise clap would think `-0.1` is a flag).
    #[arg(long, allow_hyphen_values = true)]
    pub home_lat: Option<f64>,
    /// Your own longitude.
    #[arg(long, allow_hyphen_values = true)]
    pub home_lon: Option<f64>,
    /// Steam polling and display interval, ms.
    // `default_value_t` takes a typed Rust value; `default_value` takes a string.
    #[arg(long, default_value_t = 500)]
    pub interval_ms: u64,
    /// RTT samples kept for the rolling statistics.
    #[arg(long, default_value_t = 20)]
    pub window: usize,
    /// Payload size of STUN requests, bytes.
    #[arg(long, default_value_t = 56)]
    pub req_size: u32,
    /// Payload size of STUN replies, bytes.
    #[arg(long, default_value_t = 68)]
    pub reply_size: u32,
    /// Disable ETW (no admin needed, but no RTT).
    // A `bool` flag is `false` unless the user passes `--no-etw`.
    #[arg(long)]
    pub no_etw: bool,
    /// Free-text label stored with the run (e.g. what you were testing).
    #[arg(long, default_value = "")]
    pub label: String,
    /// Don't redraw the table (log only).
    #[arg(long)]
    pub quiet: bool,
}

/// The subcommands. Each enum variant is one command; its fields are that
/// command's options.
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
        /// Output directory for the CSV files (e.g. exports/run-03).
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

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Program entry point.
///
/// Returning `Result<()>` means any error that bubbles up with `?` ends the
/// program with a non-zero exit code and prints the error chain. That gives
/// us readable failures without writing explicit error printing.
fn main() -> Result<()> {
    // Step 1 (Windows only): tell the Steam library which game we are, by
    // setting environment variables. This must happen before any thread is
    // started, which is why it's the very first statement. See
    // `steam::set_app_id_env` for why it's `unsafe`.
    #[cfg(windows)]
    // SAFETY: first statement of main, before any thread is spawned.
    unsafe {
        steam::set_app_id_env(steam::DS3_APP_ID);
    }

    // Step 2: parse the command line. On `--help` or a bad flag, clap prints a
    // message and exits the process for us.
    let cli = Cli::parse();

    // Step 3: dispatch. `match` must cover every variant, and the compiler
    // checks that. Destructuring (`Cmd::Export { db, out, .. }`) moves each
    // field into its own local variable.
    match cli.cmd {
        Cmd::Export {
            db,
            out,
            salt,
            label,
        } => {
            // Export doesn't need Steam or ETW, so it works on any OS.
            // `&db` lends the path to `open` without giving up ownership.
            let s = store::Store::open(&db)?;
            s.export_anonymized(&out, &salt, &label)?;
            println!("exported anonymized CSVs to {}", out.display());
            Ok(())
        }
        #[cfg(windows)]
        Cmd::Probe { geo } => monitor::probe(&geo),
        #[cfg(windows)]
        Cmd::Monitor(args) => monitor::run(args),
        // On non-Windows builds the two arms above don't exist, so this
        // catch-all keeps the `match` exhaustive.
        #[cfg(not(windows))]
        _ => anyhow::bail!("live capture is only supported on Windows"),
    }
}
