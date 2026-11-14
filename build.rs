//! Build script: copies `steam_api64.dll` next to the built executable.
//!
//! # What a build script is
//!
//! If a crate has a `build.rs`, Cargo compiles and runs it **before**
//! compiling the crate itself. Build scripts can generate code, compile C
//! libraries, or (as here) prepare files. They talk to Cargo by printing lines
//! that start with `cargo:`, such as `cargo:warning=...` or
//! `cargo:rerun-if-changed=...`.
//!
//! # Why it's needed
//!
//! `steamworks-sys` links the program against `steam_api64.dll`, and Windows
//! looks for that DLL **next to the .exe** when the program starts. If it's
//! missing, the program can't even launch. The game folder has its own copy,
//! but it dates from 2016 and lacks the "flat" API functions this program calls, so the build
//! uses the copy from the Steamworks SDK bundled inside the `steamworks-sys`
//! crate.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// Steps:
//   1. Only rerun this script when build.rs itself changes (saves time).
//   2. Do nothing on non-Windows targets.
//   3. Work out target/<profile>/ from OUT_DIR, which Cargo sets to
//      target/<profile>/build/ds3sm-<hash>/out (three folders deeper).
//   4. Find the DLL and copy it there, and into deps/ where `cargo test`
//      runs from.
// `let Some(x) = ... else { return; };` is *let-else*: continue with `x` if the
// pattern matches, otherwise leave the function.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    // OUT_DIR = target/<profile>/build/ds3sm-<hash>/out
    let Some(profile_dir) = out_dir.ancestors().nth(3).map(Path::to_path_buf) else {
        return;
    };
    match find_dll() {
        Some(dll) => {
            for dest in [
                profile_dir.join("steam_api64.dll"),
                profile_dir.join("deps").join("steam_api64.dll"),
            ] {
                if let Some(parent) = dest.parent() {
                    let _ = fs::create_dir_all(parent);
                }
                if let Err(e) = fs::copy(&dll, &dest) {
                    println!(
                        "cargo:warning=could not copy steam_api64.dll to {}: {e}",
                        dest.display()
                    );
                }
            }
        }
        None => println!(
            "cargo:warning=steam_api64.dll not found in the cargo registry; copy it next to ds3sm.exe manually"
        ),
    }
}

/// Look in the cargo registry sources for steamworks-sys's redistributable.
// Cargo downloads crate sources into $CARGO_HOME/registry/src/<index>/<crate>-<version>/.
// The search looks there for steamworks-sys and picks the 0.13.x copy (the version
// Cargo.toml asks for), falling back to the newest found. `?` on an `Option`
// returns `None` early if a folder can't be read.
fn find_dll() -> Option<PathBuf> {
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")))?;
    let src = cargo_home.join("registry").join("src");
    let mut candidates = Vec::new();
    for index in fs::read_dir(&src).ok()?.flatten() {
        for krate in fs::read_dir(index.path()).ok()?.flatten() {
            let name = krate.file_name().to_string_lossy().into_owned();
            if name.starts_with("steamworks-sys-") {
                let dll = krate
                    .path()
                    .join("lib/steam/redistributable_bin/win64/steam_api64.dll");
                if dll.exists() {
                    candidates.push((name, dll));
                }
            }
        }
    }
    // Prefer the version pinned in Cargo.toml (0.13.x), newest first.
    candidates.sort();
    candidates
        .iter()
        .rev()
        .find(|(n, _)| n.starts_with("steamworks-sys-0.13."))
        .or(candidates.last())
        .map(|(_, p)| p.clone())
}
