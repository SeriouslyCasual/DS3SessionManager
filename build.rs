//! Copies `steam_api64.dll` (shipped inside the `steamworks-sys` crate) next to
//! the built executable, so `cargo run` works without manual copying.
//!
//! Note: Dark Souls III's own `steam_api64.dll` is too old (it predates the
//! flat API), so the SDK copy is required.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

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
