//! Small Windows helpers: finding the game process and checking for admin.
//!
//! These call the Windows API through Microsoft's official `windows` crate,
//! which provides Rust declarations for nearly every Win32 function. Calling
//! into the OS is `unsafe` because the compiler can't check what the OS does
//! with the program's pointers. So every `unsafe` block carries a `// SAFETY:` comment
//! explaining why the call is correct.
//!
//! Note: listing processes only reads a system snapshot. The program never opens a
//! handle to the game process here.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::UI::Shell::IsUserAnAdmin;

/// The game's executable name.
pub const DS3_EXE: &str = "DarkSoulsIII.exe";

/// The Steam client's executable name. DS3's peer-to-peer packets are sent
/// and received by this process, not by the game (confirmed with `probe`).
pub const STEAM_EXE: &str = "steam.exe";

/// Executable name for each running PID (used by `probe`'s per-process
/// traffic breakdown). Same snapshot walk as [`find_process`], but collects
/// every entry.
pub fn process_names() -> std::collections::HashMap<u32, String> {
    let mut out = std::collections::HashMap::new();
    // SAFETY: as in `find_process`.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                out.insert(
                    entry.th32ProcessID,
                    String::from_utf16_lossy(&entry.szExeFile[..len]),
                );
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// Returns the process ID (PID) of the first running process whose executable
/// name matches `exe` (ignoring upper/lower case), or `None` if none does.
pub fn find_process(exe: &str) -> Option<u32> {
    // SAFETY: Toolhelp snapshot APIs with a correctly sized entry struct; the
    // snapshot handle is closed before returning.
    unsafe {
        // Step 1: ask Windows for a snapshot of all running processes.
        // `.ok()?` turns a failure into `None` and returns early.
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;

        // Step 2: prepare the struct Windows fills in for each process.
        // Win32 requires `dwSize` to be set to the struct's size before the
        // first call (it's how Windows versions the struct). `..Default::default()`
        // fills every other field with zeros.
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        // Step 3: walk the list: First, then Next until it reports the end.
        let mut found = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                // `szExeFile` is a fixed-size UTF-16 buffer ending in a 0.
                // Find that 0 to get the real length (or use the whole buffer
                // if there isn't one).
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                // Windows strings are UTF-16; convert to a Rust `String`.
                // "lossy" replaces any invalid characters instead of failing.
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case(exe) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break; // no more processes
                }
            }
        }

        // Step 4: always release the snapshot handle. `let _ =` ignores the
        // result on purpose; there's nothing useful to do if closing fails.
        let _ = CloseHandle(snap);
        found
    }
}

/// Turn on ANSI escape-code handling in the Windows console.
///
/// The live table redraws itself with `ESC[2J ESC[H` ("clear screen, cursor
/// home"). Windows Terminal understands that out of the box, but the classic
/// console host behind cmd.exe and PowerShell only does once a program
/// enables "virtual terminal processing" on its output handle. Without this,
/// the codes print literally (`←[2J←[H`) and each refresh is appended below
/// the last instead of replacing it. Failure is ignored: if output is
/// redirected to a file there is no console mode to set.
pub fn enable_ansi() {
    use windows::Win32::System::Console::{
        CONSOLE_MODE, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode, GetStdHandle,
        STD_OUTPUT_HANDLE, SetConsoleMode,
    };
    // SAFETY: standard handle query plus get/set of its mode with a valid
    // out-pointer; no memory is shared with the OS beyond the call.
    unsafe {
        let Ok(h) = GetStdHandle(STD_OUTPUT_HANDLE) else {
            return;
        };
        let mut mode = CONSOLE_MODE(0);
        if GetConsoleMode(h, &mut mode).is_ok() {
            let _ = SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

/// True if this program is running with administrator rights (needed for
/// kernel event tracing).
pub fn is_admin() -> bool {
    // SAFETY: no arguments; returns a BOOL.
    unsafe { IsUserAnAdmin().as_bool() }
}
