//! Small Windows helpers: finding the game process and checking for admin.
//! Enumerating processes needs no handle to the game itself.

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::UI::Shell::IsUserAnAdmin;

pub const DS3_EXE: &str = "DarkSoulsIII.exe";

/// PID of the first process whose executable name matches (case-insensitive).
pub fn find_process(exe: &str) -> Option<u32> {
    // SAFETY: Toolhelp snapshot APIs with a correctly sized entry struct; the
    // snapshot handle is closed before returning.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()?;
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut found = None;
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case(exe) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
        found
    }
}

pub fn is_admin() -> bool {
    // SAFETY: no arguments; returns a BOOL.
    unsafe { IsUserAnAdmin().as_bool() }
}
