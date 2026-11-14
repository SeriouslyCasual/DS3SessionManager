//! Steamworks access: who the player is connected to, and the state of each connection.
//!
//! # Technique
//!
//! (Documented by DS3ConnectionInfo; reimplemented here, no code copied.)
//! 1. Initialise the Steam API in **this** process using Dark Souls III's AppID
//!    (374320), so Steam treats this program as part of the running game.
//! 2. List Steam's "coplay" list ("recently played with") via
//!    `ISteamFriends::GetCoplayFriend`. DS3 adds players there when you meet
//!    them.
//! 3. Ask `ISteamNetworking::GetP2PSessionState` (Steam's older P2P API,
//!    which DS3 uses) about each candidate. Players with an active or
//!    connecting session are the game's current peers.
//!
//! Why can a *second* program see the game's sessions? Valve doesn't document
//! it. Both programs talk to the same Steam client under the same AppID, and
//! Steam appears to share session state between them. It's an observed
//! behaviour, which the project's first experiment checks.
//!
//! Footprint: this module never touches the game process. It only talks to
//! the local Steam client through Steam's own library.
//!
//! # Rust concepts: FFI and `unsafe`
//!
//! Steam's library (`steam_api64.dll`) has a C interface. Calling C from Rust
//! is called **FFI** (Foreign Function Interface). The `steamworks-sys` crate
//! contains auto-generated Rust *declarations* of Steam's C functions, which
//! are imported as `sys`.
//!
//! The compiler can't verify what C code does with pointers, so every call is
//! wrapped in `unsafe { ... }`. That's the programmer promising the rules are followed,
//! and each block has a `// SAFETY:` comment saying why. `*mut T` is a *raw
//! pointer*: unlike `&T`, it can be null, it isn't checked by the borrow
//! checker, and using it requires `unsafe`.

use crate::model::{P2PState, SteamId};
use anyhow::{Result, bail};
use std::collections::HashSet;
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddrV4};
use steamworks_sys as sys;

/// Dark Souls III's Steam application ID.
pub const DS3_APP_ID: u32 = 374320;

/// Sets the environment variables Steam reads to pick the AppID.
///
/// # Safety
/// Must be called before any other thread is started (it calls
/// `std::env::set_var`).
pub unsafe fn set_app_id_env(app_id: u32) {
    let v = app_id.to_string();
    // SAFETY: the caller guarantees no other threads exist yet.
    unsafe {
        std::env::set_var("SteamAppId", &v);
        std::env::set_var("SteamGameId", &v);
    }
}

/// A live connection to the Steam client.
///
/// It holds the three Steam "interface" pointers the program uses. `Steam` is created
/// by `init()` and shuts the API down in `Drop`. Raw pointers are neither
/// `Send` nor `Sync`, so the compiler automatically stops this struct from
/// being moved to another thread. That suits Steam, which expects calls
/// from one thread.
pub struct Steam {
    friends: *mut sys::ISteamFriends,
    networking: *mut sys::ISteamNetworking,
    user: *mut sys::ISteamUser,
    // Steam IDs whose names have already been requested from Steam, so each is requested once.
    requested_names: HashSet<u64>,
}

impl Steam {
    /// Initialise the Steam API. Call [`set_app_id_env`] first.
    // Steps:
    //   1. `SteamAPI_InitFlat` connects to the running Steam client. On failure,
    //      Steam writes a C string (bytes ending in 0) into a 1024-byte buffer.
    //      `CStr::from_ptr` reads up to that 0, and `to_string_lossy` turns it into
    //      Rust text.
    //   2. Fetch the interface pointers (the `_v018` suffixes are API versions).
    //   3. Check none are null before storing them. Never trust a C pointer blindly.
    // `bail!` (from anyhow) means "return this error now".
    pub fn init() -> Result<Self> {
        let mut err: sys::SteamErrMsg = [0; 1024];
        // SAFETY: FFI call with a valid, writable 1024-byte error buffer.
        let res = unsafe { sys::SteamAPI_InitFlat(&mut err) };
        if res != sys::ESteamAPIInitResult::k_ESteamAPIInitResult_OK {
            // SAFETY: Steam writes a NUL-terminated string into `err`.
            let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_string_lossy();
            bail!("SteamAPI_InitFlat failed ({res:?}): {msg}. Is Steam running and logged in?");
        }
        // SAFETY: the accessors are valid after a successful init.
        let (friends, networking, user) = unsafe {
            (
                sys::SteamAPI_SteamFriends_v018(),
                sys::SteamAPI_SteamNetworking_v006(),
                sys::SteamAPI_SteamUser_v023(),
            )
        };
        if friends.is_null() || networking.is_null() || user.is_null() {
            // SAFETY: init succeeded, so shutdown is valid.
            unsafe { sys::SteamAPI_Shutdown() };
            bail!("Steam interfaces unavailable (friends/networking/user returned null)");
        }
        Ok(Self {
            friends,
            networking,
            user,
            requested_names: HashSet::new(),
        })
    }

    /// Pump Steam callbacks (fills the persona-name cache).
    // Steam answers some requests asynchronously (e.g. a player's name arriving
    // later). Calling RunCallbacks regularly lets those answers be processed.
    pub fn run_callbacks(&self) {
        // SAFETY: Steam is initialised for the lifetime of `self`.
        unsafe { sys::SteamAPI_RunCallbacks() };
    }

    pub fn local_id(&self) -> SteamId {
        // SAFETY: `user` is a valid interface pointer.
        SteamId(unsafe { sys::SteamAPI_ISteamUser_GetSteamID(self.user) })
    }

    /// All players on the coplay list (any game, any age).
    // Steam exposes the list as "count" + "get item i". `.max(0)` guards
    // against a negative count, then `(0..n).map(...).collect()` builds a Vec by
    // calling GetCoplayFriend for each index.
    pub fn coplay_list(&self) -> Vec<SteamId> {
        // SAFETY: `friends` is a valid interface pointer.
        let n = unsafe { sys::SteamAPI_ISteamFriends_GetCoplayFriendCount(self.friends) };
        (0..n.max(0))
            .map(|i| {
                // SAFETY: index is within [0, count).
                SteamId(unsafe { sys::SteamAPI_ISteamFriends_GetCoplayFriend(self.friends, i) })
            })
            .collect()
    }

    /// `GetP2PSessionState` for one peer. `None` means Steam has no session
    /// with that peer for this AppID.
    // Steps:
    //   1. Make a zeroed `P2PSessionState_t` for Steam to fill in.
    //      `std::mem::zeroed()` is unsafe in general, but fine for a plain C struct
    //      of integers.
    //   2. Pass a pointer to it (`&mut st` coerces to `*mut`). `false` means
    //      "no session with this player".
    //   3. Convert into the friendlier `P2PState`: `u8` flags become `bool`, and
    //      an IP of 0 becomes `None` via `bool::then`, which gives `Some(...)` only
    //      if the condition is true.
    pub fn p2p_state(&self, id: SteamId) -> Option<P2PState> {
        // SAFETY: P2PSessionState_t is plain old data; zero is a valid value.
        let mut st: sys::P2PSessionState_t = unsafe { std::mem::zeroed() };
        // SAFETY: valid interface pointer and writable out-struct.
        let ok = unsafe {
            sys::SteamAPI_ISteamNetworking_GetP2PSessionState(self.networking, id.0, &mut st)
        };
        if !ok {
            return None;
        }
        // Steam reports the IP as a host-order integer, so Ipv4Addr::from(u32)
        // gives the dotted form directly. Checked live in E1.
        let remote = (st.m_nRemoteIP != 0)
            .then(|| SocketAddrV4::new(Ipv4Addr::from(st.m_nRemoteIP), st.m_nRemotePort));
        Some(P2PState {
            active: st.m_bConnectionActive != 0,
            connecting: st.m_bConnecting != 0,
            error: st.m_eP2PSessionError,
            using_relay: st.m_bUsingRelay != 0,
            bytes_queued: st.m_nBytesQueuedForSend,
            packets_queued: st.m_nPacketsQueuedForSend,
            remote,
        })
    }

    /// Coplay peers that currently have an active or connecting P2P session.
    // An iterator chain reads like a sentence:
    //   coplay list → not me → that has a session (filter_map keeps the Somes,
    //   pairing id with state) → that's live → collect into a Vec.
    pub fn active_peers(&self) -> Vec<(SteamId, P2PState)> {
        let me = self.local_id();
        self.coplay_list()
            .into_iter()
            .filter(|id| *id != me)
            .filter_map(|id| self.p2p_state(id).map(|s| (id, s)))
            .filter(|(_, s)| s.active || s.connecting)
            .collect()
    }

    /// Persona name if Steam has it cached. Asks Steam to fetch it otherwise
    /// (the name shows up on a later poll once callbacks have run).
    // Steam returns "[unknown]" (or an empty string) until it has the name
    // cached. In that case the name is requested once with RequestUserInformation; a later poll
    // will find the name. `HashSet::insert` returns true only the first time an
    // item is added, which is a neat "do this once" check.
    pub fn persona(&mut self, id: SteamId) -> Option<String> {
        // SAFETY: valid interface pointer; Steam returns a NUL-terminated
        // UTF-8 string owned by Steam, which is copied immediately.
        let name = unsafe {
            let p = sys::SteamAPI_ISteamFriends_GetFriendPersonaName(self.friends, id.0);
            (!p.is_null()).then(|| CStr::from_ptr(p).to_string_lossy().into_owned())
        };
        match name {
            Some(n) if !n.is_empty() && n != "[unknown]" => Some(n),
            _ => {
                if self.requested_names.insert(id.0) {
                    // SAFETY: valid interface pointer. `true` = name only.
                    unsafe {
                        sys::SteamAPI_ISteamFriends_RequestUserInformation(self.friends, id.0, true)
                    };
                }
                None
            }
        }
    }
}

// `Drop` is Rust's destructor: it runs automatically when a `Steam` value goes
// out of scope, even if the function exits early with an error. So Steam is
// always shut down cleanly.
impl Drop for Steam {
    fn drop(&mut self) {
        // SAFETY: Steam was initialised by `init`.
        unsafe { sys::SteamAPI_Shutdown() };
    }
}
