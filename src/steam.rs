//! Steamworks access: peer discovery and per-peer P2P session state.
//!
//! Technique (documented by DS3ConnectionInfo and reimplemented here):
//! 1. Initialise the Steam API in **this** process with Dark Souls III's AppID
//!    (374320).
//! 2. Enumerate Steam's "coplay" list (recently played with) via
//!    `ISteamFriends::GetCoplayFriend`.
//! 3. Ask `ISteamNetworking::GetP2PSessionState` (the deprecated, pre-SDR P2P
//!    API) about each candidate. Peers with an active or connecting session
//!    are the game's current P2P peers.
//!
//! Why a second process sees the game's sessions is not documented by Valve;
//! it is an empirical property checked in experiment E1.
//!
//! Footprint: this module never touches the game process. It talks only to
//! the local Steam client over Steam's own IPC.
//!
//! All `unsafe` here is plain FFI into the Steamworks flat C API. Pointers
//! are checked for null, and strings are copied out immediately.

use crate::model::{P2PState, SteamId};
use anyhow::{Result, bail};
use std::collections::HashSet;
use std::ffi::CStr;
use std::net::{Ipv4Addr, SocketAddrV4};
use steamworks_sys as sys;

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

pub struct Steam {
    friends: *mut sys::ISteamFriends,
    networking: *mut sys::ISteamNetworking,
    user: *mut sys::ISteamUser,
    requested_names: HashSet<u64>,
}

impl Steam {
    /// Initialise the Steam API. Call [`set_app_id_env`] first.
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
    pub fn run_callbacks(&self) {
        // SAFETY: Steam is initialised for the lifetime of `self`.
        unsafe { sys::SteamAPI_RunCallbacks() };
    }

    pub fn local_id(&self) -> SteamId {
        // SAFETY: `user` is a valid interface pointer.
        SteamId(unsafe { sys::SteamAPI_ISteamUser_GetSteamID(self.user) })
    }

    /// All players on the coplay list (any game, any age).
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
    pub fn persona(&mut self, id: SteamId) -> Option<String> {
        // SAFETY: valid interface pointer; Steam returns a NUL-terminated
        // UTF-8 string owned by Steam, which we copy immediately.
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

impl Drop for Steam {
    fn drop(&mut self) {
        // SAFETY: Steam was initialised by `init`.
        unsafe { sys::SteamAPI_Shutdown() };
    }
}
