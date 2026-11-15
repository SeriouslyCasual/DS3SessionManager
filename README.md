# DS3SessionManager

**See who you're connected to in Dark Souls III, and how good that connection really is.**

DS3SessionManager is a free Windows tool that runs alongside Dark Souls III. For every player in your world it shows their ping, jitter, packet loss, region, and whether the connection is direct or going through a Steam relay. So when an invasion feels laggy, you can see why.

> **Status: early development.** There's no download yet. The monitor works from source, and a first release will follow once it has been tested in real sessions. Watch or star the repo to hear about it.

## Features

**Available now (build from source)**
- Live list of the players connected to you: Steam name and Steam ID.
- **Ping** (round-trip time), updated continuously, with median and worst-case (95th percentile).
- **Jitter**: how much the ping wobbles.
- **Packet loss estimate.**
- **Direct vs. Steam relay** connection, detected even when Steam itself doesn't flag the relay. For relayed players it also shows the relay server's location (not the player's) and the traffic on each relay connection.
- **Region and distance**, estimated from an offline IP-location database. Your peers' IPs are never sent to any website.
- **Fastest possible ping** for that distance, and how far above it the real ping is. This is handy for spotting bad routes.
- Session logging to a local file, plus an anonymized export.

**Planned**
- Simple main view, with a separate *Technical* tab for the detailed numbers.
- **"Am I lagging?"** check: test your own connection and see whether the problem is on your side or theirs.
- Borderless-window option and an in-game overlay.
- Peer blocking.
- Ready-to-run downloads.

## Is it safe to use?

- The monitor is **read-only**. It never modifies the game. It asks your Steam client which players you're connected to, and it reads Windows' own network statistics to time packets.
- It doesn't inject anything into the game and doesn't change game files or memory.
- Any future feature that does more will be **off by default**, clearly labelled, and only released after thorough testing.

As with any third-party tool: use it at your own risk. This project isn't affiliated with FromSoftware, Bandai Namco or Valve.

## Privacy

- Everything stays on your PC. No accounts, no telemetry, no web lookups of other players.
- Session logs are saved locally in the `runs` folder. The `export` command produces versions with Steam IDs replaced by random-looking codes and IP addresses shortened.

## Requirements

- Windows 10 or 11 (64-bit)
- Steam, and Dark Souls III on Steam
- **Run as administrator** for ping measurement. Windows only lets administrators read network timing. Without admin rights, use `--no-etw`: you still see who's connected, but not their ping.
- Optional, for regions: the free **DB-IP "IP to City Lite"** database (MMDB format) from <https://db-ip.com/db/download/ip-to-city-lite>, saved as `geo/dbip-city-lite.mmdb` next to the program.
- Optional, for better relay detection and network names: the free **DB-IP "IP to ASN Lite"** database (MMDB format) from <https://db-ip.com/db/download/ip-to-asn-lite>, saved as `geo/dbip-asn-lite.mmdb`.

## Building from source

Install Rust from <https://rustup.rs>, then:

```powershell
git clone https://github.com/SeriouslyCasual/DS3SessionManager
cd DS3SessionManager
cargo build --release
```

The program is `target\release\ds3sm.exe`. The build places the required `steam_api64.dll` beside it automatically.

## Usage

1. **Start Dark Souls III first** and load your character.
2. Open **PowerShell as administrator** in the project folder.
3. Check that everything is detected:
   ```powershell
   .\target\release\ds3sm.exe probe
   ```
4. Start the live monitor (Ctrl+C to stop):
   ```powershell
   .\target\release\ds3sm.exe monitor
   ```
   Add your approximate location to see distances and the fastest-possible ping, for example `--home-lat 51.5 --home-lon -0.1`. Add `--tcp` (experimental) to keep measuring when Steam switches a bad connection to its TCP fallback.

### Reading the table

| Column | Meaning |
|---|---|
| `st` | `A` = connected, `C` = connecting. `A!` = Steam says connected, but no game data has reached your PC over UDP for several seconds: Steam has probably switched to its TCP fallback (see `relay`), so the ping, jitter and loss numbers are out of date. Start the monitor with `--tcp` to keep measuring. This happens when the connection is very bad. |
| `relay` | `no` = direct. `yes*` = going through a Valve relay server, and ds3sm found the relay's connections. `yes` = Steam says it's relayed, but the relay wasn't found. `tcp` = Steam has moved the connection to its **TCP fallback**, a direct TCP link to the player that it uses when normal (UDP) traffic keeps failing. Only shown with `--tcp` (experimental). Jitter then includes TCP's own resend delay, `nrep%` shows the share of your packets TCP had to send again (marked `r`), and the ping columns show `-`: Windows doesn't time TCP sends precisely enough to measure ping on this path. |
| `via` | Which signs of a relay were seen: `F` Steam's own flag, `P` the traffic pattern, `A` the network owner (needs the ASN database), `L` ds3sm's built-in list of Valve relay addresses. `-` = none. |
| `remote` | The address the ping is measured to: the player, or the relay server |
| `last` / `med` / `p95` | Latest, typical and worst-case ping in milliseconds. Through a relay, this is the full round trip to the player and back, not just to the relay. |
| `sd` / `ipdv` | Two measures of how much the ping varies (ms). Lower is smoother. |
| `jit` | Jitter of the game data arriving from that player (ms, RFC 3550). The other player's game sends a packet about 12 times a second; this shows how unevenly they arrive. Well below 1 ms on a home network, a few ms through a relay. It's updated with every packet, so it reacts much faster than the ping columns. |
| `nrep%` | Share of Steam's connection checks that got no reply: a loss estimate |
| `pps_in` / `pps_out` | Packets per second to and from that player (all relay connections included) |
| `cc` / `km` | Estimated country and distance. `R:fra` (a relay site code, here Frankfurt) means it's the **relay server's** location, not the player's. |
| `bound` | Fastest physically possible ping for that distance |
| `infl` | Actual ping ÷ fastest possible. Around 2–4 is normal; much higher suggests a long route, a relay or a VPN. Left blank when only the relay's location is known. |

`-` means "not available for this connection". The tool never guesses.

For a relayed player, a **Relay for …** section below the table lists each relay connection: its role, the relay site, packets per second, data sent and received, and an estimate of the game data with the relay's own headers removed.

Steam doesn't always say when it relays a connection, so ds3sm treats a player as relayed if any of the signs in `via` appear. To choose which signs count, use for example `--relay-detect F,L`. All four are always recorded in the session log.

## Troubleshooting

| Problem | Fix |
|---|---|
| `Steam: SteamAPI_InitFlat failed` | Make sure Steam is running and you're logged in. |
| `ETW kernel UDP trace: needs administrator` | Run the terminal as administrator. |
| Steam says the game is already running | Close `ds3sm` before starting the game. Always start the game first. |
| No players listed | You need to be in a multiplayer session (summoned, summoning or invaded). |
| Ping column empty | Run `probe` and include its output when you report the issue. |

## Credits

- Inspired by **DS3ConnectionInfo** and **SteamP2PInfo** by tremwil. Their ideas showed this was possible. No code from them is used.
- IP geolocation and network data by [DB-IP](https://db-ip.com) (CC BY 4.0).
- Valve's address space from [RIPEstat](https://stat.ripe.net), and Steam relay site locations from Steam's public relay network configuration.
- Developed in part as a networking research project. Research notes and progress logs are on the [project site](https://seriouslycasual.github.io/DS3SessionManager/).

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## License

MIT. See [LICENSE](LICENSE).
