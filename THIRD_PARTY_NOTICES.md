# Third-party notices and prior art

## Prior art (techniques studied, no code copied)

- **DS3ConnectionInfo** by William Tremblay (tremwil), https://github.com/tremwil/DS3ConnectionInfo.
  - The repository has **no licence file**, so its code is all rights reserved.
  - DS3SessionManager does **not** copy any of its code. Techniques such as "coplay list + `GetP2PSessionState`" and "ETW UDP timing of STUN-sized packets" are reimplemented from scratch from public documentation and independent measurements, and are cited as prior art.
- **SteamP2PInfo** by William Tremblay (tremwil), https://github.com/tremwil/SteamP2PInfo. MIT licence.
  - No code has been ported so far. If any is, its MIT notice will be reproduced here in full.

## Data

- **DB-IP IP to City Lite**, https://db-ip.com/db/lite.php, licensed CC BY 4.0. Required attribution: "IP Geolocation by DB-IP" (https://db-ip.com).
  - The database is downloaded locally by the user and is not committed.

## Rust dependencies

Every dependency's licence is recorded in `Cargo.lock` and can be listed with `cargo tree` or `cargo license`.
