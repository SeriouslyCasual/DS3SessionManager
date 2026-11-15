"""Regenerate src/valve_data.rs: Valve's IPv4 address space and Steam relay sites.

Usage (from the repo root; needs internet, run by hand when the list is stale):

    python -I analysis/valve_prefixes.py src/valve_data.rs

Sources (both public, no identifiers sent):
- RIPEstat "announced-prefixes" for AS32590 (Valve Corporation): every IPv4
  prefix Valve's network announced over the last two weeks.
- Steam's relay network config, ISteamApps/GetSDRConfig/v1 for app 374320
  (Dark Souls III): relay sites ("POPs") with a description, coordinates and
  relay addresses.

ds3sm uses both to recognise a relay address (detector L) and the sites to
name and place it. The relays seen in E1/E2 aren't in the SDR list
themselves but share a /24 with a listed site, so sites are matched by /24
of their relay addresses. Some sites are hosted by partners (e.g.
Datapacket) outside Valve's address space; they're marked
`valve_hosted: false`.
"""

from __future__ import annotations

import datetime
import ipaddress
import json
import subprocess
import sys
import urllib.request

RIPE = "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS32590"
SDR = "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=374320"

# Coordinates in Steam's config that are clearly wrong (checked 2026-11-14):
# these partner sites have latitude and longitude swapped, and London has also
# lost its western sign. They're corrected by rule (swap, then force west);
# everything else is kept as published. (Madrid's longitude, +3.34, also looks
# like a lost sign, but the site's exact location is unknown, so it is left.)
SWAPPED = {"dfra", "dlhr", "dvie"}
WEST = {"dlhr"}


def fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ds3sm-valve-prefixes"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def rust_str(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)


def main(out_path: str) -> int:
    ripe = fetch(RIPE)
    sdr = fetch(SDR)

    nets = set()
    for p in ripe["data"]["prefixes"]:
        n = ipaddress.ip_network(p["prefix"], strict=False)
        if n.version == 4:
            nets.add(n)
    nets = sorted(ipaddress.collapse_addresses(nets))
    latest = ripe["data"].get("latest_time", "?")

    pops = []
    for code, v in sorted(sdr["pops"].items()):
        relays = v.get("relays") or []
        nets24 = sorted({ipaddress.ip_network(f"{r['ipv4']}/24", strict=False) for r in relays})
        lon, lat = (v.get("geo") or [None, None])[:2]
        if code in SWAPPED and lat is not None:
            lat, lon = lon, lat
        if code in WEST and lon is not None:
            lon = -abs(lon)
        # Partner-hosted sites (e.g. "Datapacket ...") sit outside Valve's network.
        hosted = all(any(n.subnet_of(p) for p in nets) for n in nets24)
        pops.append((code, v.get("desc", ""), lat, lon, nets24, hosted))

    today = datetime.date.today().isoformat()
    lines = [
        "//! Valve's IPv4 address space and Steam relay sites (generated; do not edit).",
        "//!",
        f"//! Generated {today} by `analysis/valve_prefixes.py` from:",
        f"//! - RIPEstat announced prefixes for AS32590, data up to {latest}:",
        f"//!   <{RIPE}>",
        f"//! - Steam relay network config, revision {sdr.get('revision', '?')}:",
        f"//!   <{SDR}>",
        "",
        "/// IPv4 prefixes announced by AS32590 (Valve), as (network, prefix length).",
        "pub const VALVE_V4_PREFIXES: &[([u8; 4], u8)] = &[",
    ]
    for n in nets:
        o = ", ".join(str(b) for b in n.network_address.packed)
        lines.append(f"    ([{o}], {n.prefixlen}),")
    lines += [
        "];",
        "",
        "/// A Steam relay site (\"point of presence\").",
        "pub struct Pop {",
        "    /// Valve's short code, e.g. \"sea\".",
        "    pub code: &'static str,",
        "    pub desc: &'static str,",
        "    pub lat: f64,",
        "    pub lon: f64,",
        "    /// /24 networks of the site's listed relay addresses.",
        "    pub nets24: &'static [[u8; 3]],",
        "    /// Inside Valve's own address space (false for partner-hosted sites).",
        "    pub valve_hosted: bool,",
        "}",
        "",
        "/// Steam relay sites with at least one listed relay.",
        "pub const POPS: &[Pop] = &[",
    ]
    kept = 0
    for code, desc, lat, lon, nets24, hosted in pops:
        if not nets24 or lat is None:
            continue
        kept += 1
        n24 = ", ".join("[" + ", ".join(str(b) for b in n.network_address.packed[:3]) + "]" for n in nets24)
        lines.append(
            f"    Pop {{ code: {rust_str(code)}, desc: {rust_str(desc)}, lat: {float(lat)!r}, "
            f"lon: {float(lon)!r}, nets24: &[{n24}], valve_hosted: {'true' if hosted else 'false'} }},"
        )
    lines.append("];")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")
    # Format like the rest of the crate, so `cargo fmt --check` stays clean.
    try:
        subprocess.run(["rustfmt", "--edition", "2024", out_path], check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"note: rustfmt failed ({e}); run `cargo fmt`", file=sys.stderr)
    print(f"wrote {out_path}: {len(nets)} prefixes, {kept} sites")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -I analysis/valve_prefixes.py src/valve_data.rs")
    sys.exit(main(sys.argv[1]))
