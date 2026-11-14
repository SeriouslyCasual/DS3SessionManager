# Research roadmap

**Final deadline: December 4, 2026.**

| Key | Meaning |
|---|---|
| ✅ | done |
| 🔨 | in progress |
| 📋 | planned |

## Phases

| Phase | Window | Status |
|---|---|---|
| Literature review, Steam P2P architecture, existing tools | Oct 9 – Oct 22 | ✅ complete |
| Prototype: session detection, peer identification, basic telemetry | Oct 23 – Nov 5 | 🔨 live validation next |
| Extended telemetry, geographic analysis, visualization, initial testing | Nov 6 – Nov 19 | 📋 |
| Controlled experiments and routing analysis | Nov 20 – Dec 4 | 📋 |

## Research questions and experiments

| # | Question | Status |
|---|---|---|
| E1 | What can a third-party tool observe about Dark Souls III P2P sessions: identities, direct vs. relayed paths, endpoints? | 📋 [protocol](experiments/e1.md) |
| E2 | How accurate is operating-system-level RTT measurement? How reliable is identifying Steam's connectivity checks by packet size? | 📋 [protocol](experiments/e2.md) |
| E3 | Does measured RTT track artificially injected delay and loss? At what point does the game drop a session? | 📋 |
| E4 | **Why and when does Steam relay a connection? Can relaying be forced? What does it cost in latency, jitter and loss compared with a direct path?** | 📋 |
| E5 | How far above the speed-of-light-in-fiber bound are real peer RTTs? | 📋 |
| E6 | Can an alternative route (VPN exit) improve a specific peer path? | 📋 |
| E7 | How effective are connection-management actions, and what do they cost? | 📋 |
| E8 | What is the measurement tool's own overhead? | 📋 |

## Measurement-method research

- Validate packet-size identification of STUN connectivity checks against packet captures.
- Pair requests and responses exactly by STUN transaction ID, where captures show the IDs are readable.
- Better estimators: TCP-style smoothed RTT and RTT variance (RFC 6298), and percentile summaries.
- Higher-rate RTT and loss from gameplay traffic, if acknowledgements or sequence numbers can be identified.
- A route-anomaly indicator: observed RTT compared with distance-based expectations and network ownership data, to flag likely VPN or unusual routing.
