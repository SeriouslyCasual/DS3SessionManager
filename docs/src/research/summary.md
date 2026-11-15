# Research summary: literature, architecture and existing tools

This page summarises the first project phase: the literature review, the Steam peer-to-peer architecture study, and the examination of existing tools. **All three are complete.** Claims about software behaviour come from public documentation or source code. Anything still unconfirmed is marked **open** and is assigned to an experiment.

---

## 1. Literature review

### 1.1 Latency is bounded by physics, but the Internet is far from the bound

- Light in optical fiber travels at roughly two thirds of *c*. Over great-circle distance *d*, the minimum round-trip time is therefore 2*d* / (⅔*c*): about **10 ms per 1,000 km**.
- Singla et al. show that measured Internet latencies are typically more than an order of magnitude above the speed-of-light bound, and often two orders. The causes are indirect routes, protocol overheads and queuing [Singla 2014].
- The cISP proposal builds a dedicated network that gets close to the bound, which shows how much latency today's routing leaves on the table [Bhattacherjee 2022].

**Takeaway.** The ratio of observed RTT to the fiber bound (the *inflation ratio*) is a meaningful, comparable metric for each peer connection. An unusually high ratio for a given distance points to a poor route, a relay detour, a VPN, or a wrong location estimate. The tool computes this ratio, and experiment E5 measures it.

### 1.2 Delay and geography constrain each other

- Constraint-Based Geolocation turns delay into distance limits and locates hosts by multilateration [Gueye 2004].
- Topology-based Geolocation adds router-level topology and brings the median error down to tens of kilometres in its study [Katz-Bassett 2006].

**Takeaway.** IP geolocation databases are approximate. A delay measurement can *falsify* a location (an RTT below the fiber bound is impossible) but can't pin a peer down precisely. The tool labels every geographic value as an *estimate* and uses delay as a sanity check.

### 1.3 Latency prediction for online games

- Htrae predicts latency between game consoles by combining geolocation with a network coordinate system. It was built on measurements from millions of Xbox consoles and roughly halves the 90th-percentile error of earlier systems [Agarwal 2009].
- iPlane predicts end-to-end path performance from measured path segments, and shows that overlay services benefit from that prediction [Madhyastha 2006].

**Takeaway.** "Expected latency for this distance" is a well-founded idea. A simple expected-RTT model will be fitted to this project's own measurements, and use it for the route-anomaly indicator and the E5/E6 analysis.

### 1.4 Latency mitigation

- Client-side prediction reduces *perceived* latency in cross-regional play [Tariono 2025].

**Takeaway.** Prediction requires changing game logic, which is not practical for a closed-source title, and it risks breaking synchronisation. It stays a discussion topic, not a feature.

### 1.5 Protocols and metric definitions

- Peers behind NATs find a working path with **ICE** [RFC 8445], which uses **STUN** [RFC 8489] binding requests as connectivity checks. Those checks keep running during the session to hold NAT mappings open.
- Jitter definitions come from RTP [RFC 3550] and the IETF delay-variation guidance [RFC 5481]. RTT smoothing follows TCP [RFC 6298].

**Takeaway.** Ongoing STUN checks are a free source of request/response timing that needs no cooperation from the game. That is the basis of this project's RTT measurement.

### 1.6 Gap

The literature search found no published measurement study of Steam P2P connection quality, or of latency in FromSoftware's multiplayer. Existing knowledge sits in community tools that do not report their accuracy. This project addresses that gap.

---

## 2. Steam peer-to-peer architecture

### 2.1 Two generations of Steam networking APIs

| | `ISteamNetworking` (old, deprecated) | `ISteamNetworkingMessages` / `Sockets` (new) |
|---|---|---|
| Addressing | By Steam ID | By Steam ID / identity |
| Path | Direct UDP after NAT traversal; relay fallback | Normally over the Steam Datagram Relay (SDR) |
| What a tool can see | Session active/connecting, **relay flag**, **remote IP and port**, send-queue depth (`GetP2PSessionState`) | Ping and connection quality reported directly; **IP usually hidden** under SDR |
| Used by | **Dark Souls III** (evidence from prior tools; *open* until E1) | Likely Elden Ring (inference, not confirmed) |

Sources: Valve's ISteamNetworking, ISteamNetworkingMessages and SDR documentation; Valve's GameNetworkingSockets.

### 2.2 How a session is formed

1. FromSoftware's matchmaking servers introduce players: summon signs, invasions, covenants. The open-source ds3os server reimplementation documents this server-side protocol.
2. Gameplay traffic then flows **peer to peer** through Steam networking.
3. Steam tries a direct UDP path through the players' NATs (ICE/STUN). If that fails, or if a player's Steam *IP sharing* setting forbids it, Steam forwards traffic through **Valve relays**.

### 2.3 Relays as an overlay network

Valve's relays are application-level forwarding nodes chosen by Steam, not by Internet routing. That makes them an overlay network. A relayed path:
- hides each player's IP address from the other;
- adds at least one extra hop;
- can be **slower or faster** than the direct Internet path, depending on whether Valve's backbone beats ordinary BGP routing for that pair.

**Takeaway.** Comparing direct and relayed paths for the same pair of players (experiment E4) directly measures the cost or benefit of an overlay.

**Result (E3): a third path, a direct TCP fallback.** When every UDP path between the two players was impaired, Steam's older P2P interface moved the session to a direct TCP connection between the two Steam clients. It carries the same datagrams, each with a 2-byte length prefix, and is not relayed. `GetP2PSessionState` still reported a direct session, so a tool that only watches UDP loses it. On this path, delay makes the other player's updates arrive in bursts, and movement looks choppy at a ping that would be smooth on UDP ([E3](../experiments/e3.md)).

### 2.4 What a third-party tool can and cannot observe

| Observable without touching the game | Not observable |
|---|---|
| Which players the local player is connected to (Steam coplay list + session state) | Packet contents (encrypted / proprietary) |
| Direct vs. relayed, and the remote endpoint | The true network path end to end (only partially, by traceroute) |
| Precise send and receive timing and sizes of every UDP packet the game sends (Windows kernel ETW) | The peer's real physical location (only database estimates) |
| Packet rates and receive gaps | Loss in the peer-to-local direction, beyond what the STUN checks reveal |

**Open (E1):** whether a second process still sees DS3's sessions, the exact byte order of fields, the current STUN packet sizes, and how often sessions are relayed.

---

## 3. Examination of existing tools

### 3.1 DS3ConnectionInfo (W. Tremblay)

**Technique**
- Runs the Steam API inside its own process under DS3's AppID.
- Enumerates the coplay ("recently played with") list and queries `GetP2PSessionState` for each entry.
- Times STUN checks through kernel ETW, matching 56-byte requests with 68-byte replies **by size only**.
- Reports jitter as the standard deviation over a 10-sample window.
- Geolocates peers with the ip-api.com web service.
- Reads character names from hard-coded game-memory addresses.

**Strengths**
- Proven: it established that third-party session monitoring is feasible.
- The ETW approach needs no packet-capture driver.

**Limitations this project addresses**
- **Accuracy unknown.** The size heuristic has never been validated (addressed by experiment E2).
- **Privacy.** Every peer IP is sent to a third-party web service; this project uses an offline database instead.
- **Fragile.** Hard-coded addresses break when the game updates; this project uses pattern (AOB) scans.
- **Intrusive control.** Leaving a session works by injecting code into the game process.
- **No licence file.** The code is all rights reserved, so its techniques are reimplemented from public documentation and the tool is cited as prior art. No code is reused.

### 3.2 SteamP2PInfo (W. Tremblay, MIT licence)

**Technique**
- Discovers peers by reading Steam's IPC log.
- Supports both the old API (with ETW timing) and the new `ISteamNetworkingMessages` API (with Steam-reported ping and quality).
- Never opens the game process.

**Takeaways**
- Its "no game access" design shows that useful monitoring is possible without touching the game process.
- Its new-API path shows what Elden Ring support would look like: ping without IPs.
- An open issue (#53, 2024) reports ping no longer displaying for Elden Ring, which suggests these techniques need ongoing maintenance.

### 3.3 ds3os (TLeonardUK, MIT licence)

- A reimplementation of the Dark Souls III *server*.
- Useful as documentation of how players are matched before P2P begins.
- Not a monitoring tool.

---

## References

- S. Agarwal and J. R. Lorch, "Matchmaking for online games and other latency-sensitive P2P systems," *Proc. ACM SIGCOMM*, 2009, pp. 315–326. doi:10.1145/1592568.1592605
- D. Bhattacherjee et al., "cISP: A speed-of-light Internet service provider," *Proc. USENIX NSDI*, 2022, pp. 1115–1133.
- B. Gueye, A. Ziviani, M. Crovella and S. Fdida, "Constraint-based geolocation of Internet hosts," *Proc. ACM IMC*, 2004, pp. 288–293.
- E. Katz-Bassett et al., "Towards IP geolocation using delay and topology measurements," *Proc. ACM IMC*, 2006, pp. 71–84.
- H. V. Madhyastha et al., "iPlane: An information plane for distributed services," *Proc. USENIX OSDI*, 2006, pp. 367–380.
- A. Singla, B. Chandrasekaran, P. B. Godfrey and B. Maggs, "The Internet at the speed of light," *Proc. ACM HotNets*, 2014. doi:10.1145/2670518.2673876
- J. T. Tariono et al., "Enhancing cross-regional multiplayer gaming: Implementing client-side prediction to reduce network latency," *Procedia Computer Science*, vol. 269, pp. 474–484, 2025. doi:10.1016/j.procs.2025.08.300
- IETF RFC 3550 (RTP), RFC 5481 (delay variation), RFC 6298 (RTT estimation), RFC 8445 (ICE), RFC 8489 (STUN).
- Valve Corporation, Steamworks documentation: ISteamNetworking; ISteamNetworkingMessages; Steam Datagram Relay; GameNetworkingSockets (GitHub).
- W. Tremblay, DS3ConnectionInfo (GitHub, release V4.5, 2023); SteamP2PInfo (GitHub, release V1.2.0, 2024).
- TLeonardUK, ds3os: Dark Souls III Open Server (GitHub).
