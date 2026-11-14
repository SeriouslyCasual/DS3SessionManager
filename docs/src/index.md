<div class="hero">
<p class="eyebrow">Peer-to-peer networking research</p>
<h1>Real-Time Network Telemetry and Connection Quality in Dark Souls III</h1>
<p class="lede">How can real-time network telemetry be used to analyze, and potentially improve, connection quality in Dark Souls III?</p>
</div>

<div class="cards">
<a class="card card-primary" href="reports/progress-report-1.pdf">
<span class="card-kicker">Latest report · Nov 13, 2026</span>
<span class="card-title">Progress Report 1 (PDF)</span>
<span class="card-text">Literature review, Steam P2P architecture study and examination of existing tools: complete.</span>
</a>
<a class="card" href="roadmap.html">
<span class="card-kicker">Plan</span>
<span class="card-title">Research roadmap</span>
<span class="card-text">Project phases, research questions and experiments.</span>
</a>
<a class="card" href="research/summary.html">
<span class="card-kicker">Findings</span>
<span class="card-title">Research summary</span>
<span class="card-text">Key takeaways from the literature, the Steam networking architecture and existing tools.</span>
</a>
</div>

## About the project

Dark Souls III connects players directly, peer to peer, through Steam's networking layer, which falls back to Valve's relay servers when a direct path can't be made. Players from different continents regularly share a session, so geography, Internet routing and NAT traversal all shape how responsive an encounter feels.

The project measures those connections in real time:
- who a player is connected to;
- whether each path is direct or relayed;
- round-trip time, jitter and loss;
- how observed latency compares with the physical limit set by distance.

Controlled experiments then test the accuracy of these measurements, compare direct and relayed paths, and evaluate whether connection quality can be improved.

## Status

| Phase | Status |
|---|---|
| Literature review, Steam P2P architecture, existing tools | ✅ Complete |
| Measurement prototype | 🔨 In progress |
| Experiments and analysis | 📋 Planned |

The measurement tool itself is open source: [github.com/SeriouslyCasual/DS3SessionManager](https://github.com/SeriouslyCasual/DS3SessionManager).
