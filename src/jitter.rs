//! RFC 3550 interarrival jitter on a peer's periodic packet stream.
//!
//! # The networking idea
//!
//! RFC 3550 (RTP) defines jitter from two packets' send and receive times:
//! `D(i,j) = (Rj - Ri) - (Sj - Si)`, the change in one-way transit time, and
//! smooths it with `J += (|D| - J) / 16`. Steam's packets are opaque, so the
//! send times `S` aren't available. But the other player's client sends one
//! packet size on a strict clock: in the E2 captures, 85-byte packets every
//! 83.33 ms (12 Hz), arriving as 129 bytes on a wrapped relay port. For a
//! sender with a fixed period `T`, `Sj - Si = T` for consecutive packets, so:
//!
//! ```text
//! D = inter-arrival - k*T,   k = round(inter-arrival / T)
//! ```
//!
//! - `T` is the median of the last 64 per-slot inter-arrival times (the
//!   sender's period, learned from the stream itself). It starts from the
//!   first 16 raw gaps: their 10th percentile is the seed period (a gap of
//!   one slot, even when most gaps span several because of loss; E3 C2
//!   showed new endpoints starting under 50 % loss learning 2–3T from a
//!   median), and those 16 gaps are rewritten per slot against it. After
//!   that each gap goes in as `gap / k`, so a gap
//!   that spans k slots counts as k slots, not as one long period. Without
//!   this, heavy loss drags `T` up: at about 50 % loss most gaps are 2T or
//!   longer, the median doubles, and jitter reads about T/2 on a clean
//!   stream (seen in E3 at 50 % injected loss: 45–65 ms instead of 0.3 ms).
//!   A gap with k = 0 (an extra packet) is left out of the period.
//! - `k` absorbs a lost packet (gap of about 2T, so k = 2 and D is about 0),
//!   which keeps loss and jitter separate. An extra packet of the same size
//!   between two slots gets k = 0, so it counts as its offset, not as a gap.
//! - The period follows changes of less than half a slot (e.g. 12 → 10 Hz);
//!   a sender that halves its rate looks like 50 % loss and keeps the old
//!   `T`, which still gives the right jitter. A stream that starts under
//!   loss so heavy that fewer than about 1 gap in 10 is a single slot (over
//!   ~85 % loss) can still learn a multiple of the true period.
//! - Delays above T/2 (about 42 ms at 12 Hz) can't be told apart from a
//!   missing or extra packet; the largest inbound gap shows those.
//!
//! Which stream: per endpoint and direction, the packet size seen most often
//! (the "dominant" size). If another size overtakes it, the estimate starts
//! over. The first ~16 packets only learn `T`, and `J` starts at 0 (as in
//! RFC 3550), so it reads low for the first two or three seconds.
//!
//! # The Rust idea
//!
//! Like `stats.rs`, a plain struct with no I/O, fed one packet at a time and
//! unit-tested at the bottom of the file.

use std::collections::{HashMap, VecDeque};

/// RFC 3550's smoothing factor: each sample moves the estimate 1/16 of the way.
const GAIN: f64 = 16.0;
/// Inter-arrival times kept for the period estimate.
const PERIOD_WINDOW: usize = 64;
/// Inter-arrival times needed before the period (and so jitter) is trusted.
const MIN_PERIOD_SAMPLES: usize = 16;
/// Percentile of the first gaps taken as the seed period: low enough to land
/// on a single-slot gap under heavy loss, high enough to skip a stray extra
/// packet or two.
const SEED_PERCENTILE: f64 = 10.0;

/// Jitter of one endpoint's packets in one direction.
#[derive(Default, Clone, Debug)]
pub struct StreamJitter {
    /// Packets seen per size, to find the dominant size.
    counts: HashMap<u32, u64>,
    /// The size being tracked.
    size: Option<u32>,
    /// Arrival (or send) time of the last packet of that size, ns.
    last_ns: Option<i128>,
    /// Recent per-slot inter-arrival times (gap / k once `T` is known), ms.
    iats: VecDeque<f64>,
    /// The first gaps have been rewritten against the seed period.
    seeded: bool,
    jitter_ms: f64,
    /// Number of D values fed into `jitter_ms`.
    samples: u64,
}

impl StreamJitter {
    /// Feed one packet: its size in bytes and its kernel timestamp.
    pub fn observe(&mut self, size: u32, t_ns: i128) {
        let n = {
            let c = self.counts.entry(size).or_insert(0);
            *c += 1;
            *c
        };
        match self.size {
            Some(s) if s == size => {}
            // Another size, still not the most common one: ignore it.
            Some(s) if n <= self.counts[&s] => return,
            // First packet, or a new dominant size: start over.
            _ => {
                self.size = Some(size);
                self.last_ns = None;
                self.iats.clear();
                self.seeded = false;
                self.jitter_ms = 0.0;
                self.samples = 0;
            }
        }
        let Some(prev) = self.last_ns else {
            self.last_ns = Some(t_ns);
            return;
        };
        // Same tick or out of order (events from different CPUs): skip it.
        if t_ns <= prev {
            return;
        }
        self.last_ns = Some(t_ns);
        let iat = (t_ns - prev) as f64 / 1e6;
        let slot = match self.period_ms() {
            Some(t) => {
                let k = (iat / t).round();
                let d = iat - k * t;
                self.jitter_ms += (d.abs() - self.jitter_ms) / GAIN;
                self.samples += 1;
                // Per-slot gap for the period; an extra packet (k = 0) has none.
                (k >= 1.0).then(|| iat / k)
            }
            None => Some(iat),
        };
        if let Some(s) = slot {
            if self.iats.len() == PERIOD_WINDOW {
                self.iats.pop_front();
            }
            self.iats.push_back(s);
            if self.iats.len() == MIN_PERIOD_SAMPLES && self.period_ms().is_none() {
                self.seed_period();
            }
        }
    }

    /// Rewrite the first raw gaps per slot against a low-percentile seed, so
    /// the median that follows is the period even if the stream started
    /// under heavy loss. Gaps shorter than half the seed (extra packets) are
    /// dropped; if that leaves too few, more raw gaps are collected first.
    fn seed_period(&mut self) {
        let mut v: Vec<f64> = self.iats.iter().copied().collect();
        v.sort_by(|a, b| a.total_cmp(b));
        let seed = crate::stats::percentile(&v, SEED_PERCENTILE);
        self.iats = self
            .iats
            .iter()
            .filter_map(|&g| {
                let k = (g / seed).round();
                (k >= 1.0).then(|| g / k)
            })
            .collect();
        self.seeded = self.iats.len() >= MIN_PERIOD_SAMPLES;
    }

    /// The sender's period `T` (median per-slot gap), once enough are known.
    pub fn period_ms(&self) -> Option<f64> {
        if !self.seeded {
            return None;
        }
        let mut v: Vec<f64> = self.iats.iter().copied().collect();
        v.sort_by(|a, b| a.total_cmp(b));
        Some(crate::stats::percentile(&v, 50.0))
    }

    /// The smoothed jitter, ms, or `None` before the first D value.
    pub fn jitter_ms(&self) -> Option<f64> {
        (self.samples > 0).then_some(self.jitter_ms)
    }

    /// The packet size being tracked.
    pub fn size(&self) -> Option<u32> {
        self.size
    }

    /// Time of the last packet of the tracked size, ns.
    pub fn last_ns(&self) -> Option<i128> {
        self.last_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: i128 = 1_000_000;
    const T: i128 = 83 * MS + MS / 3; // 83.33 ms, the 12 Hz game stream

    /// Feed `n` packets of `size` on a perfect clock starting at `t0`, each
    /// delayed by `delay(i)` ns. Returns the time after the last slot.
    fn feed(
        j: &mut StreamJitter,
        size: u32,
        t0: i128,
        n: i128,
        delay: impl Fn(i128) -> i128,
    ) -> i128 {
        for i in 0..n {
            j.observe(size, t0 + i * T + delay(i));
        }
        t0 + n * T
    }

    #[test]
    fn perfect_clock_has_zero_jitter() {
        let mut j = StreamJitter::default();
        feed(&mut j, 85, 0, 200, |_| 0);
        assert_eq!(j.size(), Some(85));
        assert!((j.period_ms().unwrap() - 83.333).abs() < 0.01);
        assert!(j.jitter_ms().unwrap() < 1e-6);
    }

    #[test]
    fn no_value_before_the_period_is_known() {
        let mut j = StreamJitter::default();
        // n + 1 packets give the n inter-arrival times the period needs.
        let n = MIN_PERIOD_SAMPLES as i128 + 1;
        feed(&mut j, 85, 0, n, |_| 0);
        assert!(j.jitter_ms().is_none());
        j.observe(85, n * T);
        assert!(j.jitter_ms().is_some());
    }

    /// Alternating +a/-a delays give |D| = 2a on every packet, so J
    /// converges to 2a (RFC 3550's D is the change in transit time).
    #[test]
    fn converges_to_mean_abs_transit_change() {
        let mut j = StreamJitter::default();
        feed(&mut j, 85, 0, 400, |i| if i % 2 == 0 { MS } else { -MS });
        assert!(
            (j.jitter_ms().unwrap() - 2.0).abs() < 0.01,
            "{:?}",
            j.jitter_ms()
        );
    }

    #[test]
    fn a_lost_packet_is_not_jitter() {
        let mut j = StreamJitter::default();
        for i in 0..200 {
            if i % 10 != 5 {
                j.observe(85, i * T);
            }
        }
        assert!(j.jitter_ms().unwrap() < 1e-6);
        assert!((j.period_ms().unwrap() - 83.333).abs() < 0.01);
    }

    /// One extra packet 15 ms after a slot adds two |D| of 15 ms (k = 0,
    /// then k = 1), not a 68 ms spike.
    #[test]
    fn an_extra_packet_counts_as_its_offset() {
        let mut j = StreamJitter::default();
        let t = feed(&mut j, 85, 0, 100, |_| 0);
        j.observe(85, t - T + 15 * MS);
        j.observe(85, t);
        let want = 15.0 / GAIN + 15.0 * (1.0 - 1.0 / GAIN) / GAIN;
        assert!(
            (j.jitter_ms().unwrap() - want).abs() < 1e-6,
            "{:?}",
            j.jitter_ms()
        );
    }

    /// Other sizes interleaved (the real stream mixes 25/56/68/241 B) don't
    /// disturb the dominant stream.
    #[test]
    fn other_sizes_are_ignored() {
        let mut j = StreamJitter::default();
        for i in 0..300 {
            j.observe(85, i * T);
            if i % 3 == 0 {
                j.observe(241, i * T + 7 * MS);
            }
            if i % 6 == 0 {
                j.observe(68, i * T + 40 * MS);
            }
        }
        assert_eq!(j.size(), Some(85));
        assert!(j.jitter_ms().unwrap() < 1e-6);
    }

    #[test]
    fn a_new_dominant_size_restarts_the_estimate() {
        let mut j = StreamJitter::default();
        feed(&mut j, 85, 0, 20, |i| if i % 2 == 0 { MS } else { -MS });
        // A wrapped relay stream takes over: 129 B on the same clock.
        let t = feed(&mut j, 129, 30 * T, 60, |_| 0);
        assert_eq!(j.size(), Some(129));
        assert!(j.jitter_ms().unwrap() < 1e-6);
        assert_eq!(j.last_ns(), Some(t - T));
    }

    /// E3 Block C: 50 % injected loss each way left ~40 % of the stream.
    /// Keeping 2 slots in 5 (gaps 3T, 2T, 3T, ...) used to move the median
    /// gap to 2.5T and jitter to ~40 ms; per-slot gaps keep T and J at 0.
    #[test]
    fn heavy_loss_keeps_the_period() {
        let mut j = StreamJitter::default();
        let t = feed(&mut j, 85, 0, 100, |_| 0);
        for i in 0..500 {
            if i % 5 == 0 || i % 5 == 3 {
                j.observe(85, t + i * T);
            }
        }
        assert!((j.period_ms().unwrap() - 83.333).abs() < 0.01);
        assert!(j.jitter_ms().unwrap() < 1e-6, "{:?}", j.jitter_ms());
    }

    /// The same loss with ±1 ms alternating delay: J stays near the clean
    /// stream's value instead of jumping to tens of ms.
    #[test]
    fn heavy_loss_with_jitter_reads_the_jitter() {
        let mut j = StreamJitter::default();
        let d = |i: i128| if i % 2 == 0 { MS } else { -MS };
        let t = feed(&mut j, 85, 0, 100, d);
        for i in 0..800 {
            if i % 5 == 0 || i % 5 == 3 {
                j.observe(85, t + i * T + d(i));
            }
        }
        let v = j.jitter_ms().unwrap();
        assert!(v < 2.5, "{v}");
    }

    /// E3 C2: a new endpoint whose stream starts under heavy loss. Keeping 2
    /// slots in 5 (gaps T, 4T, T, 4T, ...) has a raw median of 2.5T; the
    /// low-percentile seed finds T.
    #[test]
    fn a_stream_starting_under_heavy_loss_learns_the_period() {
        let mut j = StreamJitter::default();
        for i in 0..400 {
            if i % 5 < 2 {
                j.observe(85, i * T);
            }
        }
        assert!((j.period_ms().unwrap() - 83.333).abs() < 0.01);
        assert!(j.jitter_ms().unwrap() < 1e-6, "{:?}", j.jitter_ms());
    }

    /// Random 60 % loss from the first packet (xorshift, 20 fixed seeds):
    /// every run learns T exactly, and jitter stays below the 0.1 ms sender
    /// floor measured live (a start-up transient can leave a few µs).
    #[test]
    fn random_heavy_loss_from_the_start_learns_the_period() {
        for seed in 1..=20u64 {
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
            let mut j = StreamJitter::default();
            for i in 0..600 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if x % 100 >= 60 {
                    j.observe(85, i * T);
                }
            }
            let t = j.period_ms().unwrap();
            assert!((t - 83.333).abs() < 0.01, "seed {seed}: T = {t}");
            assert!(
                j.jitter_ms().unwrap() < 0.1,
                "seed {seed}: J = {:?}",
                j.jitter_ms()
            );
        }
    }

    /// An extra packet during the first gaps doesn't become the seed.
    #[test]
    fn an_extra_packet_while_seeding_is_skipped() {
        let mut j = StreamJitter::default();
        for i in 0..100 {
            j.observe(85, i * T);
            if i == 3 {
                j.observe(85, i * T + 20 * MS);
            }
        }
        assert!((j.period_ms().unwrap() - 83.333).abs() < 0.01);
    }

    /// A small rate change (12 → 10 Hz) is followed.
    #[test]
    fn the_period_follows_a_small_rate_change() {
        let mut j = StreamJitter::default();
        let t = feed(&mut j, 85, 0, 100, |_| 0);
        for i in 0..200 {
            j.observe(85, t + i * 100 * MS);
        }
        assert!((j.period_ms().unwrap() - 100.0).abs() < 0.01);
        assert!(j.jitter_ms().unwrap() < 0.5, "{:?}", j.jitter_ms());
    }

    #[test]
    fn out_of_order_timestamps_are_skipped() {
        let mut j = StreamJitter::default();
        let t = feed(&mut j, 85, 0, 100, |_| 0);
        j.observe(85, t - 2 * T); // older than the last packet
        j.observe(85, t);
        assert!(j.jitter_ms().unwrap() < 1e-6);
    }
}
