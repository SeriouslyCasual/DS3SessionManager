//! Rolling latency statistics over the most recent RTT samples.
//!
//! # The networking idea
//!
//! A single ping sample is noisy, so the code keeps a sliding window of the last N
//! samples and summarise it:
//! - **median**: the typical RTT, unaffected by one-off spikes;
//! - **p95**: the 95th percentile, "how bad does it get". Lag spikes live in
//!   this tail;
//! - **jitter**, reported two ways because the literature uses both:
//!   - `stddev`: the population standard deviation over the window (what
//!     DS3ConnectionInfo displays as "jitter");
//!   - `ipdv`: the mean absolute difference between *consecutive* samples, a
//!     smoothed form of RFC 3550 interarrival jitter applied to RTT (see also
//!     RFC 5481 on delay-variation metrics). It measures how much each sample
//!     differs from the previous one, which players feel as stutter.
//!
//! # The Rust idea
//!
//! Pure functions over plain data, with unit tests at the bottom of the file.
//! This module has no I/O at all, which makes it easy to test and reason about.

use std::collections::VecDeque;

/// A fixed-size sliding window of `f64` samples.
///
/// `VecDeque` is a ring buffer: adding at the back and removing from the front
/// are both O(1), exactly what a sliding window needs. The fields are private
/// (no `pub`), so other modules can only use the methods below. That keeps
/// the "never more than `cap` items" rule enforced in one place.
#[derive(Clone, Debug)]
pub struct Rolling {
    cap: usize,
    buf: VecDeque<f64>,
}

/// The summary statistics of a window. All values are in the samples' unit
/// (milliseconds for RTT).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    /// Number of samples in the window.
    pub n: usize,
    /// Most recent sample.
    pub last: f64,
    pub mean: f64,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
    /// Population standard deviation (jitter, definition 1).
    pub stddev: f64,
    /// Mean of `|sample[i] - sample[i-1]|` (jitter, definition 2).
    pub ipdv: f64,
}

impl Rolling {
    /// Create an empty window holding at most `cap` samples.
    ///
    /// `Self` is shorthand for the type being implemented (`Rolling`).
    /// `assert!` panics (crashes with a message) if the condition is false.
    /// It's used for programmer mistakes like a zero-size window, not for
    /// bad user input.
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "window must be non-empty");
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    /// Add a sample, dropping the oldest one if the window is full.
    ///
    /// `&mut self` means this method *changes* the struct. Rust guarantees no
    /// other code can read or write it while this runs.
    pub fn push(&mut self, v: f64) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    /// Compute the summary, or `None` if there are no samples yet.
    ///
    /// Returning `Option` forces callers to handle the "no data" case. They
    /// can't accidentally display a fake 0 ms.
    pub fn summary(&self) -> Option<Summary> {
        let n = self.buf.len();
        if n == 0 {
            return None;
        }

        // Step 1: copy the window into a plain `Vec` (contiguous memory) so
        // slice helpers can be used like `windows()`. `.iter()` yields `&f64`;
        // `.copied()` turns each into an `f64`; `.collect()` builds the Vec.
        let v: Vec<f64> = self.buf.iter().copied().collect();

        // Step 2: mean and population variance. `as f64` converts the
        // integer count to a float; Rust never converts numbers implicitly.
        // `sum::<f64>()` uses the "turbofish" to say which type to sum into.
        let mean = v.iter().sum::<f64>() / n as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;

        // Step 3: IPDV jitter. `windows(2)` yields overlapping pairs
        // [a,b], [b,c], [c,d]..., which is perfect for consecutive differences.
        // `if` is an expression in Rust, so it can produce a value directly.
        let ipdv = if n > 1 {
            v.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };

        // Step 4: percentiles need sorted data. Floats can be NaN, so `f64`
        // has no total order (it isn't `Ord`) and `.sort()` won't compile.
        // `total_cmp` defines an order that includes NaN, so sorting uses it.
        let mut sorted = v.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));

        // Step 5: assemble the result. Field-init shorthand: `n,` means `n: n,`.
        Some(Summary {
            n,
            last: v[n - 1],
            mean,
            median: percentile(&sorted, 50.0),
            p95: percentile(&sorted, 95.0),
            min: sorted[0],
            max: sorted[n - 1],
            stddev: var.sqrt(),
            ipdv,
        })
    }
}

/// Linear-interpolated percentile of an already sorted, non-empty slice.
///
/// `&[f64]` is a *slice*: a borrowed view into a run of `f64`s (here, the
/// sorted `Vec`). Taking a slice instead of `&Vec<f64>` makes the function
/// work with arrays and sub-ranges too.
///
/// Method: the p-th percentile sits at fractional position
/// `rank = p/100 * (len-1)`. If `rank` falls between two items, interpolate
/// linearly between them. (This is the "linear" method used by NumPy's
/// default.)
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    assert!(!sorted.is_empty());
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0).clamp(0.0, 1.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    sorted[lo] + (sorted[hi] - sorted[lo]) * frac
}

// ---------------------------------------------------------------------------
// Unit tests: `cargo test stats` runs just these.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_summary() {
        assert!(Rolling::new(4).summary().is_none());
    }

    #[test]
    fn window_evicts_oldest() {
        let mut r = Rolling::new(3);
        for v in [100.0, 1.0, 2.0, 3.0] {
            r.push(v);
        }
        let s = r.summary().unwrap();
        assert_eq!(s.n, 3);
        assert_eq!(s.max, 3.0);
    }

    #[test]
    fn stats_match_hand_computation() {
        let mut r = Rolling::new(10);
        for v in [10.0, 20.0, 30.0, 40.0] {
            r.push(v);
        }
        let s = r.summary().unwrap();
        assert_eq!(s.mean, 25.0);
        assert_eq!(s.median, 25.0);
        assert!((s.stddev - 125f64.sqrt()).abs() < 1e-9);
        assert_eq!(s.ipdv, 10.0);
        assert!((s.p95 - 38.5).abs() < 1e-9);
    }
}
