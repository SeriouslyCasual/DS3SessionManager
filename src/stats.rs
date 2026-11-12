//! Rolling latency statistics.
//!
//! Two jitter definitions are reported because the literature uses both:
//! - `stddev`: population standard deviation of RTT over the window
//!   (what DS3ConnectionInfo displays as "jitter");
//! - `ipdv`: mean absolute difference between consecutive RTT samples, the
//!   smoothed form of RFC 3550 interarrival jitter applied to RTT
//!   (cf. RFC 5481 on delay-variation metrics).

use std::collections::VecDeque;

#[derive(Clone, Debug)]
pub struct Rolling {
    cap: usize,
    buf: VecDeque<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Summary {
    pub n: usize,
    pub last: f64,
    pub mean: f64,
    pub median: f64,
    pub p95: f64,
    pub min: f64,
    pub max: f64,
    pub stddev: f64,
    pub ipdv: f64,
}

impl Rolling {
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "window must be non-empty");
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    pub fn push(&mut self, v: f64) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(v);
    }

    pub fn summary(&self) -> Option<Summary> {
        let n = self.buf.len();
        if n == 0 {
            return None;
        }
        let v: Vec<f64> = self.buf.iter().copied().collect();
        let mean = v.iter().sum::<f64>() / n as f64;
        let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n as f64;
        let ipdv = if n > 1 {
            v.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (n - 1) as f64
        } else {
            0.0
        };
        let mut sorted = v.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));
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
