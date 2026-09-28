//! Choosing the home DERP region by measured latency (docs/rfc4-derp-home-by-latency.md).
//!
//! Every so often the node sends a STUN request to each region's STUN
//! servers; the round trip of each answer is a latency sample for that
//! region. The home region is the fastest one, switched only when another
//! is clearly faster and not too soon after the last switch, so two regions
//! of similar latency do not make the node flap between them.
//!
//! Sans-IO: requests to send and answers received go in, a home comes out.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::stun::TxId;

/// Samples kept per region (the best of them counts).
const SAMPLES: usize = 3;
/// A sample older than this no longer counts.
const SAMPLE_TTL: Duration = Duration::from_secs(15 * 60);
/// An unanswered probe is forgotten after this.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Switch only to a region at least this much faster...
const SWITCH_RATIO: f64 = 0.8;
/// ...and by at least this much...
const SWITCH_MIN_GAIN: Duration = Duration::from_millis(10);
/// ...and not sooner than this after the last switch.
const SWITCH_HOLD: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
pub struct Netcheck {
    pending: HashMap<TxId, (i32, Instant)>,
    samples: BTreeMap<i32, Vec<(Duration, Instant)>>,
    last_switch: Option<Instant>,
}

impl Netcheck {
    pub fn new() -> Self {
        Self::default()
    }

    /// Note a STUN request `tx` sent to `region`'s server.
    pub fn sent(&mut self, tx: TxId, region: i32, now: Instant) {
        self.pending
            .retain(|_, (_, at)| now.duration_since(*at) < PROBE_TIMEOUT);
        self.pending.insert(tx, (region, now));
    }

    /// A STUN answer for `tx`: records a sample if it answers a probe.
    /// Returns the region it measured.
    pub fn answered(&mut self, tx: &TxId, now: Instant) -> Option<i32> {
        let (region, at) = self.pending.remove(tx)?;
        let samples = self.samples.entry(region).or_default();
        samples.push((now.duration_since(at), now));
        if samples.len() > SAMPLES {
            samples.remove(0);
        }
        Some(region)
    }

    /// Whether `tx` is one of our probes (still waiting for its answer).
    pub fn is_pending(&self, tx: &TxId) -> bool {
        self.pending.contains_key(tx)
    }

    /// A region's latency: the best recent sample.
    pub fn latency(&self, region: i32, now: Instant) -> Option<Duration> {
        self.samples
            .get(&region)?
            .iter()
            .filter(|(_, at)| now.duration_since(*at) < SAMPLE_TTL)
            .map(|(d, _)| *d)
            .min()
    }

    /// Every region's latency (for reporting `DERPLatency` to control).
    pub fn latencies(&self, now: Instant) -> BTreeMap<i32, Duration> {
        self.samples
            .keys()
            .filter_map(|&r| Some((r, self.latency(r, now)?)))
            .collect()
    }

    /// The home to use given the `current` one and the `candidates` (regions
    /// a node may home to). `None` keeps the current one.
    pub fn choose(
        &mut self,
        current: Option<i32>,
        candidates: &[i32],
        now: Instant,
    ) -> Option<i32> {
        let best = candidates
            .iter()
            .filter_map(|&r| Some((r, self.latency(r, now)?)))
            .min_by_key(|&(r, d)| (d, r))?;
        let switch = match current.and_then(|c| Some((c, self.latency(c, now)?))) {
            // No measurement for the current home (or none yet): take the best.
            None => current != Some(best.0),
            Some((c, _)) if c == best.0 => false,
            Some((_, cur)) => {
                let clearly_faster = best.1.as_secs_f64() < cur.as_secs_f64() * SWITCH_RATIO
                    && cur.saturating_sub(best.1) >= SWITCH_MIN_GAIN;
                let settled = self
                    .last_switch
                    .is_none_or(|at| now.duration_since(at) >= SWITCH_HOLD);
                clearly_faster && settled
            }
        };
        if switch {
            self.last_switch = Some(now);
            Some(best.0)
        } else {
            None
        }
    }
}

/// Every region's STUN targets, as `(region, addr)`, from the DERP map: the
/// IPv4 and IPv6 addresses of nodes that serve STUN.
pub fn targets(
    regions: &BTreeMap<i32, crate::control::types::DerpRegion>,
) -> Vec<(i32, SocketAddr)> {
    regions
        .values()
        .filter(|r| !r.avoid && !r.no_measure_no_home)
        .flat_map(|r| {
            r.nodes.iter().flat_map(move |n| {
                n.stun_addrs().into_iter().filter_map(move |(host, port)| {
                    let ip: std::net::IpAddr = host.parse().ok()?;
                    Some((r.region_id, SocketAddr::new(ip, port)))
                })
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(nc: &mut Netcheck, region: i32, ms: u64, now: Instant) {
        let tx = [region as u8; 12];
        nc.sent(tx, region, now);
        nc.answered(&tx, now + Duration::from_millis(ms));
    }

    #[test]
    fn the_fastest_region_is_chosen_first() {
        let mut nc = Netcheck::new();
        let t = Instant::now();
        sample(&mut nc, 1, 120, t);
        sample(&mut nc, 2, 20, t);
        // Unmeasured current home (the start-up guess): take the best.
        assert_eq!(
            nc.choose(Some(1), &[1, 2], t + Duration::from_secs(1)),
            Some(2)
        );
        // Already there: nothing to do.
        assert_eq!(
            nc.choose(Some(2), &[1, 2], t + Duration::from_secs(2)),
            None
        );
    }

    #[test]
    fn switching_needs_a_clear_gain_and_time() {
        let mut nc = Netcheck::new();
        let t = Instant::now();
        sample(&mut nc, 1, 50, t);
        sample(&mut nc, 2, 45, t);
        let t1 = t + Duration::from_secs(1);
        assert_eq!(
            nc.choose(None, &[1, 2], t1),
            Some(2),
            "first choice is free"
        );
        // Region 1 gets a bit faster: 40 vs 45 is not 20% better.
        sample(&mut nc, 1, 40, t1);
        assert_eq!(
            nc.choose(Some(2), &[1, 2], t1 + Duration::from_secs(120)),
            None
        );
        // Much faster, but too soon after the last switch...
        sample(&mut nc, 1, 5, t1);
        assert_eq!(
            nc.choose(Some(2), &[1, 2], t1 + Duration::from_secs(10)),
            None
        );
        // ...and once the hold is over, switch.
        assert_eq!(
            nc.choose(Some(2), &[1, 2], t1 + Duration::from_secs(61)),
            Some(1)
        );
    }

    #[test]
    fn unmeasured_regions_are_never_chosen() {
        let mut nc = Netcheck::new();
        let t = Instant::now();
        assert_eq!(
            nc.choose(Some(1), &[1, 2], t),
            None,
            "no data: keep the guess"
        );
        sample(&mut nc, 2, 30, t);
        // Region 1 never answers (its STUN is dead): 2 wins.
        assert_eq!(
            nc.choose(Some(1), &[1, 2], t + Duration::from_secs(1)),
            Some(2)
        );
        // Only regions a node may home to count.
        let mut nc = Netcheck::new();
        sample(&mut nc, 3, 1, t);
        assert_eq!(nc.choose(Some(1), &[1, 2], t), None);
    }

    #[test]
    fn samples_age_out_and_only_the_best_counts() {
        let mut nc = Netcheck::new();
        let t = Instant::now();
        sample(&mut nc, 1, 80, t);
        sample(&mut nc, 1, 30, t);
        sample(&mut nc, 1, 60, t);
        assert_eq!(nc.latency(1, t), Some(Duration::from_millis(30)));
        assert_eq!(nc.latency(1, t + SAMPLE_TTL + Duration::from_secs(1)), None);
        // Answers to unknown or expired probes are ignored.
        assert_eq!(nc.answered(&[9; 12], t), None);
    }
}
