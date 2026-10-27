use crate::{socket::tcp::RttEstimator, time::Instant};

use super::Controller;

/// RFC 6928's initial window, in segments.
const INITIAL_WINDOW: usize = 10;

// arkitekt-mesh's fork: RFC 5681 as written. Upstream, in congestion
// avoidance, set ssthresh to the window and grew it by a segment every ACK
// (doubling it a round trip, as in slow start), never cut it on duplicate
// ACKs, and halved it, not reset it, on a timeout.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Reno {
    cwnd: usize,
    min_cwnd: usize,
    mss: usize,
    ssthresh: usize,
    rwnd: usize,
    /// Octets ACKed towards the next segment of congestion avoidance.
    acked: usize,
}

impl Reno {
    pub fn new() -> Self {
        Reno {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            mss: 1024,
            ssthresh: usize::MAX,
            rwnd: 64 * 1024,
            acked: 0,
        }
    }

    fn back_off(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(2 * self.mss);
        self.acked = 0;
    }
}

impl Controller for Reno {
    fn window(&self) -> usize {
        self.cwnd
    }

    fn on_ack(&mut self, _now: Instant, len: usize, _rtt: &RttEstimator) {
        if self.cwnd < self.ssthresh {
            // Slow start: by what was ACKed, up to ssthresh.
            self.cwnd = self.cwnd.saturating_add(len).min(self.ssthresh);
        } else {
            // Congestion avoidance: a segment a window's worth of ACKs.
            self.acked += len;
            if self.acked >= self.cwnd {
                self.acked -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.mss);
            }
        }
        self.cwnd = self.cwnd.min(self.rwnd).max(self.min_cwnd);
    }

    /// A loss found by duplicate ACKs (the socket calls it once a loss with
    /// SACK recovery): half the window.
    fn on_duplicate_ack(&mut self, _now: Instant) {
        self.back_off();
        self.cwnd = self.ssthresh;
    }

    /// A retransmission timeout: one segment, slow start again.
    fn on_retransmit(&mut self, _now: Instant) {
        self.back_off();
        self.cwnd = self.min_cwnd;
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
        self.mss = mss.max(1);
        if self.ssthresh == usize::MAX {
            self.cwnd = self.cwnd.max(INITIAL_WINDOW * mss);
        }
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }
}

#[cfg(test)]
mod test {
    use crate::time::Instant;

    use super::*;

    #[test]
    fn test_reno() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut reno = Reno::new();
                reno.set_mss(1480);

                // Set remote window.
                reno.set_remote_window(remote_window);

                reno.on_ack(now, 4096, &RttEstimator::default());

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                if i & 1 == 0 {
                    reno.on_retransmit(now);
                } else {
                    reno.on_duplicate_ack(now);
                }

                let elapsed = Instant::from_millis(1000);
                reno.on_ack(elapsed, n, &RttEstimator::default());

                let cwnd = reno.window();
                println!("Reno: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= reno.min_cwnd);
                assert!(reno.window() <= remote_window);
            }
        }
    }

    #[test]
    fn reno_min_cwnd() {
        let remote_window = 64 * 1024;
        let now = Instant::from_millis(0);

        let mut reno = Reno::new();
        reno.set_remote_window(remote_window);

        for _ in 0..100 {
            reno.on_retransmit(now);
            assert!(reno.window() >= reno.min_cwnd);
        }
    }

    #[test]
    fn reno_backs_off_once_and_grows_a_segment_a_window() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 << 20);
        reno.set_mss(1000);
        assert_eq!(reno.window(), 10_000, "the initial window");
        reno.on_ack(Instant::ZERO, 90_000, &RttEstimator::default());
        assert_eq!(reno.window(), 100_000, "slow start");

        reno.on_duplicate_ack(Instant::ZERO);
        assert_eq!(reno.window(), 50_000);
        // A window's worth of ACKs: one segment more, not a doubling.
        for _ in 0..50 {
            reno.on_ack(Instant::ZERO, 1000, &RttEstimator::default());
        }
        assert_eq!(reno.window(), 51_000);

        reno.on_retransmit(Instant::ZERO);
        assert_eq!(reno.window(), 1000, "a timeout: one segment");
        reno.on_ack(Instant::ZERO, 1000, &RttEstimator::default());
        assert_eq!(reno.window(), 2000, "slow start again");
    }

    #[test]
    fn reno_set_rwnd() {
        let mut reno = Reno::new();
        reno.set_remote_window(64 * 1024 * 1024);

        println!("{reno:?}");
    }
}
