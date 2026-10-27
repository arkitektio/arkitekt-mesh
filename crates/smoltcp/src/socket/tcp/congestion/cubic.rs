use crate::time::Instant;

use super::Controller;

// Constants for the Cubic congestion control algorithm.
// See RFC 8312.
const BETA_CUBIC: f64 = 0.7;
const C: f64 = 0.4;
/// RFC 6928's initial window, in segments.
const INITIAL_WINDOW: usize = 10;

// arkitekt-mesh's fork: RFC 8312 as written. Upstream computed W(t) in
// octets with C meant for segments (regaining a 1 MiB window took some 90
// s), and cut the window on every duplicate ACK, not once a loss.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Cubic {
    cwnd: usize,     // Congestion window, octets
    min_cwnd: usize, // The minimum size of congestion window
    mss: usize,
    w_max: usize, // Window size just before congestion, octets
    /// When the congestion avoidance epoch began, and its K (seconds).
    epoch: Option<(Instant, f64)>,
    rwnd: usize, // Remote window
    ssthresh: usize,
    /// The smoothed round trip, ms (0: none yet), for the Reno-friendly
    /// window.
    srtt_ms: u32,
}

impl Cubic {
    pub fn new() -> Cubic {
        Cubic {
            cwnd: 1024 * 2,
            min_cwnd: 1024 * 2,
            mss: 1024,
            w_max: 1024 * 2,
            epoch: None,
            rwnd: 64 * 1024,
            ssthresh: usize::MAX,
            srtt_ms: 0,
        }
    }

    /// A loss: back off to `BETA_CUBIC` of the window, and grow from there
    /// on the cubic curve back towards where the loss happened.
    fn loss(&mut self, now: Instant) {
        self.w_max = self.cwnd;
        self.ssthresh = ((self.cwnd as f64 * BETA_CUBIC) as usize).max(2 * self.mss);
        // K = cubic_root(W_max * (1 - beta) / C), W in segments.
        let w_max = self.w_max as f64 / self.mss as f64;
        let k = cube_root(w_max * (1.0 - BETA_CUBIC) / C).unwrap_or(0.0);
        self.epoch = Some((now, k));
    }
}

impl Controller for Cubic {
    fn window(&self) -> usize {
        self.cwnd
    }

    /// A retransmission timeout: the window is gone, slow start again.
    fn on_retransmit(&mut self, now: Instant) {
        self.loss(now);
        self.cwnd = self.min_cwnd;
    }

    /// A loss found by duplicate ACKs (the socket calls it once a loss).
    fn on_duplicate_ack(&mut self, now: Instant) {
        self.loss(now);
        self.cwnd = self.ssthresh;
    }

    fn set_remote_window(&mut self, remote_window: usize) {
        if self.rwnd < remote_window {
            self.rwnd = remote_window;
        }
    }

    fn on_ack(&mut self, _now: Instant, len: usize, rtt: &crate::socket::tcp::RttEstimator) {
        if rtt.have_measurement {
            self.srtt_ms = rtt.srtt;
        }
        // Slow start.
        if self.cwnd < self.ssthresh {
            self.cwnd = self
                .cwnd
                .saturating_add(len)
                .min(self.ssthresh.max(self.cwnd))
                .min(self.rwnd)
                .max(self.min_cwnd);
        }
    }

    fn pre_transmit(&mut self, now: Instant) {
        // Congestion avoidance only.
        if self.cwnd < self.ssthresh {
            return;
        }
        let (start, k) = match self.epoch {
            Some(epoch) => epoch,
            None => {
                // Left slow start without a loss: the curve starts here.
                self.w_max = self.cwnd;
                self.epoch = Some((now, 0.0));
                (now, 0.0)
            }
        };
        if now < start {
            return;
        }
        let t = (now - start).total_millis();
        // W(t) = C (t - K)^3 + W_max, in segments.
        let w_max = self.w_max as f64 / self.mss as f64;
        let s = t as f64 / 1000.0 - k;
        let mut w = C * s * s * s + w_max;
        // Where it would grow slower than Reno does (small windows, short
        // round trips: the curve takes seconds to come back), Reno's:
        // W_est(t) = W_max beta + 3 (1 - beta) / (1 + beta) t / RTT.
        if self.srtt_ms > 0 {
            let w_est = w_max * BETA_CUBIC
                + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * t as f64 / self.srtt_ms as f64;
            w = w.max(w_est);
        }
        let cwnd = (w * self.mss as f64).max(0.0) as usize;
        self.cwnd = cwnd.max(self.min_cwnd).min(self.rwnd.max(self.min_cwnd));
    }

    fn set_mss(&mut self, mss: usize) {
        self.min_cwnd = mss;
        self.mss = mss.max(1);
        if self.epoch.is_none() && self.ssthresh == usize::MAX {
            self.cwnd = self.cwnd.max(INITIAL_WINDOW * mss);
        }
    }
}

#[inline]
fn abs(a: f64) -> f64 {
    if a < 0.0 { -a } else { a }
}

/// Calculate cube root by using the Newton-Raphson method.
fn cube_root(a: f64) -> Option<f64> {
    if a <= 0.0 {
        return None;
    }

    let (tolerance, init) = if a < 1_000.0 {
        (1.0, 8.879040017426005) // cube_root(700.0)
    } else if a < 1_000_000.0 {
        (5.0, 88.79040017426004) // cube_root(700_000.0)
    } else if a < 1_000_000_000.0 {
        (50.0, 887.9040017426004) // cube_root(700_000_000.0)
    } else if a < 1_000_000_000_000.0 {
        (500.0, 8879.040017426003) // cube_root(700_000_000_000.0)
    } else if a < 1_000_000_000_000_000.0 {
        (5000.0, 88790.40017426001) // cube_root(700_000_000_000.0)
    } else {
        (50000.0, 887904.0017426) // cube_root(700_000_000_000_000.0)
    };

    let mut x = init; // initial value
    let mut n = 20; // The maximum iteration
    loop {
        let next_x = (2.0 * x + a / (x * x)) / 3.0;
        if abs(next_x - x) < tolerance {
            return Some(next_x);
        }
        x = next_x;

        if n == 0 {
            return Some(next_x);
        }

        n -= 1;
    }
}

#[cfg(test)]
mod test {
    use crate::{socket::tcp::RttEstimator, time::Instant};

    use super::*;

    #[test]
    fn test_cubic() {
        let remote_window = 64 * 1024 * 1024;
        let now = Instant::from_millis(0);

        for i in 0..10 {
            for j in 0..9 {
                let mut cubic = Cubic::new();
                // Set remote window.
                cubic.set_remote_window(remote_window);

                cubic.set_mss(1480);

                if i & 1 == 0 {
                    cubic.on_retransmit(now);
                } else {
                    cubic.on_duplicate_ack(now);
                }

                cubic.pre_transmit(now);

                let mut n = i;
                for _ in 0..j {
                    n *= i;
                }

                let elapsed = Instant::from_millis(n);
                cubic.pre_transmit(elapsed);

                let cwnd = cubic.window();
                println!("Cubic: elapsed = {}, cwnd = {}", elapsed, cwnd);

                assert!(cwnd >= cubic.min_cwnd);
                assert!(cubic.window() <= remote_window);
            }
        }
    }

    #[test]
    fn cubic_time_inversion() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_retransmit(t2);
        cubic.pre_transmit(t1);

        let cwnd = cubic.window();
        println!("Cubic:time_inversion: cwnd: {}, cubic: {cubic:?}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_long_elapsed_time() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_micros(i64::MAX);

        cubic.on_retransmit(t1);
        cubic.pre_transmit(t2);

        let cwnd = cubic.window();
        println!("Cubic:long_elapsed_time: cwnd: {}", cwnd);

        assert!(cwnd >= cubic.min_cwnd);
        assert!(cwnd <= cubic.rwnd);
    }

    #[test]
    fn cubic_last_update() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_millis(0);
        let t2 = Instant::from_millis(100);
        let t3 = Instant::from_millis(199);
        let t4 = Instant::from_millis(20000);

        cubic.on_retransmit(t1);

        cubic.pre_transmit(t2);
        let cwnd2 = cubic.window();

        cubic.pre_transmit(t3);
        let cwnd3 = cubic.window();

        cubic.pre_transmit(t4);
        let cwnd4 = cubic.window();

        println!(
            "Cubic:last_update: cwnd2: {}, cwnd3: {}, cwnd4: {}",
            cwnd2, cwnd3, cwnd4
        );

        // Out of slow start, the window follows the curve, back up to
        // where it was long after the loss.
        assert!(cwnd2 <= cwnd3);
        assert!(cwnd3 < cwnd4);
    }

    #[test]
    fn cubic_slow_start() {
        let mut cubic = Cubic::new();

        let t1 = Instant::from_micros(0);

        let cwnd = cubic.window();
        let ack_len = 1024;

        cubic.on_ack(t1, ack_len, &RttEstimator::default());

        assert!(cubic.window() > cwnd);

        for i in 1..1000 {
            let t2 = Instant::from_micros(i);
            cubic.on_ack(t2, ack_len * 100, &RttEstimator::default());
            assert!(cubic.window() <= cubic.rwnd);
        }

        let t3 = Instant::from_micros(2000);

        let cwnd = cubic.window();
        cubic.on_retransmit(t3);
        assert_eq!((cwnd as f64 * BETA_CUBIC) as usize, cubic.ssthresh);
        assert_eq!(cubic.window(), cubic.min_cwnd);
    }

    #[test]
    fn cubic_pre_transmit() {
        let mut cubic = Cubic::new();
        cubic.pre_transmit(Instant::from_micros(2000));
    }

    #[test]
    fn a_loss_backs_off_once_and_the_curve_regains_it() {
        let mut cubic = Cubic::new();
        cubic.set_remote_window(64 << 20);
        cubic.set_mss(1000);
        assert_eq!(cubic.window(), 10_000, "the initial window");
        // Slow start to 1 MB.
        cubic.on_ack(Instant::ZERO, 990_000, &RttEstimator::default());
        assert_eq!(cubic.window(), 1_000_000);

        let at = Instant::from_secs(1);
        cubic.on_duplicate_ack(at);
        assert_eq!(cubic.window(), 700_000);
        // K = cbrt(1000 * 0.3 / 0.4) = 9.1 s: back at W_max then, not
        // (as with octets for segments) after 90 s.
        cubic.pre_transmit(at + crate::time::Duration::from_millis(9086));
        assert!(
            (990_000..=1_010_000).contains(&cubic.window()),
            "{}",
            cubic.window()
        );
        cubic.pre_transmit(at + crate::time::Duration::from_secs(15));
        assert!(cubic.window() > 1_050_000, "and past it, probing");
    }

    #[test]
    fn test_cube_root() {
        for n in (1..1000000).step_by(99) {
            let a = n as f64;
            let a = a * a * a;
            let result = cube_root(a);
            println!("cube_root({a}) = {}", result.unwrap());
        }
    }

    #[test]
    #[should_panic]
    fn cube_root_zero() {
        cube_root(0.0).unwrap();
    }
}
