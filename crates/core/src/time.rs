//! Time as the core sees it: [`Instant`], a monotonic point the driver
//! hands in (microseconds since the driver's own epoch), and the wall clock
//! WireGuard's handshake timestamps need ([`unix_now`]).

use core::ops::{Add, AddAssign, Sub, SubAssign};
pub use core::time::Duration;

/// A point in monotonic time: microseconds since the driver's epoch (its
/// start, its boot). Only differences mean anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(u64);

impl Instant {
    pub const ZERO: Self = Self(0);

    pub const fn from_micros(micros: u64) -> Self {
        Self(micros)
    }

    pub const fn as_micros(self) -> u64 {
        self.0
    }

    /// The time from `earlier` to `self`; zero if `earlier` is later (as
    /// `std::time::Instant` does).
    pub fn duration_since(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }

    pub fn saturating_duration_since(self, earlier: Instant) -> Duration {
        Duration::from_micros(self.0.saturating_sub(earlier.0))
    }

    pub fn checked_duration_since(self, earlier: Instant) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_micros)
    }

    pub fn checked_add(self, duration: Duration) -> Option<Instant> {
        u64::try_from(duration.as_micros())
            .ok()
            .and_then(|d| self.0.checked_add(d))
            .map(Self)
    }

    pub fn checked_sub(self, duration: Duration) -> Option<Instant> {
        u64::try_from(duration.as_micros())
            .ok()
            .and_then(|d| self.0.checked_sub(d))
            .map(Self)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    fn add(self, duration: Duration) -> Instant {
        self.checked_add(duration)
            .expect("overflow when adding a duration to an instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, duration: Duration) {
        *self = *self + duration;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, duration: Duration) -> Instant {
        self.checked_sub(duration)
            .expect("overflow when subtracting a duration from an instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, duration: Duration) {
        *self = *self - duration;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    fn sub(self, earlier: Instant) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

static WALL_CLOCK: spin::Once<fn() -> Duration> = spin::Once::new();

/// Where the wall clock comes from without std (SNTP, an RTC): the time since
/// the Unix epoch. The first call wins.
pub fn set_wall_clock(clock: fn() -> Duration) {
    WALL_CLOCK.call_once(|| clock);
}

/// The time since the Unix epoch: the installed clock, else (with std) the
/// system's.
pub fn unix_now() -> Duration {
    if let Some(clock) = WALL_CLOCK.get() {
        return clock();
    }
    #[cfg(feature = "std")]
    return std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    #[cfg(not(feature = "std"))]
    panic!("no wall clock: call mesh_core::time::set_wall_clock first")
}

/// With std: [`Instant`]s from `std::time::Instant`, against one epoch for
/// the process (the drivers and tests on std).
#[cfg(feature = "std")]
mod std_clock {
    use super::{Duration, Instant};
    use std::sync::OnceLock;

    fn epoch() -> std::time::Instant {
        static EPOCH: OnceLock<std::time::Instant> = OnceLock::new();
        *EPOCH.get_or_init(std::time::Instant::now)
    }

    /// Now, against the process's epoch.
    pub fn now() -> Instant {
        from_std(std::time::Instant::now())
    }

    pub fn from_std(instant: std::time::Instant) -> Instant {
        Instant::from_micros(instant.saturating_duration_since(epoch()).as_micros() as u64)
    }

    pub fn to_std(instant: Instant) -> std::time::Instant {
        epoch() + Duration::from_micros(instant.as_micros())
    }
}

#[cfg(feature = "std")]
pub use std_clock::{from_std, now, to_std};
