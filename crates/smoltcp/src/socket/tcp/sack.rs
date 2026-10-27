//! The sender's SACK scoreboard (RFC 6675; arkitekt-mesh's fork): which
//! octets past the cumulative ACK the receiver says it holds, so that a
//! loss is repaired by sending the holes again, not everything after it.

use crate::wire::TcpSeqNumber;

/// Ranges kept. A receiver reports at most 3 (4 without timestamps) a
/// segment, the most recent first; past this many the highest are dropped,
/// which only makes the sender send more again than it had to.
const RANGES: usize = 32;

/// SACKed ranges above the cumulative ACK: sorted, disjoint, half-open.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Scoreboard {
    ranges: [(TcpSeqNumber, TcpSeqNumber); RANGES],
    len: usize,
}

impl Default for Scoreboard {
    fn default() -> Self {
        Self {
            ranges: [(TcpSeqNumber(0), TcpSeqNumber(0)); RANGES],
            len: 0,
        }
    }
}

impl Scoreboard {
    fn ranges(&self) -> &[(TcpSeqNumber, TcpSeqNumber)] {
        &self.ranges[..self.len]
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Record that the receiver holds `start..end`, of what was sent
    /// between `una` (the cumulative ACK) and `nxt`; anything else in the
    /// block is ignored (stale, or not ours).
    pub(crate) fn add(
        &mut self,
        start: TcpSeqNumber,
        end: TcpSeqNumber,
        una: TcpSeqNumber,
        nxt: TcpSeqNumber,
    ) {
        let (start, end) = (start.max(una), end.min(nxt));
        if start >= end {
            return;
        }
        // Where it goes, and every range it touches merges into it.
        let first = self
            .ranges()
            .iter()
            .position(|r| r.1 >= start)
            .unwrap_or(self.len);
        let mut last = first;
        let (mut start, mut end) = (start, end);
        while last < self.len && self.ranges[last].0 <= end {
            start = start.min(self.ranges[last].0);
            end = end.max(self.ranges[last].1);
            last += 1;
        }
        let removed = last - first;
        if removed == 0 {
            if self.len == RANGES {
                if first == RANGES {
                    return;
                }
                // Full: the highest range goes.
                self.len -= 1;
            }
            self.ranges.copy_within(first..self.len, first + 1);
            self.len += 1;
        } else {
            self.ranges.copy_within(last..self.len, first + 1);
            self.len -= removed - 1;
        }
        self.ranges[first] = (start, end);
    }

    /// Forget what the cumulative ACK, now `una`, covers.
    pub(crate) fn acked(&mut self, una: TcpSeqNumber) {
        let gone = self.ranges().iter().take_while(|r| r.1 <= una).count();
        self.ranges.copy_within(gone..self.len, 0);
        self.len -= gone;
        if let Some(first) = self.ranges[..self.len].first_mut() {
            first.0 = first.0.max(una);
        }
    }

    /// The highest octet SACKed, plus one.
    pub(crate) fn highest(&self) -> Option<TcpSeqNumber> {
        self.ranges().last().map(|r| r.1)
    }

    /// Octets SACKed in all.
    pub(crate) fn sacked(&self) -> usize {
        self.ranges().iter().map(|r| r.1 - r.0).sum()
    }

    /// Octets SACKed at or above `seq`.
    pub(crate) fn sacked_above(&self, seq: TcpSeqNumber) -> usize {
        self.ranges()
            .iter()
            .filter(|r| r.1 > seq)
            .map(|r| r.1 - r.0.max(seq))
            .sum()
    }

    /// The first hole (octets not SACKed) at or after `from` and before
    /// `until`, as (start, length).
    pub(crate) fn hole(
        &self,
        from: TcpSeqNumber,
        until: TcpSeqNumber,
    ) -> Option<(TcpSeqNumber, usize)> {
        let mut at = from;
        for &(start, end) in self.ranges() {
            if end <= at {
                continue;
            }
            if start > at {
                break;
            }
            at = end;
        }
        if at >= until {
            return None;
        }
        let next = self
            .ranges()
            .iter()
            .map(|r| r.0)
            .find(|&start| start > at)
            .map_or(until, |start| start.min(until));
        Some((at, next - at))
    }

    /// Octets in holes between `from` and `until`.
    pub(crate) fn holes(&self, from: TcpSeqNumber, until: TcpSeqNumber) -> usize {
        if from >= until {
            return 0;
        }
        let sacked: usize = self
            .ranges()
            .iter()
            .filter(|r| r.1 > from && r.0 < until)
            .map(|r| r.1.min(until) - r.0.max(from))
            .sum();
        (until - from) - sacked
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn s(n: i32) -> TcpSeqNumber {
        TcpSeqNumber(n)
    }

    fn board(ranges: &[(i32, i32)]) -> Scoreboard {
        let mut b = Scoreboard::default();
        for &(start, end) in ranges {
            b.add(s(start), s(end), s(0), s(10_000));
        }
        b
    }

    fn list(b: &Scoreboard) -> Vec<(i32, i32)> {
        b.ranges().iter().map(|r| (r.0.0, r.1.0)).collect()
    }

    #[test]
    fn ranges_merge_and_stay_sorted() {
        let b = board(&[(300, 400), (100, 200), (500, 600), (200, 250), (390, 510)]);
        assert_eq!(list(&b), [(100, 250), (300, 600)]);
        assert_eq!(b.sacked(), 450);
        assert_eq!(b.highest(), Some(s(600)));
    }

    #[test]
    fn blocks_outside_what_was_sent_are_clipped() {
        let mut b = Scoreboard::default();
        b.add(s(50), s(150), s(100), s(1000));
        b.add(s(900), s(1200), s(100), s(1000));
        b.add(s(10), s(90), s(100), s(1000));
        assert_eq!(list(&b), [(100, 150), (900, 1000)]);
    }

    #[test]
    fn the_cumulative_ack_retires_ranges() {
        let mut b = board(&[(100, 200), (300, 400)]);
        b.acked(s(150));
        assert_eq!(list(&b), [(150, 200), (300, 400)]);
        b.acked(s(350));
        assert_eq!(list(&b), [(350, 400)]);
        b.acked(s(400));
        assert!(b.is_empty());
    }

    #[test]
    fn holes_between_the_ranges() {
        let b = board(&[(100, 200), (300, 400)]);
        assert_eq!(b.hole(s(0), s(400)), Some((s(0), 100)));
        assert_eq!(b.hole(s(100), s(400)), Some((s(200), 100)));
        assert_eq!(b.hole(s(250), s(400)), Some((s(250), 50)));
        assert_eq!(b.hole(s(300), s(400)), None);
        assert_eq!(b.hole(s(300), s(1000)), Some((s(400), 600)));
        assert_eq!(b.holes(s(0), s(400)), 200);
        assert_eq!(b.holes(s(150), s(350)), 100);
        assert_eq!(b.sacked_above(s(150)), 150);
    }

    #[test]
    fn a_full_board_drops_the_highest() {
        let mut b = Scoreboard::default();
        for i in 0..RANGES as i32 + 4 {
            b.add(s(i * 10), s(i * 10 + 5), s(0), s(100_000));
        }
        assert_eq!(b.len, RANGES);
        assert_eq!(b.highest(), Some(s((RANGES as i32 - 1) * 10 + 5)));
        // A lower one still gets in.
        b.add(s(1), s(3), s(0), s(100_000));
        assert_eq!(b.len, RANGES);
        assert_eq!(list(&b)[0], (0, 5));
    }
}
