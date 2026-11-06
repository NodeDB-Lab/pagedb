//! 96-bit nonce: `file_id[0..6] ‖ counter_le_u48`. Plus the in-memory
//! anchor state machine for main.db nonces. Durability of the anchor
//! (fsync to A/B header) is the header layer's responsibility — this module
//! exposes `pending_anchor()` so the header writer can persist the right value.
//!
//! A follower shares its source's key and `file_id`. So a Follower handle seals
//! its own `main.db` pages under a random prefix drawn at each open, never under
//! `file_id[0..6]`. Delta pages land verbatim and keep the source's prefix.

use crate::Result;
use crate::errors::PagedbError;

/// 96-bit AEAD nonce.
#[derive(Debug, Clone, Copy)]
pub struct Nonce([u8; 12]);

impl Nonce {
    pub const COUNTER_MAX: u64 = (1u64 << 48) - 1;

    /// Build a nonce from a 6-byte file-id partition and a 48-bit counter.
    /// Counters past `COUNTER_MAX` are forbidden; the constructor truncates
    /// silently here — callers reach this only after the counter-state
    /// machine has already permitted the value. Use `MainDbNonceGen` /
    /// `SegmentNonceGen` to obtain counters safely.
    #[must_use]
    pub fn from_parts(file_id6: [u8; 6], counter: u64) -> Self {
        let mut out = [0u8; 12];
        out[..6].copy_from_slice(&file_id6);
        let le = counter.to_le_bytes();
        out[6..].copy_from_slice(&le[..6]);
        Self(out)
    }

    /// Build a nonce directly from a 12-byte array. Intended for reconstructing
    /// a stored nonce (e.g., from a spill segment metadata record).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 12]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }

    /// Adapter for the `aes-gcm` crate (`Nonce<U12>`).
    #[must_use]
    pub fn as_aead_nonce(&self) -> &aes_gcm::Nonce<aes_gcm::aes::cipher::consts::U12> {
        aes_gcm::Nonce::from_slice(&self.0)
    }

    /// Adapter for the `chacha20poly1305` crate (`Nonce`).
    #[must_use]
    pub fn as_chacha_nonce(&self) -> &chacha20poly1305::Nonce {
        chacha20poly1305::Nonce::from_slice(&self.0)
    }
}

/// Default budget `N` between durable anchor commits. The invariant is
/// `durable_anchor < n ≤ durable_anchor + N` for every issued nonce `n`.
pub const DEFAULT_ANCHOR_BUDGET: u64 = 1024;

/// Largest budget a generator honours. A larger option issues under this value.
///
/// No file records the budget of an earlier run, so an open cannot rely on the
/// current option. Every run stays inside this window above its durable anchor.
/// [`MainDbNonceGen::recover`] always skips the whole window.
///
/// One open that writes a header spends `2^20` counter values. The 48-bit counter
/// therefore lasts `2^48 / 2^20 = 2^28` (268,435,456) such opens, before sealed
/// pages are counted. That is about 8.5 years at one such open per second.
pub const MAX_ANCHOR_BUDGET: u64 = 1 << 20;

/// main.db nonce generator. Tracks `(durable_anchor, next_nonce)`. When
/// `next_nonce` would exceed `durable_anchor + budget`, callers must persist
/// `pending_anchor()` to the A/B header and call `commit_anchor()` before
/// requesting another nonce.
pub struct MainDbNonceGen {
    prefix: [u8; 6],
    next: u64,
    durable_anchor: u64,
    budget: u64,
}

impl MainDbNonceGen {
    /// Build a fresh generator at DB creation. `next` starts at 1 (anchor 0,
    /// no nonces issued yet — first issued counter is 1, well inside
    /// `(0, budget]`).
    #[must_use]
    pub fn new(file_id: &[u8; 16], budget: u64) -> Self {
        let mut prefix = [0u8; 6];
        prefix.copy_from_slice(&file_id[..6]);
        Self {
            prefix,
            next: 1,
            durable_anchor: 0,
            budget: budget.min(MAX_ANCHOR_BUDGET),
        }
    }

    /// Reconstruct at an open: `next_nonce := recovered_anchor + MAX_ANCHOR_BUDGET + 1`.
    ///
    /// `next` is strictly greater than every counter an earlier run issued under
    /// this anchor, whichever budget that run used.
    ///
    /// `durable_anchor` stays at the recovered value, because the header holds that
    /// value. The issuing window therefore starts empty. The first flush persists
    /// `pending_anchor()` and calls `commit_anchor` before it seals a page.
    #[must_use]
    pub fn recover(file_id: &[u8; 16], recovered_anchor: u64, budget: u64) -> Self {
        let mut prefix = [0u8; 6];
        prefix.copy_from_slice(&file_id[..6]);
        let next = recovered_anchor
            .saturating_add(MAX_ANCHOR_BUDGET)
            .saturating_add(1);
        Self {
            prefix,
            next,
            durable_anchor: recovered_anchor,
            budget: budget.min(MAX_ANCHOR_BUDGET),
        }
    }

    /// Issue every later nonce under `prefix`. The counter and the anchor stay as
    /// they are.
    pub(crate) fn use_prefix(&mut self, prefix: [u8; 6]) {
        self.prefix = prefix;
    }

    #[cfg(test)]
    pub(crate) fn prefix(&self) -> [u8; 6] {
        self.prefix
    }

    /// Issue the next nonce. Returns `Aborted` if a commit is required first
    /// (caller must persist `pending_anchor()` to the header and call
    /// `commit_anchor`). Returns `NonceCounterExhausted` if the 48-bit
    /// counter space is full.
    pub fn next_nonce(&mut self) -> Result<Nonce> {
        if self.next > Nonce::COUNTER_MAX {
            return Err(PagedbError::NonceCounterExhausted);
        }
        if self.next > self.durable_anchor.saturating_add(self.budget) {
            // Caller must commit the anchor first.
            return Err(PagedbError::Aborted);
        }
        let n = Nonce::from_parts(self.prefix, self.next);
        self.next += 1;
        Ok(n)
    }

    /// The anchor value the header writer should persist next. Always equals
    /// `next - 1` (the largest nonce already issued). After fsyncing this
    /// value to both A/B headers, call `commit_anchor(value)`.
    #[must_use]
    pub fn pending_anchor(&self) -> u64 {
        self.next.saturating_sub(1)
    }

    /// How many more nonces can be issued before the durable anchor has to be
    /// advanced. Zero means the next `next_nonce()` returns `Aborted`.
    ///
    /// Callers that issue nonces in long runs — a compaction rebuild, a rekey
    /// re-seal, a large flush — size their work against this instead of against
    /// a fixed page count: the budget is configurable and can be far smaller
    /// than one flush.
    #[must_use]
    pub fn window_remaining(&self) -> u64 {
        self.durable_anchor
            .saturating_add(self.budget)
            .saturating_sub(self.pending_anchor())
    }

    /// The anchor value currently persisted in the A/B header.
    #[cfg(test)]
    #[must_use]
    pub fn durable_anchor(&self) -> u64 {
        self.durable_anchor
    }

    /// Notify the generator that the header writer has durably persisted the
    /// supplied anchor. Must be ≥ the current `durable_anchor` and ≤
    /// `pending_anchor()`.
    pub fn commit_anchor(&mut self, persisted: u64) -> Result<()> {
        if persisted < self.durable_anchor || persisted > self.pending_anchor() {
            return Err(PagedbError::Aborted);
        }
        self.durable_anchor = persisted;
        Ok(())
    }
}

/// Segment nonce generator. No durability anchor — the seal record commits
/// the entire range atomically. Caller is responsible for honoring the
/// tentative-until-seal contract: pre-seal nonces have no anchor.
pub struct SegmentNonceGen {
    file_id6: [u8; 6],
    next: u64,
}

impl SegmentNonceGen {
    #[must_use]
    pub fn new(segment_id: &[u8; 16]) -> Self {
        let mut f = [0u8; 6];
        f.copy_from_slice(&segment_id[..6]);
        Self {
            file_id6: f,
            next: 1,
        }
    }

    /// Issue the next nonce. The final value reached before `seal()` is the
    /// `final_counter` persisted in the footer; the footer manifest itself
    /// uses counter `final_counter + 1` (caller manages this — call
    /// `next_counter_value()` to fetch the counter without building a nonce
    /// if you need to record it in a footer record).
    pub fn next_nonce(&mut self) -> Result<Nonce> {
        if self.next > Nonce::COUNTER_MAX {
            return Err(PagedbError::NonceCounterExhausted);
        }
        let n = Nonce::from_parts(self.file_id6, self.next);
        self.next += 1;
        Ok(n)
    }

    /// The counter value the next `next_nonce()` call would consume.
    ///
    /// The segment writer derives page ids from its own append cursor, so only
    /// tests call this.
    #[cfg(test)]
    #[must_use]
    pub fn peek_counter(&self) -> u64 {
        self.next
    }

    /// The largest counter value already issued (or 0 if none yet).
    #[must_use]
    pub fn final_counter(&self) -> u64 {
        self.next.saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_layout_matches_spec() {
        let n = Nonce::from_parts([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11], 0x0102_0304_0506);
        let bytes = n.as_bytes();
        assert_eq!(&bytes[..6], &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11]);
        // Little-endian 48-bit counter: 0x06 0x05 0x04 0x03 0x02 0x01
        assert_eq!(&bytes[6..], &[0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn main_db_issues_within_budget() {
        let mut g = MainDbNonceGen::new(&[0; 16], 4);
        for i in 1..=4 {
            let n = g.next_nonce().unwrap();
            let mut want = [0u8; 6];
            want[0] = u8::try_from(i).unwrap();
            assert_eq!(&n.as_bytes()[6..], &want);
        }
        // Fifth issue must require an anchor commit.
        assert!(matches!(g.next_nonce(), Err(PagedbError::Aborted)));
    }

    #[test]
    fn main_db_commit_anchor_unblocks_issue() {
        let mut g = MainDbNonceGen::new(&[0; 16], 4);
        for _ in 0..4 {
            let _ = g.next_nonce().unwrap();
        }
        let pending = g.pending_anchor();
        assert_eq!(pending, 4);
        g.commit_anchor(pending).unwrap();
        // Now another budget-full slice is available.
        for _ in 0..4 {
            let _ = g.next_nonce().unwrap();
        }
        assert!(matches!(g.next_nonce(), Err(PagedbError::Aborted)));
    }

    #[test]
    fn window_remaining_tracks_issued_and_committed_nonces() {
        let mut g = MainDbNonceGen::new(&[0; 16], 4);
        assert_eq!(g.window_remaining(), 4);
        let _ = g.next_nonce().unwrap();
        let _ = g.next_nonce().unwrap();
        assert_eq!(g.window_remaining(), 2);
        let pending = g.pending_anchor();
        g.commit_anchor(pending).unwrap();
        assert_eq!(g.durable_anchor(), 2);
        // A committed anchor restores the whole budget without issuing anything.
        assert_eq!(g.window_remaining(), 4);
        for _ in 0..4 {
            let _ = g.next_nonce().unwrap();
        }
        assert_eq!(g.window_remaining(), 0);
        assert!(matches!(g.next_nonce(), Err(PagedbError::Aborted)));
    }

    fn counter_of(nonce: &Nonce) -> u64 {
        let mut buf = [0u8; 8];
        buf[..6].copy_from_slice(&nonce.as_bytes()[6..]);
        u64::from_le_bytes(buf)
    }

    #[test]
    fn first_flush_after_open_persists_the_anchor_before_sealing() {
        let mut g = MainDbNonceGen::recover(&[0; 16], 1000, 1024);
        assert_eq!(g.window_remaining(), 0);
        assert_eq!(g.durable_anchor(), 1000);
        assert!(matches!(g.next_nonce(), Err(PagedbError::Aborted)));

        let pending = g.pending_anchor();
        assert_eq!(pending, 1000 + MAX_ANCHOR_BUDGET);
        g.commit_anchor(pending).unwrap();

        assert_eq!(g.window_remaining(), 1024);
        let first = g.next_nonce().unwrap();
        assert_eq!(counter_of(&first), 1000 + MAX_ANCHOR_BUDGET + 1);
    }

    #[test]
    fn an_open_skips_the_maximum_budget_whatever_the_option() {
        for budget in [1, 8, 1024, MAX_ANCHOR_BUDGET, MAX_ANCHOR_BUDGET * 4] {
            let g = MainDbNonceGen::recover(&[0; 16], 1000, budget);
            assert_eq!(g.pending_anchor(), 1000 + MAX_ANCHOR_BUDGET, "{budget}");
        }
    }

    #[test]
    fn a_budget_above_the_maximum_issues_under_the_maximum() {
        let fresh = MainDbNonceGen::new(&[0; 16], MAX_ANCHOR_BUDGET + 5);
        assert_eq!(fresh.window_remaining(), MAX_ANCHOR_BUDGET);

        let mut recovered = MainDbNonceGen::recover(&[0; 16], 7, MAX_ANCHOR_BUDGET + 5);
        let pending = recovered.pending_anchor();
        recovered.commit_anchor(pending).unwrap();
        assert_eq!(recovered.window_remaining(), MAX_ANCHOR_BUDGET);
    }

    #[test]
    fn the_counter_lasts_the_stated_number_of_opens() {
        assert_eq!((Nonce::COUNTER_MAX + 1) / MAX_ANCHOR_BUDGET, 1 << 28);
    }

    #[test]
    fn a_local_prefix_replaces_the_file_prefix_and_keeps_the_counter() {
        let mut g = MainDbNonceGen::new(&[0xAA; 16], 8);
        let before = g.next_nonce().unwrap();
        assert_eq!(&before.as_bytes()[..6], &[0xAA; 6]);

        g.use_prefix([0x5C; 6]);
        let after = g.next_nonce().unwrap();
        assert_eq!(&after.as_bytes()[..6], &[0x5C; 6]);
        assert_eq!(counter_of(&after), counter_of(&before) + 1);
    }

    #[test]
    fn segment_counter_progress() {
        let mut g = SegmentNonceGen::new(&[1; 16]);
        let _ = g.next_nonce().unwrap();
        let _ = g.next_nonce().unwrap();
        assert_eq!(g.final_counter(), 2);
        assert_eq!(g.peek_counter(), 3);
    }
}
