//! 96-bit nonce: `file_id[0..6] ‖ counter_le_u48`. Plus the in-memory
//! anchor state machine for main.db nonces. Durability of the anchor
//! (fsync to A/B header) is the header layer's responsibility — this module
//! exposes `pending_anchor()` so the header writer can persist the right value.

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
    pub fn from_parts(file_id6: &[u8; 6], counter: u64) -> Self {
        let mut out = [0u8; 12];
        out[..6].copy_from_slice(file_id6);
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

/// main.db nonce generator. Tracks `(durable_anchor, next_nonce)`. When
/// `next_nonce` would exceed `durable_anchor + budget`, callers must persist
/// `pending_anchor()` to the A/B header and call `commit_anchor()` before
/// requesting another nonce.
pub struct MainDbNonceGen {
    file_id6: [u8; 6],
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
        let mut f = [0u8; 6];
        f.copy_from_slice(&file_id[..6]);
        Self {
            file_id6: f,
            next: 1,
            durable_anchor: 0,
            budget,
        }
    }

    /// Reconstruct on recovery: `next_nonce := recovered_anchor + budget + 1`.
    /// Guarantees `next` is strictly greater than every pre-crash issued nonce.
    /// `durable_anchor` is advanced to `next - 1` so the first post-recovery
    /// nonce issue succeeds without requiring an immediate anchor commit.
    #[must_use]
    pub fn recover(file_id: &[u8; 16], recovered_anchor: u64, budget: u64) -> Self {
        let mut f = [0u8; 6];
        f.copy_from_slice(&file_id[..6]);
        let next = recovered_anchor.saturating_add(budget).saturating_add(1);
        // Treat the post-crash skip as already anchored: the pager will write
        // the new anchor to the A/B header on the next commit.
        let durable_anchor = next.saturating_sub(1);
        Self {
            file_id6: f,
            next,
            durable_anchor,
            budget,
        }
    }

    /// Issue the next nonce. Returns `Aborted` if a commit is required first
    /// (caller must persist `pending_anchor()` to the header and call
    /// `commit_anchor`). Returns `NonceCounterExhausted` if the 48-bit
    /// counter space is full.
    pub fn next_nonce(&mut self) -> Result<Nonce> {
        if self.next > Nonce::COUNTER_MAX {
            return Err(PagedbError::NonceCounterExhausted);
        }
        if self.next > self.durable_anchor + self.budget {
            // Caller must commit the anchor first.
            return Err(PagedbError::Aborted);
        }
        let n = Nonce::from_parts(&self.file_id6, self.next);
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

    #[must_use]
    pub fn durable_anchor(&self) -> u64 {
        self.durable_anchor
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
        let n = Nonce::from_parts(&self.file_id6, self.next);
        self.next += 1;
        Ok(n)
    }

    /// The counter value the next `next_nonce()` call would consume.
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
        let n = Nonce::from_parts(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11], 0x0102_0304_0506);
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
    fn main_db_recover_jumps_past_pre_crash_window() {
        let g = MainDbNonceGen::recover(&[0; 16], 1000, 1024);
        // Next issued counter must be > 1000 + 1024 = 2024.
        assert_eq!(g.pending_anchor(), 2024);
        // next == 2025
        let mut g = g;
        let n = g.next_nonce().unwrap();
        // The first issued counter is 2025.
        let counter_le = &n.as_bytes()[6..];
        let mut buf = [0u8; 8];
        buf[..6].copy_from_slice(counter_le);
        assert_eq!(u64::from_le_bytes(buf), 2025);
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
