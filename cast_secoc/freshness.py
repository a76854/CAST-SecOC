"""
Freshness Manager — counter-based FV with truncation and reconstruction.
Eqs. (5)–(8) from the paper.
"""
from dataclasses import dataclass
from enum import Enum, auto


class RxState(Enum):
    """Eq.(9): Receiver internal states."""
    SYNC = auto()
    DESYNC = auto()
    RESYNC_PENDING = auto()
    ROLLOVER_PENDING = auto()


class FvRelation(Enum):
    """Eq.(10): Input freshness value relationship."""
    NEXT = auto()           # Fresh, in sequence
    STALE = auto()          # Duplicate or older
    IN_WINDOW_GAP = auto()  # Within W, but with a gap
    OUT_OF_WINDOW = auto()  # Beyond W
    WRAP_CANDIDATE = auto() # Near rollover boundary


@dataclass
class FreshnessState:
    """Receiver-side freshness tracking."""
    fv_last: int = 0              # Last accepted full FV
    state: RxState = RxState.SYNC
    epoch: int = 0                # Rollover epoch counter
    resync_requested: bool = False

    def copy(self) -> "FreshnessState":
        return FreshnessState(self.fv_last, self.state, self.epoch, self.resync_requested)


class FreshnessManager:
    """Manages FV generation (sender) and reconstruction (receiver)."""

    def __init__(self, bit_width: int = 32, trunc_bits: int = 12, window: int = 16):
        self.b = bit_width          # Full FV bit width
        self.lmbda = trunc_bits     # Transmitted FV field length
        self.W = window             # Receive window
        self._counter = 0           # Sender counter
        self._rx_state = FreshnessState()

    # ── Sender API ─────────────────────────────────────────────────

    def next_fv(self) -> int:
        """Generate next full FV for sender."""
        fv = self._counter
        self._counter = (self._counter + 1) % (1 << self.b)
        return fv

    @property
    def sender_counter(self) -> int:
        return self._counter

    def truncate(self, full_fv: int) -> int:
        """Truncate full FV to transmitted field width."""
        return full_fv & ((1 << self.lmbda) - 1)

    # ── Receiver API — Eq.(5)–(8) ──────────────────────────────────

    def reconstruct(self, fv_tr: int) -> tuple[int | None, FvRelation]:
        """Eq.(5)–(8): Reconstruct full FV from truncated value.
        Returns (reconstructed_fv_or_None, relation).
        """
        # Handle special states
        if self._rx_state.state in (RxState.DESYNC, RxState.RESYNC_PENDING):
            return None, FvRelation.OUT_OF_WINDOW

        x = fv_tr
        shift = 1 << self.lmbda

        # Eq.(5): high bits estimate
        h = self._rx_state.fv_last // shift

        # Eq.(6): candidate set
        candidates = []
        for j in (-1, 0, 1):
            val = (h + j) * shift + x
            if 0 <= val < (1 << self.b):
                candidates.append(val)

        if not candidates:
            return None, FvRelation.OUT_OF_WINDOW

        # In ROLLOVER_PENDING, the full 32-bit counter may have wrapped.
        # j∈{-1,0,1} can't see across the 2^32 boundary.
        # The truncated value x itself is the post-rollover epoch FV
        # (e.g. fv_last=2^32-3, sender wraps to 0, sends FV=5 → x=5).
        if self._rx_state.state == RxState.ROLLOVER_PENDING:
            # Low truncated values (< shift) are post-rollover candidates
            if x < self.W + 1:
                return int(x), FvRelation.WRAP_CANDIDATE
            # Higher candidates from j∈{-1,0,1} search
            fresh = [y for y in candidates if y > self._rx_state.fv_last]
            if fresh:
                return min(fresh), FvRelation.WRAP_CANDIDATE
            return min(candidates), FvRelation.STALE

        # Eq.(7): acceptable window candidates (non-rollover)
        acceptable = [y for y in candidates
                      if 0 < y - self._rx_state.fv_last <= self.W]

        # Check rollover condition (for non-ROLLOVER_PENDING state)
        near_upper = self._rx_state.fv_last > (1 << self.b) - self.W
        low_candidates = [y for y in candidates if y < shift]

        if near_upper and low_candidates:
            return min(low_candidates), FvRelation.WRAP_CANDIDATE

        if acceptable:
            # Eq.(8): pick minimum acceptable
            fv_hat = min(acceptable)
            gap = fv_hat - self._rx_state.fv_last
            if gap == 1:
                return fv_hat, FvRelation.NEXT
            else:
                return fv_hat, FvRelation.IN_WINDOW_GAP

        if candidates:
            best = min(candidates)
            if best == self._rx_state.fv_last:
                return best, FvRelation.STALE
            elif best > self._rx_state.fv_last:
                return best, FvRelation.OUT_OF_WINDOW
            else:
                return best, FvRelation.STALE

        return None, FvRelation.OUT_OF_WINDOW

    def accept(self, fv: int, authenticated: bool) -> None:
        """Update state after accepting (or rejecting) a candidate."""
        if authenticated and fv > self._rx_state.fv_last:
            self._rx_state.fv_last = fv
            if self._rx_state.state == RxState.ROLLOVER_PENDING:
                self._rx_state.epoch += 1
                self._rx_state.state = RxState.SYNC
            elif self._rx_state.state == RxState.RESYNC_PENDING:
                self._rx_state.state = RxState.SYNC

    def set_state(self, state: RxState) -> None:
        self._rx_state.state = state

    @property
    def rx_state(self) -> FreshnessState:
        return self._rx_state

    @rx_state.setter
    def rx_state(self, value: FreshnessState) -> None:
        self._rx_state = value

    def reset_rx(self) -> None:
        self._rx_state = FreshnessState()

    # ── State preparation helpers (Table 3) ────────────────────────

    def prepare_sync(self, fv_start: int = 0) -> None:
        """Prepare SYNC state — restore known checkpoint.
        Sets receiver fv_last AND sender counter to ensure FV sync."""
        self._rx_state = FreshnessState(fv_last=fv_start, state=RxState.SYNC)
        self._counter = fv_start + 1  # Sender starts after receiver's last accepted

    def prepare_desync(self) -> None:
        """Prepare DESYNC state — set FV to a value far from sender."""
        self._rx_state = FreshnessState(fv_last=0xFFFF0000, state=RxState.DESYNC)

    def prepare_rollover_pending(self) -> None:
        """Put FV near upper bound to trigger rollover handling."""
        near_max = (1 << self.b) - 3
        self._rx_state = FreshnessState(fv_last=near_max, state=RxState.ROLLOVER_PENDING)
        self._counter = near_max + 1  # Sender continues from near max

    def prepare_resync_pending(self) -> None:
        """Set state to RESYNC_PENDING."""
        self._rx_state.state = RxState.RESYNC_PENDING
