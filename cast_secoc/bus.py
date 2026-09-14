"""
CAN FD Bus model — physical bit-timing with M/M/1 queueing.
Arbitration: 500 kbit/s, Data: 2 Mbit/s (matching Table 5).
"""
import random
import time


ARB_RATE = 500_000      # 500 kbit/s arbitration
DATA_RATE = 2_000_000   # 2 Mbit/s data phase
ARB_OVERHEAD_BITS = 45  # SOF + ID + RTR + IDE + EDL + r0 + BRS
CRC_EOF_BITS = 40       # CRC + ACK + EOF + IFS
DATA_PER_BYTE_BITS = 9  # 8 data + stuff bit (~1 per byte avg)
BITS_PER_FRAME_FIXED = ARB_OVERHEAD_BITS + CRC_EOF_BITS


def _frame_tx_time_sec(payload_bytes: int) -> float:
    """CAN FD frame transmission time from bit rates.
    Ref: ISO 11898-1:2015, simplified.
    """
    arb_bits = ARB_OVERHEAD_BITS  # arbitration field
    data_bits = payload_bytes * DATA_PER_BYTE_BITS + CRC_EOF_BITS  # data phase

    tx_time = arb_bits / ARB_RATE + data_bits / DATA_RATE
    return tx_time


class CanFDBus:
    """CAN FD bus with configurable load and queueing delay."""

    def __init__(self, load: float = 0.30):
        self.load = load  # Bus load fraction [0, 1]
        self._last_tx_end = 0.0

    def _queue_delay(self, tx_time: float) -> float:
        """M/M/1 queueing delay at given load level.
        At low load → negligible delay.
        At high load → nonlinear blowup (real bus behavior).
        """
        if self.load >= 1.0:
            return float('inf')
        if self.load <= 0.01:
            return 0.0

        mu = 1.0 / tx_time
        lambd = self.load * mu

        # Mean queueing delay: ρ/(μ-λ) where ρ=λ/μ
        rho = self.load
        mean_wait = rho / (mu - lambd) if mu > lambd else tx_time * 10

        # Sample from exponential distribution
        return random.expovariate(1.0 / max(mean_wait, 1e-9))

    def transmit(self, payload_bytes: int) -> float:
        """Transmit a frame, return timestamp when frame arrives at receiver.
        Returns: elapsed seconds including TX time + queueing delay.
        """
        tx_time = _frame_tx_time_sec(payload_bytes)
        queue_wait = self._queue_delay(tx_time)

        # Simulate real time passage
        total = tx_time + queue_wait
        time.sleep(total * 0.001)  # Scale down — simulation not real-time

        return total

    def tx_time_only(self, payload_bytes: int) -> float:
        """Return pure transmission time (no queueing, no sleep)."""
        return _frame_tx_time_sec(payload_bytes)
