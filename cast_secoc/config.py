"""
Configuration model — Eq.(15) from the paper.
Each SecOCConfig captures authentication length, freshness parameters,
window, rollover policy, authentication area, crypto context mapping,
timeout policy, and persistence policy.
"""
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecOCConfig:
    """Eq.(15): SecOC configuration for a message."""
    # Authentication
    ell: int = 64          # Truncated MAC length (bits)
    # Freshness
    lambda_: int = 12       # Transmitted FV field length (bits)
    b: int = 32             # Full FV bit-width
    W: int = 16             # Receive window
    # Rollover / resync
    rho: str = "AUTH_RESTRICTED"  # Rollover policy
    # Authentication area — (offset, length) in bytes
    A: tuple[int, int] = (0, 16)
    # Crypto context — (auth_service_config_ref, csm_job_id, key_ref)
    kappa: tuple = (0, 0, 0)
    # Timeout and persistence
    timeout_policy: str = "REJECT_AND_REPORT"
    timeout_ms: float = 100.0   # Verification timeout threshold (ms)
    persist_policy: str = "ON_AUTH_UPDATE"
    # Per-message base config
    msg_id: str = ""
    data_id: int = 0

    @property
    def config_hash(self) -> str:
        raw = json.dumps(self.__dict__, sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class MessageSpec:
    """Eq.(14): Message definition — sensor/control semantics."""
    can_id: int            # CAN ID
    data_id: int           # SecOC DataID
    src: str               # Source ECU
    dst: str               # Destination ECU
    payload_len: int       # Authentic I-PDU length (bytes)
    period_ms: float       # Transmission period (ms)
    deadline_ms: float     # End-to-end deadline (ms)
    risk: str              # Risk level
    semantics: str         # Message semantics description
    critical_positions: list[int] = field(default_factory=list)  # Critical byte positions
    auth_area: tuple[int, int] = (0, 16)  # (offset, length) for authentication


# ── Default messages (Table 6) ────────────────────────────────────────

DEFAULT_MESSAGES = [
    MessageSpec(can_id=0x100, data_id=1, src="BMS", dst="VCU",
                payload_len=16, period_ms=10, deadline_ms=20, risk="HIGH",
                semantics="Battery voltage, current, SOC",
                critical_positions=list(range(12)), auth_area=(0, 12)),
    MessageSpec(can_id=0x200, data_id=2, src="ESC", dst="VCU",
                payload_len=16, period_ms=10, deadline_ms=20, risk="HIGH",
                semantics="Vehicle speed, wheel speeds, validity",
                critical_positions=list(range(10)), auth_area=(0, 10)),
    MessageSpec(can_id=0x300, data_id=3, src="MCU", dst="VCU",
                payload_len=16, period_ms=5, deadline_ms=10, risk="HIGH",
                semantics="Motor speed, actual torque, inverter status",
                critical_positions=list(range(12)), auth_area=(0, 12)),
    MessageSpec(can_id=0x400, data_id=4, src="VCU", dst="MCU",
                payload_len=12, period_ms=5, deadline_ms=10, risk="HIGH",
                semantics="Target torque, drive enable, torque limit",
                critical_positions=list(range(8)), auth_area=(0, 8)),
    MessageSpec(can_id=0x500, data_id=5, src="BMS", dst="VCU",
                payload_len=16, period_ms=100, deadline_ms=200, risk="MEDIUM",
                semantics="Cell min/max temp, insulation status",
                critical_positions=list(range(14)), auth_area=(0, 14)),
]

# ── Default config (Section 5.3) ──────────────────────────────────────

DEFAULT_CONFIG = SecOCConfig(
    ell=64, lambda_=12, b=32, W=16,
    rho="AUTH_RESTRICTED",
    A=(0, 16),
    kappa=(0, 0, 0),
    timeout_policy="REJECT_AND_REPORT",
    persist_policy="ON_AUTH_UPDATE",
    msg_id="DEFAULT",
    data_id=0,
)
