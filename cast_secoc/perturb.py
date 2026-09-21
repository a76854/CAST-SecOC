"""
Perturbation operators Γ — tampering, forgery, replay, boundary manipulation.
These act on P_wire (the Secured I-PDU) at the bus level, simulating
what an attacker or test controller can do.
"""
import random
from dataclasses import dataclass
from enum import Enum, auto
from .config import SecOCConfig


class PerturbType(Enum):
    """Perturbation types for test vectors."""
    NONE = auto()               # No perturbation — valid message
    TAMPER_AUTH_REGION = auto() # Modify bits inside auth area
    TAMPER_UNAUTH_REGION = auto()  # Modify bits outside auth area
    FORGE_MAC = auto()           # Replace MAC with random/zero
    REPLAY_HISTORICAL = auto()   # Replay a captured P_wire
    FV_MANIPULATE = auto()       # Manipulate truncated FV field
    WINDOW_BOUNDARY = auto()     # FV at window boundary
    ROLLOVER_CANDIDATE = auto()  # FV near rollover
    CROSS_CONTEXT = auto()       # Use wrong crypto context
    HIGH_LOAD = auto()           # High bus load injection


@dataclass
class Perturbation:
    """A perturbation specification for a test vector."""
    ptype: PerturbType = PerturbType.NONE
    # For tampering
    tamper_positions: list[int] | None = None  # Byte positions to modify
    tamper_mask: bytes | None = None           # XOR mask
    tamper_value: bytes | None = None          # Replacement bytes
    # For MAC forgery
    forge_mac_type: str = "random"  # "random" or "zero"
    # For replay
    replay_pdu: bytes | None = None
    # For FV manipulation
    fv_offset: int = 0          # Offset from current FV
    fv_force_value: int | None = None  # Force specific truncated FV
    # For window boundary
    window_position: int = 0    # Position relative to FV_last (e.g., W-1, W, W+1)
    # For cross-context
    cross_data_id: int = 0
    cross_key: bytes | None = None
    # For load
    target_load: float = 0.30


def apply_perturbation(p_wire: bytes, perturbation: Perturbation,
                       config: SecOCConfig,
                       rng: random.Random | None = None) -> bytes:
    """Apply perturbation to a Secured I-PDU. Returns modified P_wire."""
    rng = rng or random.SystemRandom()
    ptype = perturbation.ptype
    result = bytearray(p_wire)

    fv_bytes = (config.lambda_ + 7) // 8
    mac_bytes = config.ell // 8
    if len(p_wire) <= fv_bytes + mac_bytes:
        raise ValueError("secured PDU is too short for the configured fields")
    pos = len(p_wire) - fv_bytes - mac_bytes
    fv_pos = pos
    mac_pos = pos + fv_bytes

    if ptype == PerturbType.NONE:
        return bytes(result)

    elif ptype == PerturbType.TAMPER_AUTH_REGION:
        o, n = config.A
        for bp in (perturbation.tamper_positions or []):
            if o <= bp < o + n:
                result[bp] ^= perturbation.tamper_mask[0] if perturbation.tamper_mask else 0xFF

    elif ptype == PerturbType.TAMPER_UNAUTH_REGION:
        o, n = config.A
        for bp in (perturbation.tamper_positions or []):
            if bp < o or bp >= o + n:
                if bp < len(result):
                    result[bp] ^= perturbation.tamper_mask[0] if perturbation.tamper_mask else 0xFF

    elif ptype == PerturbType.FORGE_MAC:
        if perturbation.forge_mac_type == "random":
            result[mac_pos:mac_pos + mac_bytes] = rng.randbytes(mac_bytes)
        elif perturbation.forge_mac_type == "zero":
            result[mac_pos:mac_pos + mac_bytes] = b'\x00' * mac_bytes
        elif perturbation.forge_mac_type == "swap":
            # Swap with another message's MAC
            half = mac_bytes // 2
            tag = bytes(result[mac_pos:mac_pos + mac_bytes])
            result[mac_pos:mac_pos + mac_bytes] = tag[half:] + tag[:half]
        else:
            raise ValueError("unsupported MAC forgery type")

    elif ptype == PerturbType.REPLAY_HISTORICAL:
        if perturbation.replay_pdu:
            return perturbation.replay_pdu

    elif ptype == PerturbType.FV_MANIPULATE:
        fv_mask = (1 << config.lambda_) - 1
        if perturbation.fv_force_value is not None:
            val = perturbation.fv_force_value & fv_mask
            result[fv_pos:fv_pos + fv_bytes] = val.to_bytes(fv_bytes, 'big')
        else:
            current = int.from_bytes(result[fv_pos:fv_pos + fv_bytes], 'big')
            new_val = (current + perturbation.fv_offset) & fv_mask
            result[fv_pos:fv_pos + fv_bytes] = new_val.to_bytes(fv_bytes, 'big')

    elif ptype == PerturbType.WINDOW_BOUNDARY:
        val = perturbation.window_position & ((1 << config.lambda_) - 1)
        result[fv_pos:fv_pos + fv_bytes] = val.to_bytes(fv_bytes, 'big')

    elif ptype == PerturbType.ROLLOVER_CANDIDATE:
        # Force FV to a low value simulating post-rollover
        low_val = perturbation.window_position & ((1 << config.lambda_) - 1)
        result[fv_pos:fv_pos + fv_bytes] = low_val.to_bytes(fv_bytes, 'big')

    elif ptype == PerturbType.CROSS_CONTEXT:
        # The PDU itself is from one context but authenticated with another
        # Cross-context detection requires config-level tracking
        pass  # The orchestrator handles this via config switching

    elif ptype == PerturbType.HIGH_LOAD:
        pass  # Load is handled by bus configuration

    return bytes(result)
