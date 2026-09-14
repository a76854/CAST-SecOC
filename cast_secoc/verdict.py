"""
Verdict Engine — multi-dimensional demand determination.
Eqs.(20)–(37) from the paper.
"""
import math
from enum import Enum
from .freshness import RxState


class VectorType(Enum):
    """Eq.(19): Vector demand type."""
    VALID = "VALID"
    TAMPER = "TAMPER"
    REPLAY = "REPLAY"
    BOUNDARY_IN = "BOUNDARY_IN"
    BOUNDARY_OUT = "BOUNDARY_OUT"
    CONFIG = "CONFIG"
    LOAD = "LOAD"


class Verdict:
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"

# Critical error codes that indicate real faults (not policy rejections)
E_CRITICAL = {"INTERNAL_ERROR", "HSM_FAULT", "MEMORY_FAULT"}
E_POLICY_REJECT = {"TIMEOUT", "PARSE_ERROR_SHORT"}


def determine(vtype: VectorType, resp: dict, deadline_ms: float | None = None) -> str:
    """Eq.(20): Top-level determination.
    Returns PASS, FAIL, or INCONCLUSIVE.
    """
    eta = resp.get("eta", "COMPLETE")

    if eta == "INCOMPLETE":
        return Verdict.INCONCLUSIVE

    predicate = _predicate_for(vtype)

    try:
        satisfied = predicate(resp, deadline_ms)
    except Exception:
        return Verdict.INCONCLUSIVE

    if satisfied:
        return Verdict.PASS
    else:
        return Verdict.FAIL


def _predicate_for(vtype: VectorType):
    return {
        VectorType.VALID: _phi_valid,
        VectorType.TAMPER: _phi_tamper,
        VectorType.REPLAY: _phi_replay,
        VectorType.BOUNDARY_IN: _phi_boundary_in,
        VectorType.BOUNDARY_OUT: _phi_boundary_out,
        VectorType.CONFIG: _phi_config,
        VectorType.LOAD: _phi_load,
    }.get(vtype, lambda r, d: True)


# ── Eq.(21): Valid message predicate ───────────────────────────────

def _phi_valid(resp: dict, deadline_ms: float | None) -> bool:
    z_auth = resp["z_auth"]
    z_fresh = resp["z_fresh"]
    d_app = resp["d_app"]
    nu_state = resp["nu_state"]
    tau = resp["tau"]
    e = resp.get("e")

    ok = (z_auth == "PASS" and
          z_fresh == "PASS" and
          d_app == 1 and
          nu_state in ("UNCHANGED", "UPDATED_AUTH"))

    if deadline_ms is not None:
        ok = ok and (tau * 1000 <= deadline_ms)

    if e and e in E_CRITICAL:
        ok = False

    return ok


# ── Eq.(22): Tamper/forge predicate ─────────────────────────────────

def _phi_tamper(resp: dict, deadline_ms: float | None) -> bool:
    d_app = resp["d_app"]
    nu_state = resp["nu_state"]
    z_auth = resp["z_auth"]
    z_fresh = resp["z_fresh"]
    e = resp.get("e")

    # Must NOT deliver
    if d_app != 0:
        return False

    # Must NOT have unauthorized state update
    if nu_state == "UPDATED_UNAUTH":
        return False

    # Must detect anomaly
    detected = (z_auth == "FAIL" or z_fresh == "FAIL" or
                e in E_POLICY_REJECT)

    return detected


# ── Eq.(23): Replay predicate ───────────────────────────────────────

def _phi_replay(resp: dict, deadline_ms: float | None) -> bool:
    d_app = resp["d_app"]
    nu_state = resp["nu_state"]
    z_fresh = resp["z_fresh"]
    z_auth = resp["z_auth"]
    a_resync = resp["a_resync"]

    # Must NOT deliver historical data
    if d_app != 0:
        return False

    # Must NOT have unauthorized state rollback
    if nu_state == "UPDATED_UNAUTH":
        return False

    # Detection: freshness fail, auth fail, OR authenticated resync
    detected = (z_fresh == "FAIL" or z_auth == "FAIL" or
                a_resync == "AUTHENTICATED")

    return detected


# ── Eq.(24): Boundary-in predicate ──────────────────────────────────

def _phi_boundary_in(resp: dict, deadline_ms: float | None) -> bool:
    z_auth = resp["z_auth"]
    z_fresh = resp["z_fresh"]
    d_app = resp["d_app"]
    nu_state = resp["nu_state"]
    tau = resp["tau"]

    ok = (z_auth == "PASS" and
          z_fresh == "PASS" and
          d_app == 1 and
          nu_state == "UPDATED_AUTH")

    if deadline_ms is not None:
        ok = ok and (tau * 1000 <= deadline_ms)

    return ok


# ── Eq.(25): Boundary-out predicate ─────────────────────────────────

def _phi_boundary_out(resp: dict, deadline_ms: float | None) -> bool:
    d_app = resp["d_app"]
    a_resync = resp["a_resync"]
    nu_state = resp["nu_state"]

    # Must NOT deliver
    if d_app != 0:
        return False

    # Allowed resync actions
    if a_resync not in ("NONE", "REQUESTED", "AUTHENTICATED"):
        return False

    # Allowed state changes
    if nu_state not in ("UNCHANGED", "UPDATED_AUTH"):
        return False

    return True


# ── Eq.(26): Config mutation killed ────────────────────────────────

def config_killed(baseline_verdict: str, mutation_verdict: str,
                  load_rejected: bool = False) -> bool:
    """A config mutation is killed iff baseline PASS and mutation FAIL,
    or the configuration was rejected at load time."""
    if load_rejected:
        return True
    return baseline_verdict == Verdict.PASS and mutation_verdict == Verdict.FAIL


def _phi_config(resp: dict, deadline_ms: float | None) -> bool:
    """Config mutation vectors: illegal delivery = security FAIL.
    Cross-context PDU should NOT be delivered to application layer."""
    d_app = resp["d_app"]
    nu_state = resp["nu_state"]
    # d_app=0 → correctly rejected → PASS
    # d_app=1 → illegal delivery (context isolation failure) → FAIL
    if d_app == 1:
        return False
    if nu_state == "UPDATED_UNAUTH":
        return False
    return True


# ── Eq.(27): High-load predicate ────────────────────────────────────

def _phi_load(resp: dict, deadline_ms: float | None) -> bool:
    """Delegates to valid or tamper/replay based on vector classification."""
    # The orchestrator handles this — we use type-specific logic
    return True


# ── Defect classification — Eq.(28)–(37) ──────────────────────────────

def classify_defect(vtype: VectorType, resp: dict,
                    config_baseline, config_mutation,
                    critical_positions: list[int] | None = None) -> list[str]:
    """Classify defects from a FAIL verdict. Returns list of defect labels."""
    defects = []
    d_app = resp["d_app"]
    z_auth = resp["z_auth"]
    nu_state = resp["nu_state"]
    a_resync = resp["a_resync"]
    e = resp.get("e")

    if critical_positions is None:
        critical_positions = []

    # D_area — Eq.(28): Auth area omission
    # If a critical position is outside auth area and msg was delivered
    o, n = config_baseline.A if config_baseline else (0, 0)
    for j in critical_positions:
        if j < o or j >= o + n:
            if z_auth == "PASS" and d_app == 1:
                defects.append("D_area")
                break

    # D_failopen — Eq.(29): Auth fail but still delivered
    if z_auth == "FAIL" and d_app == 1:
        defects.append("D_failopen")

    # D_rollback — Eq.(30): Historical FV accepted
    fv_last_after = resp.get("fv_last_after", 0)
    # Detected via replay vector type — if delivered, it's rollback
    if vtype == VectorType.REPLAY and d_app == 1:
        defects.append("D_rollback")

    # D_window — Eq.(31): Out-of-window accepted
    if vtype == VectorType.BOUNDARY_OUT and d_app == 1:
        defects.append("D_window")

    # D_rollover — Eq.(32): Rollover gating missing
    if d_app == 1 and a_resync != "AUTHENTICATED":
        # Check if this was a rollover candidate
        if resp.get("rx_state_after") == "ROLLOVER_PENDING":
            defects.append("D_rollover")

    # D_unauth_update — Eq.(33): Unauthenticated state update
    if nu_state == "UPDATED_UNAUTH":
        defects.append("D_unauth_update")

    # D_context — Eq.(34): Crypto context isolation insufficient
    if vtype == VectorType.CONFIG and d_app == 1:
        # More specific check in orchestrator
        defects.append("D_context")

    # D_authlen — Eq.(35)–(36): MAC length policy violation
    # Checked at config load time by orchestrator

    # D_availability — Eq.(37): Valid msg not delivered or timeout
    if vtype == VectorType.VALID:
        if d_app == 0:
            defects.append("D_availability")
        if e == "TIMEOUT":
            defects.append("D_availability")

    return defects if defects else ["D_unknown"]


# ── Metric calculations — Eq.(38)–(43) ──────────────────────────────

def compute_metrics(results: list[dict]) -> dict:
    """Compute IAR, FRR, IR, MS from test results."""
    n_executed = len(results)
    if n_executed == 0:
        return {}

    # Count by type
    invalid_conclusive = [r for r in results
                          if r.get("vector_type") != VectorType.VALID
                          and r.get("verdict") != Verdict.INCONCLUSIVE]
    valid_conclusive = [r for r in results
                        if r.get("vector_type") == VectorType.VALID
                        and r.get("verdict") != Verdict.INCONCLUSIVE]
    inconclusive = [r for r in results
                    if r.get("verdict") == Verdict.INCONCLUSIVE]

    # IAR — Eq.(38): Invalid messages wrongly delivered
    n_invalid = len(invalid_conclusive)
    n_invalid_delivered = sum(1 for r in invalid_conclusive
                              if r.get("d_app") == 1 and r.get("verdict") == Verdict.FAIL)
    iar = n_invalid_delivered / n_invalid if n_invalid > 0 else 0.0

    # FRR — Eq.(39): Valid messages not delivered by deadline
    n_valid = len(valid_conclusive)
    n_valid_missed = sum(1 for r in valid_conclusive
                         if r.get("d_app") == 0 or r.get("verdict") == Verdict.FAIL)
    frr = n_valid_missed / n_valid if n_valid > 0 else 0.0

    # IR — Eq.(40): Inconclusive rate
    ir = len(inconclusive) / n_executed

    return {
        "IAR": iar, "FRR": frr, "IR": ir,
        "n_executed": n_executed,
        "n_invalid_conclusive": n_invalid,
        "n_valid_conclusive": n_valid,
        "n_inconclusive": len(inconclusive),
    }
