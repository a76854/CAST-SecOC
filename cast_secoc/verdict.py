"""Requirement-oriented verdicts, defect labels, and aggregate metrics."""
from enum import Enum


class VectorType(Enum):
    """Expected behavior category for a test vector."""
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
    """Evaluate one response against its expected behavior.
    Returns PASS, FAIL, or INCONCLUSIVE.
    """
    eta = resp.get("eta", "COMPLETE")

    if eta == "INCOMPLETE":
        return Verdict.INCONCLUSIVE

    predicate = _predicate_for(vtype)
    if predicate is None:
        return Verdict.INCONCLUSIVE

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
    }.get(vtype)


# ── Valid message predicate ───────────────────────────────

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

    if e and any(e.startswith(code) for code in E_CRITICAL):
        ok = False

    return ok


# ── Tamper/forge predicate ─────────────────────────────────

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


# ── Replay predicate ───────────────────────────────────────

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


# ── Boundary-in predicate ──────────────────────────────────

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


# ── Boundary-out predicate ─────────────────────────────────

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


# ── Config mutation killed ────────────────────────────────

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


# ── High-load predicate ────────────────────────────────────

def _phi_load(resp: dict, deadline_ms: float | None) -> bool:
    """Evaluate load-only vectors as valid traffic under a deadline."""
    return _phi_valid(resp, deadline_ms)


# ── Defect classification ──────────────────────────────

def classify_defect(vtype: VectorType, resp: dict,
                    config,
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

    # D_area: Auth area omission
    # If a critical position is outside auth area and msg was delivered
    o, n = config.A if config else (0, 0)
    for j in critical_positions:
        if j < o or j >= o + n:
            if z_auth == "PASS" and d_app == 1:
                defects.append("D_area")
                break

    # D_failopen: Auth fail but still delivered
    if z_auth == "FAIL" and d_app == 1:
        defects.append("D_failopen")

    # D_rollback: Historical FV accepted
    if vtype == VectorType.REPLAY and d_app == 1:
        defects.append("D_rollback")

    # D_window: Out-of-window accepted
    if vtype == VectorType.BOUNDARY_OUT and d_app == 1:
        defects.append("D_window")

    # D_rollover: Rollover gating missing
    if (d_app == 1 and a_resync != "AUTHENTICATED"
            and resp.get("rx_state_before") == "ROLLOVER_PENDING"):
        defects.append("D_rollover")

    # D_unauth_update: Unauthenticated state update
    if nu_state == "UPDATED_UNAUTH":
        defects.append("D_unauth_update")

    # D_context: Crypto context isolation insufficient
    if vtype == VectorType.CONFIG and d_app == 1:
        # More specific check in orchestrator
        defects.append("D_context")

    # D_authlen: MAC length policy violation
    # Checked at config load time by orchestrator

    # D_availability: Valid msg not delivered or timeout
    if vtype == VectorType.VALID:
        if d_app == 0:
            defects.append("D_availability")
        if e == "TIMEOUT":
            defects.append("D_availability")

    return defects if defects else ["D_unknown"]


# ── Metric calculations ──────────────────────────────

def compute_metrics(results: list[dict]) -> dict:
    """Compute invalid-acceptance, false-rejection, and inconclusive rates."""
    n_executed = len(results)
    if n_executed == 0:
        return {}

    def vector_type(record):
        value = record.get("vector_type", record.get("VectorType"))
        return value.value if isinstance(value, VectorType) else value

    def verdict(record):
        return record.get("verdict", record.get("Verdict"))

    valid_types = {VectorType.VALID.value, VectorType.BOUNDARY_IN.value}
    invalid_conclusive = [
        r for r in results
        if vector_type(r) not in valid_types
        and verdict(r) != Verdict.INCONCLUSIVE
    ]
    valid_conclusive = [
        r for r in results
        if vector_type(r) in valid_types
        and verdict(r) != Verdict.INCONCLUSIVE
    ]
    inconclusive = [r for r in results if verdict(r) == Verdict.INCONCLUSIVE]

    # IAR: Invalid messages wrongly delivered
    n_invalid = len(invalid_conclusive)
    n_invalid_delivered = sum(1 for r in invalid_conclusive
                              if r.get("d_app") == 1)
    iar = n_invalid_delivered / n_invalid if n_invalid > 0 else 0.0

    # FRR: Valid messages not delivered by deadline
    n_valid = len(valid_conclusive)
    n_valid_missed = sum(1 for r in valid_conclusive
                         if r.get("d_app") == 0 or verdict(r) == Verdict.FAIL)
    frr = n_valid_missed / n_valid if n_valid > 0 else 0.0

    # IR: Inconclusive rate
    ir = len(inconclusive) / n_executed

    return {
        "IAR": iar, "FRR": frr, "IR": ir,
        "n_executed": n_executed,
        "n_invalid_conclusive": n_invalid,
        "n_valid_conclusive": n_valid,
        "n_inconclusive": len(inconclusive),
    }
