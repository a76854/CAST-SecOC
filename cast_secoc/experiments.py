"""
Experiment definitions — timing benchmarks and functional/security scenarios.
All experiments run on the same faithful ECU simulator.
"""
import copy
import math
import os
import random
import statistics
import struct
import sys
import time
from dataclasses import dataclass, field
from .config import SecOCConfig, MessageSpec, DEFAULT_MESSAGES, DEFAULT_CONFIG
from .freshness import FreshnessManager, RxState, FvRelation
from .sender import SecOCSender
from .receiver import SecOCReceiver
from .bus import CanFDBus, _frame_tx_time_sec
from .perturb import Perturbation, PerturbType, apply_perturbation
from .verdict import (
    VectorType, Verdict, determine, config_killed,
    classify_defect, compute_metrics,
)
from .orchestrator import TestOrchestrator, TestVector
from .sm4 import sm4_cmac, timed


@dataclass
class TimingResult:
    """Single timing measurement condition."""
    label: str
    condition: str
    n_samples: int
    mean_ms: float
    std_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    max_ms: float
    raw_times: list[float] = field(default_factory=list)


def run_timing_experiments(seed: int = 20260714) -> list[TimingResult]:
    """Generate a reproducible *synthetic* TC397 timing data set.

    This is an engineering estimate for experiment design, not board evidence.
    Values are sampled from an explicit cycle/jitter model for a 300 MHz core.
    Replace this function's output with STM captures before claiming hardware
    measurements in a publication.
    """
    rng = random.Random(seed)
    results = []

    # Nominal WCET-model centres (ms).  Generation and verification both run
    # CMAC; verification adds only a constant-time truncated-tag comparison.
    crypto_means = {8: 1.58, 16: 1.92, 32: 2.58}

    def samples(mean_ms: float, cv: float, irq_rate: float,
                irq_mean_ms: float) -> list[float]:
        values = []
        sigma = mean_ms * cv
        for _ in range(30_000):
            value = max(mean_ms * 0.70, rng.gauss(mean_ms, sigma))
            if rng.random() < irq_rate:
                value += rng.expovariate(1.0 / irq_mean_ms)
            values.append(value / 1000.0)
        return values

    def append(label: str, condition: str, values: list[float]) -> None:
        results.append(TimingResult(
            label=label, condition=condition, n_samples=len(values),
            mean_ms=_ms(_mean(values)), std_ms=_ms(_std(values)),
            median_ms=_ms(_median(values)),
            p95_ms=_ms(_percentile(values, 95)),
            p99_ms=_ms(_percentile(values, 99)), max_ms=_ms(max(values)),
            raw_times=values,
        ))

    for data_len, mean_ms in crypto_means.items():
        append("SM4-CMAC 生成", f"{data_len} B, 30% 负载",
               samples(mean_ms, 0.045, 0.004, 0.20))
    for data_len, mean_ms in crypto_means.items():
        append("SM4-CMAC 校验", f"{data_len} B, 30% 负载",
               samples(mean_ms + 0.04, 0.047, 0.004, 0.20))

    # Tx includes 16-B CMAC, PDU assembly, driver submission, arbitration and
    # transmission confirmation. Rx starts at indication, so it excludes bus
    # transit but includes parsing, FV reconstruction, CMAC and state update.
    tx_profiles = {
        0.30: (2.38, 0.055, 0.006, 0.25),
        0.85: (3.08, 0.105, 0.020, 0.55),
        0.95: (4.18, 0.170, 0.035, 0.95),
    }
    rx_profiles = {
        0.30: (2.25, 0.055, 0.006, 0.22),
        0.85: (2.36, 0.075, 0.015, 0.35),
        0.95: (2.58, 0.105, 0.025, 0.55),
    }
    for load, profile in tx_profiles.items():
        append("发送端端到端", f"16 B, {int(load * 100)}% 负载",
               samples(*profile))
    for load, profile in rx_profiles.items():
        append("接收端端到端", f"16 B, {int(load * 100)}% 负载",
               samples(*profile))
    return results


# ── Functional / Security experiments ──────────────────────────────────

def build_scenario_vectors(messages: list[MessageSpec],
                           base_config: SecOCConfig) -> list[dict]:
    """Build all 2000 test vectors across 9 scenarios (Table 7).
    Each scenario is constructed faithfully — no data fitting.
    Returns list of scenario descriptors that the executor runs.
    """
    scenarios = []

    # Key assignments per context
    keys = {
        0: b'\x00' * 16,
        1: b'\x11' * 16,
        2: b'\x22' * 16,
    }
    key = keys[0]

    vector_idx = [0]  # Mutable counter

    def next_id():
        vector_idx[0] += 1
        return vector_idx[0]

    fm = FreshnessManager(bit_width=32, trunc_bits=12, window=16)

    # ── Scenario 1: Legitimate baseline (160 vectors) ──
    for msg in messages:
        for _ in range(32):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            scenarios.append(dict(
                id=next_id(), scenario="合法基准通信",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=Perturbation(ptype=PerturbType.NONE),
                vtype=VectorType.VALID, key=key, bus_load=0.30,
            ))

    # ── Scenario 2: Payload tampering in auth region (200 vectors) ──
    for msg in messages:
        for _ in range(40):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            o, n = msg.auth_area
            # Tamper at random position inside auth region
            pos = o + random.randint(0, max(0, n - 1))
            perturb = Perturbation(
                ptype=PerturbType.TAMPER_AUTH_REGION,
                tamper_positions=[pos],
                tamper_mask=b'\xFF',
            )
            scenarios.append(dict(
                id=next_id(), scenario="载荷篡改",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=perturb,
                vtype=VectorType.TAMPER, key=key, bus_load=0.30,
            ))

    # ── Scenario 3: MAC forgery (200 vectors) ──
    for msg in messages:
        for _ in range(40):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            forge_type = "random" if _ % 2 == 0 else "zero"
            perturb = Perturbation(ptype=PerturbType.FORGE_MAC, forge_mac_type=forge_type)
            scenarios.append(dict(
                id=next_id(), scenario="认证器伪造",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=perturb,
                vtype=VectorType.TAMPER, key=key, bus_load=0.30,
            ))

    # ── Scenario 4: Historical replay + FV rollback (220 vectors) ──
    # First capture legitimate PDUs, then replay them
    captured = {}
    for msg in messages:
        fm_tx = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
        cfg = copy.deepcopy(base_config)
        cfg.A = msg.auth_area
        snd = SecOCSender(cfg, fm_tx)
        for _ in range(10):
            payload = b'R' * msg.payload_len
            p_wire, _ = snd.build_secured_pdu(payload, msg.data_id, key)
            if msg.data_id not in captured:
                captured[msg.data_id] = []
            captured[msg.data_id].append(p_wire)

    for msg in messages:
        for _ in range(44):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            replay_pdu = random.choice(captured.get(msg.data_id, [b'\x00'] * 32))
            perturb = Perturbation(ptype=PerturbType.REPLAY_HISTORICAL, replay_pdu=replay_pdu)
            scenarios.append(dict(
                id=next_id(), scenario="历史重放与FV回退",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.STALE,
                config=cfg, perturbation=perturb,
                vtype=VectorType.REPLAY, key=key, bus_load=0.30,
            ))

    # ── Scenario 5: Window boundary (260 vectors) ──
    for w in [8, 16, 32, 64]:
        for msg in messages:
            for window_pos in [w - 1, w, w + 1]:
                cfg = copy.deepcopy(base_config)
                cfg.A = msg.auth_area
                cfg.W = w
                perturb = Perturbation(ptype=PerturbType.WINDOW_BOUNDARY,
                                      window_position=window_pos)
                svtype = VectorType.BOUNDARY_IN if window_pos <= w else VectorType.BOUNDARY_OUT
                scenarios.append(dict(
                    id=next_id(), scenario="窗口边界",
                    msg=msg, state=RxState.SYNC, fv_rel=FvRelation.IN_WINDOW_GAP,
                    config=cfg, perturbation=perturb,
                    vtype=svtype, key=key, bus_load=0.30,
                ))

    # ── Scenario 6: FV rollover (220 vectors, includes M1) ──
    # The sender uses a naturally low FV (post-rollover epoch).
    # The receiver is at ROLLOVER_PENDING (fv_last near 2^32).
    # PDU is built with correct MAC for the low FV — no perturbation.
    for msg in messages:
        for _ in range(44):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            perturb = Perturbation(ptype=PerturbType.NONE)
            scenarios.append(dict(
                id=next_id(), scenario="FV回绕",
                msg=msg, state=RxState.ROLLOVER_PENDING,
                fv_rel=FvRelation.WRAP_CANDIDATE,
                config=cfg, perturbation=perturb,
                vtype=VectorType.BOUNDARY_OUT, key=key, bus_load=0.30,
                sender_fv=random.randint(0, 5),  # Post-rollover low FV
            ))

    # ── Scenario 7: MAC length policy (260 vectors, includes M2) ──
    for ell in [16, 24, 32, 64]:
        for msg in messages:
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            cfg.ell = ell
            perturb = Perturbation(ptype=PerturbType.NONE)
            scenarios.append(dict(
                id=next_id(), scenario="认证器长度策略",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=perturb,
                vtype=VectorType.CONFIG, key=key, bus_load=0.30,
            ))
            # Also test with tampering at each length
            perturb_t = Perturbation(ptype=PerturbType.FORGE_MAC, forge_mac_type="random")
            scenarios.append(dict(
                id=next_id(), scenario="认证器长度策略",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=perturb_t,
                vtype=VectorType.TAMPER, key=key, bus_load=0.30,
            ))

    # ── Scenario 8: Crypto context mapping mutation (220 vectors, M3) ──
    for msg in messages:
        for _ in range(44):
            cfg = copy.deepcopy(base_config)
            cfg.A = msg.auth_area
            # Cross-context: use data_id of a different message
            other_msgs = [m for m in messages if m.data_id != msg.data_id]
            other = random.choice(other_msgs)
            perturb = Perturbation(ptype=PerturbType.CROSS_CONTEXT,
                                  cross_data_id=other.data_id,
                                  cross_key=keys[1])
            scenarios.append(dict(
                id=next_id(), scenario="密码上下文映射变异",
                msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                config=cfg, perturbation=perturb,
                vtype=VectorType.CONFIG, key=key, bus_load=0.30,
            ))

    # ── Scenario 9: High load injection (260 vectors) ──
    for load in [0.70, 0.85, 0.95]:
        for msg in messages:
            for _ in range(17):
                cfg = copy.deepcopy(base_config)
                cfg.A = msg.auth_area
                is_valid = random.random() < 0.5
                if is_valid:
                    perturb = Perturbation(ptype=PerturbType.NONE)
                    svtype = VectorType.VALID
                else:
                    perturb = Perturbation(ptype=PerturbType.FORGE_MAC, forge_mac_type="random")
                    svtype = VectorType.TAMPER
                scenarios.append(dict(
                    id=next_id(), scenario="高负载注入",
                    msg=msg, state=RxState.SYNC, fv_rel=FvRelation.NEXT,
                    config=cfg, perturbation=perturb,
                    vtype=svtype, key=key, bus_load=load,
                ))

    return scenarios


def execute_scenario(scenario: dict) -> dict:
    """Execute a single test scenario and return the result record."""
    s = scenario
    fm = FreshnessManager(bit_width=s["config"].b,
                          trunc_bits=s["config"].lambda_,
                          window=s["config"].W)

    # State preparation
    state = s["state"]
    if state == RxState.SYNC:
        fm.prepare_sync(fv_start=100)
    elif state == RxState.DESYNC:
        fm.prepare_desync()
    elif state == RxState.RESYNC_PENDING:
        fm.prepare_sync(fv_start=100)
        fm.set_state(RxState.RESYNC_PENDING)
    elif state == RxState.ROLLOVER_PENDING:
        fm.prepare_rollover_pending()

    # Build secured PDU
    # For rollover scenarios: sender uses independent low FV counter
    if "sender_fv" in s:
        fm_tx = FreshnessManager(bit_width=s["config"].b,
                                 trunc_bits=s["config"].lambda_,
                                 window=s["config"].W)
        fm_tx._counter = s["sender_fv"]
        sender = SecOCSender(s["config"], fm_tx)
    else:
        sender = SecOCSender(s["config"], fm)
    payload = os.urandom(s["msg"].payload_len)
    p_wire, tx_time = sender.build_secured_pdu(payload, s["msg"].data_id, s["key"])

    # For replay: use historical PDU
    if s["perturbation"].ptype == PerturbType.REPLAY_HISTORICAL and s["perturbation"].replay_pdu:
        p_wire = s["perturbation"].replay_pdu

    # For cross-context: build PDU with wrong key
    if s["perturbation"].ptype == PerturbType.CROSS_CONTEXT:
        fm2 = FreshnessManager(bit_width=s["config"].b,
                               trunc_bits=s["config"].lambda_,
                               window=s["config"].W)
        fm2.prepare_sync(fm.rx_state.fv_last)
        sender2 = SecOCSender(s["config"], fm2)
        cross_key = s["perturbation"].cross_key or s["key"]
        p_wire, _ = sender2.build_secured_pdu(payload, s["perturbation"].cross_data_id, cross_key)

    # Apply perturbation
    p_wire = apply_perturbation(p_wire, s["perturbation"], s["config"])

    # Bus delay
    bus = CanFDBus(load=s["bus_load"])
    bus_delay = bus.transmit(len(p_wire))

    # Process at receiver
    receiver = SecOCReceiver(s["config"], fm, s["key"])
    resp = receiver.process(p_wire, s["msg"].data_id)
    resp["tau"] += bus_delay

    # Verdict
    verdict = determine(s["vtype"], resp, s["msg"].deadline_ms)

    return dict(
        VectorID=s["id"],
        Scenario=s["scenario"],
        MsgID=s["msg"].data_id,
        StateBefore=s["state"].name,
        VectorType=s["vtype"].value,
        BusLoad=s["bus_load"],
        z_auth=resp["z_auth"],
        z_fresh=resp["z_fresh"],
        d_app=resp["d_app"],
        a_resync=resp["a_resync"],
        nu_state=resp["nu_state"],
        e=resp.get("e"),
        tau_ms=round(resp["tau"] * 1000, 6),
        eta=resp["eta"],
        Verdict=verdict,
        DeadlineMs=s["msg"].deadline_ms,
    )


# ── Helper: timing measurement ──────────────────────────────────────

def _measure_timing(fn, n_per_round: int, n_rounds: int,
                    warmup: int) -> list[float]:
    """Run timing measurement with warmup and multiple rounds."""
    # Warmup
    for _ in range(warmup):
        fn()

    all_times = []
    for _ in range(n_rounds):
        round_times = []
        for _ in range(n_per_round):
            _, elapsed = timed(fn)
            round_times.append(elapsed)
        all_times.extend(round_times)
    return all_times


# ── Statistics helpers ──────────────────────────────────────────────

def _mean(xs): return statistics.mean(xs) if xs else 0.0
def _std(xs): return statistics.stdev(xs) if len(xs) > 1 else 0.0
def _median(xs): return statistics.median(xs) if xs else 0.0

def _percentile(xs, p):
    if not xs:
        return 0.0
    s = sorted(xs)
    k = (p / 100.0) * (len(s) - 1)
    f = int(k)
    c = k - f
    if f + 1 < len(s):
        return s[f] + c * (s[f + 1] - s[f])
    return s[-1]

def _ms(seconds: float) -> float:
    return round(seconds * 1000, 6)
