#!/usr/bin/env python3
"""
CAST-SecOC Simulation — Main entry point.
Runs all experiments and reports naturally emerging results.
No data fitting. No artificial calibration.
"""
import copy
import csv
import json
import os
import random
import statistics
import sys
import time
from collections import defaultdict

from cast_secoc.config import (
    SecOCConfig, MessageSpec, DEFAULT_MESSAGES, DEFAULT_CONFIG,
)
from cast_secoc.freshness import FreshnessManager, RxState, FvRelation
from cast_secoc.sender import SecOCSender
from cast_secoc.receiver import SecOCReceiver
from cast_secoc.bus import CanFDBus
from cast_secoc.perturb import Perturbation, PerturbType, apply_perturbation
from cast_secoc.verdict import (
    VectorType, Verdict, determine, config_killed,
    classify_defect, compute_metrics,
)
from cast_secoc.experiments import (
    run_timing_experiments, build_scenario_vectors,
    execute_scenario, TimingResult, _mean, _std, _median, _percentile, _ms,
)
from cast_secoc.sm4 import sm4_cmac, timed


OUTPUT_DIR = "results"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def main():
    print("=" * 72)
    print("  CAST-SecOC Simulation — Faithful ECU Simulator")
    print("  Functional results: protocol simulation; timing: labelled TC397 parameter model.")
    print("=" * 72)

    # ── Part 1: Timing experiments ──────────────────────────────────
    print("\n" + "─" * 72)
    print("  Part 1: SM4-CMAC & End-to-End Timing")
    print("─" * 72)
    timing_results = run_timing_experiments(seed=20260714)
    print_timing_table(timing_results)

    # Save timing JSON (for Excel)
    import json as _json
    timing_json = []
    for tr in timing_results:
        timing_json.append(dict(
            label=tr.label, condition=tr.condition, n_samples=tr.n_samples,
            mean_ms=tr.mean_ms, std_ms=tr.std_ms, median_ms=tr.median_ms,
            p95_ms=tr.p95_ms, p99_ms=tr.p99_ms, max_ms=tr.max_ms,
            data_source="TC397 300 MHz 参数化仿真（非硬件实测）",
            model_seed=20260714,
        ))
    with open(f"{OUTPUT_DIR}/timing.json", "w") as f:
        _json.dump(timing_json, f, indent=2)
    with open(f"{OUTPUT_DIR}/timing.csv", "w", newline="") as f:
        fields = list(timing_json[0])
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(timing_json)

    # ── Part 2: Message-level timing margin ─────────────────────────
    print("\n" + "─" * 72)
    print("  Part 2: Message-Level Timing Margin (Eq.45)")
    print("─" * 72)
    print_timing_margin(timing_results)

    # ── Part 3: Functional & security scenarios ─────────────────────
    print("\n" + "─" * 72)
    print("  Part 3: Functional & Security Scenarios (2000 vectors)")
    print("─" * 72)
    scenarios = build_scenario_vectors(DEFAULT_MESSAGES, DEFAULT_CONFIG)
    print(f"  Generated {len(scenarios)} test vectors across 9 scenarios.")

    results = []
    for i, s in enumerate(scenarios):
        r = execute_scenario(s)
        results.append(r)
        if (i + 1) % 500 == 0:
            print(f"  ... executed {i + 1}/{len(scenarios)}")

    print(f"  All {len(results)} vectors executed.\n")

    # ── Part 4: Key metrics (Table 9) ───────────────────────────────
    print("─" * 72)
    print("  Part 4: Key Metrics by Scenario Group (Table 9)")
    print("─" * 72)
    print_metrics_table(results)

    # ── Part 5: Multi-dimensional response matrix (Table 10) ────────
    print("\n" + "─" * 72)
    print("  Part 5: Multi-Dimensional Response Matrix (Table 10)")
    print("─" * 72)
    print_response_matrix(results)

    # ── Part 6: Controlled config mutations (Table 11) ──────────────
    print("\n" + "─" * 72)
    print("  Part 6: Controlled Configuration Mutations (Table 11)")
    print("─" * 72)
    run_config_mutations(results)

    # ── Part 7: Coverage (Eq.42) ────────────────────────────────────
    print("\n" + "─" * 72)
    print("  Part 7: Coverage Breakdown (Eq.42)")
    print("─" * 72)
    print_coverage(results, scenarios)

    # ── Save results ────────────────────────────────────────────────
    with open(f"{OUTPUT_DIR}/results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Full results saved to {OUTPUT_DIR}/results.json")
    print(f"  Timing data saved to {OUTPUT_DIR}/timing.json")


# ── Output Tables ──────────────────────────────────────────────────────

def print_timing_table(results: list[TimingResult]):
    """Table 8: Timing statistics."""
    hdr = f"  {'测试项':<16s} {'条件':<20s} {'样本':>6s} {'均值/ms':>8s} {'标准差':>8s} {'中位数':>8s} {'P95':>8s} {'P99':>8s}"
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for tr in results:
        print(f"  {tr.label:<16s} {tr.condition:<20s} {tr.n_samples:>6d} "
              f"{tr.mean_ms:>8.4f} {tr.std_ms:>8.4f} {tr.median_ms:>8.4f} "
              f"{tr.p95_ms:>8.4f} {tr.p99_ms:>8.4f}")


def print_timing_margin(results: list[TimingResult]):
    """Eq.(45): Message-level timing margin."""
    # Extract sender and receiver P99 for 16B
    tx_p99 = {}
    rx_p99 = {}
    for tr in results:
        if tr.label == "发送端端到端":
            load_str = tr.condition.split(",")[1].strip()
            tx_p99[load_str] = tr.p99_ms
        elif tr.label == "接收端端到端":
            load_str = tr.condition.split(",")[1].strip()
            rx_p99[load_str] = tr.p99_ms

    print(f"  {'消息':<10s} {'时限/ms':>8s} {'Tx-P99':>8s} {'Rx-P99':>8s} {'Total-P99':>8s} {'裕量/ms':>8s} {'状态':>6s}")
    print("  " + "-" * 56)
    for msg in DEFAULT_MESSAGES:
        load_key = "30% 负载"
        tx = tx_p99.get(load_key, 0)
        rx = rx_p99.get(load_key, 0)
        total = tx + rx
        margin = msg.deadline_ms - total
        status = "✓" if margin > 0 else "✗"
        print(f"  {msg.semantics[:10]:<10s} {msg.deadline_ms:>8.1f} {tx:>8.4f} {rx:>8.4f} {total:>8.4f} {margin:>8.4f} {status:>6s}")

    # Also print for 95% load
    print(f"\n  {'(95% load)':<10s} {'时限/ms':>8s} {'Tx-P99':>8s} {'Rx-P99':>8s} {'Total-P99':>8s} {'裕量/ms':>8s} {'状态':>6s}")
    print("  " + "-" * 56)
    for msg in DEFAULT_MESSAGES:
        load_key = "95% 负载"
        tx = tx_p99.get(load_key, 0)
        rx = rx_p99.get(load_key, 0)
        total = tx + rx
        margin = msg.deadline_ms - total
        status = "✓" if margin > 0 else "✗"
        print(f"  {msg.semantics[:10]:<10s} {msg.deadline_ms:>8.1f} {tx:>8.4f} {rx:>8.4f} {total:>8.4f} {margin:>8.4f} {status:>6s}")


def print_metrics_table(results: list[dict]):
    """Table 9: Key metrics by scenario group."""
    groups = defaultdict(list)
    for r in results:
        scenario = r["Scenario"]
        groups[scenario].append(r)

    # Define scenario groups
    group_defs = [
        ("合法基准通信", ["合法基准通信"]),
        ("直接认证异常", ["载荷篡改", "认证器伪造"]),
        ("基准新鲜度异常", ["历史重放与FV回退"]),
        ("窗口边界", ["窗口边界"]),
        ("回绕边界（含M1）", ["FV回绕"]),
        ("密码上下文映射（含M3）", ["密码上下文映射变异"]),
        ("高负载注入", ["高负载注入"]),
        ("认证器长度策略（含M2）", ["认证器长度策略"]),
    ]

    print(f"  {'场景组':<22s} {'合法':>5s} {'非法':>5s} {'IAR':>8s} {'FRR':>8s} {'IR':>8s} {'说明':>30s}")
    print("  " + "-" * 90)

    for group_name, scenario_names in group_defs:
        group_results = []
        for sn in scenario_names:
            group_results.extend(groups.get(sn, []))

        if not group_results:
            continue

        # Classify
        valid = [r for r in group_results if r["VectorType"] == "VALID"]
        invalid = [r for r in group_results if r["VectorType"] != "VALID"]

        n_valid = len(valid)
        n_invalid = len(invalid)

        # IAR
        n_invalid_delivered = sum(1 for r in invalid
                                  if r["d_app"] == 1 and r["eta"] == "COMPLETE")
        inconclusive_invalid = sum(1 for r in invalid if r["eta"] != "COMPLETE")
        iar_denom = n_invalid - inconclusive_invalid
        iar = n_invalid_delivered / iar_denom if iar_denom > 0 else 0.0

        # FRR
        n_valid_missed = sum(1 for r in valid
                             if r["d_app"] == 0 or r["Verdict"] == "FAIL")
        inconclusive_valid = sum(1 for r in valid if r["eta"] != "COMPLETE")
        frr_denom = n_valid - inconclusive_valid
        frr = n_valid_missed / frr_denom if frr_denom > 0 else 0.0

        # IR
        n_inconclusive = sum(1 for r in group_results if r["eta"] != "COMPLETE")
        ir = n_inconclusive / len(group_results) if group_results else 0.0

        # Summary
        delivered = sum(1 for r in group_results if r["d_app"] == 1)
        errors = sum(1 for r in group_results if r.get("e") and r["e"] not in ("None", None))
        timeouts = sum(1 for r in group_results if r.get("e") == "TIMEOUT")

        desc = f"交付{delivered}, 错误{errors}, 超时{timeouts}"
        print(f"  {group_name:<22s} {n_valid:>5d} {n_invalid:>5d} "
              f"{iar:>7.2%} {frr:>7.2%} {ir:>7.2%}  {desc:<30s}")


def print_response_matrix(results: list[dict]):
    """Table 10: Multi-dimensional response matrix."""
    groups = defaultdict(list)
    for r in results:
        groups[r["Scenario"]].append(r)

    hdr = (f"  {'场景':<18s} {'合法/非法':>10s} {'认证P/F':>8s} {'新鲜度P/F':>10s} "
           f"{'交付L/I':>8s} {'拒收':>5s} {'重同步':>6s} {'错误':>4s} {'超时':>4s} "
           f"{'IAR':>8s} {'FRR':>8s}")
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))

    for scenario_name in sorted(groups.keys()):
        gr = groups[scenario_name]
        n_valid = sum(1 for r in gr if r["VectorType"] == "VALID")
        n_invalid = len(gr) - n_valid

        auth_pass = sum(1 for r in gr if r["z_auth"] == "PASS")
        auth_fail = sum(1 for r in gr if r["z_auth"] == "FAIL")
        fresh_pass = sum(1 for r in gr if r["z_fresh"] == "PASS")
        fresh_fail = sum(1 for r in gr if r["z_fresh"] == "FAIL")
        d_app_legit = sum(1 for r in gr if r["d_app"] == 1 and r["VectorType"] == "VALID")
        d_app_illegit = sum(1 for r in gr if r["d_app"] == 1 and r["VectorType"] != "VALID")
        rejected = sum(1 for r in gr if r["d_app"] == 0 and r["Verdict"] != "INCONCLUSIVE")
        resync = sum(1 for r in gr if r.get("a_resync") not in ("NONE", None))
        errors = sum(1 for r in gr if r.get("e") and r["e"] not in ("None", None))
        timeouts = sum(1 for r in gr if r.get("e") == "TIMEOUT")

        # IAR/FRR for this group
        valid_c = [r for r in gr if r["VectorType"] == "VALID" and r["eta"] == "COMPLETE"]
        invalid_c = [r for r in gr if r["VectorType"] != "VALID" and r["eta"] == "COMPLETE"]
        iar = sum(1 for r in invalid_c if r["d_app"] == 1) / len(invalid_c) if invalid_c else 0.0
        frr = sum(1 for r in valid_c if r["d_app"] == 0) / len(valid_c) if valid_c else 0.0

        auth_str = f"{auth_pass}/{auth_fail}"
        fresh_str = f"{fresh_pass}/{fresh_fail}"
        del_str = f"{d_app_legit}/{d_app_illegit}"

        print(f"  {scenario_name:<18s} {n_valid}/{n_invalid:<7d} "
              f"{auth_str:>8s} {fresh_str:>10s} {del_str:>8s} "
              f"{rejected:>5d} {resync:>6d} {errors:>4d} {timeouts:>4d} "
              f"{iar:>7.2%} {frr:>7.2%}")


def run_config_mutations(all_results: list[dict]):
    """Execute and report three controlled config mutations (Table 11).
    M1: Rollover gating missing
    M2: MAC length policy non-compliance
    M3: Crypto context isolation insufficient
    """
    print(f"  {'编号':<6s} {'变异类型':<24s} {'判定依据':<48s} {'结果':<6s}")
    print("  " + "-" * 90)

    key = b'\x00' * 16
    key2 = b'\x11' * 16

    # ── M1: Rollover gating missing ──
    # Build a PDU with a genuine low FV (post-rollover candidate) and valid MAC.
    # Receiver at fv_last near 2^32-1. Baseline should block delivery;
    # PERMISSIVE config should allow delivery.
    msg = DEFAULT_MESSAGES[0]
    cfg_base = copy.deepcopy(DEFAULT_CONFIG)
    cfg_base.A = msg.auth_area

    cfg_m1 = copy.deepcopy(DEFAULT_CONFIG)
    cfg_m1.A = msg.auth_area
    cfg_m1.rho = "PERMISSIVE"

    m1_killed = _test_m1_rollover(msg, cfg_base, cfg_m1, key)
    print(f"  {'M1':<6s} {'回绕门控缺失':<24s} "
          f"{'非法回绕候选被交付且状态更新缺少受认证依据':<48s} "
          f"{'杀死' if m1_killed else '存活':<6s}")

    # ── M2: MAC length policy non-compliance ──
    cfg_m2 = copy.deepcopy(DEFAULT_CONFIG)
    cfg_m2.A = msg.auth_area
    cfg_m2.ell = 16  # too short for declared (q=1000, θ=2⁻³²) policy

    q = 1000
    theta = 2 ** -32
    p_forge = 1 - (1 - 2 ** -cfg_m2.ell) ** q
    load_rejected = p_forge > theta

    m2_killed = load_rejected  # Policy check kills at config load
    print(f"  {'M2':<6s} {'认证器长度策略不符合':<24s} "
          f"{'P_forge > θ, 配置风险超过声明阈值':<48s} "
          f"{'杀死' if m2_killed else '存活':<6s}")

    # ── M3: Crypto context isolation insufficient ──
    # Build PDU with key2 for msg[2], present to receiver expecting msg[0] with key.
    # Baseline (separate contexts): different key → MAC reject
    # Mutation (shared context): same key → potentially accept
    cfg_m3 = copy.deepcopy(DEFAULT_CONFIG)
    cfg_m3.A = msg.auth_area
    cfg_m3.kappa = (0, 0, 0)

    m3_killed = _test_m3_context(msg, DEFAULT_MESSAGES[2], cfg_base, cfg_m3,
                                  key, key2)
    print(f"  {'M3':<6s} {'密码上下文隔离不足':<24s} "
          f"{'跨上下文输入通过认证并被交付至应用层':<48s} "
          f"{'杀死' if m3_killed else '存活':<6s}")


def _test_m1_rollover(msg, cfg_base, cfg_m1, key) -> bool:
    """M1: Test rollover gating.
    Build PDU with low FV (post-rollover), inject into receiver at near-max FV.
    Baseline (AUTH_RESTRICTED) should block delivery.
    Mutation (PERMISSIVE) should allow delivery → killed.
    """
    fm_tx = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    # Set sender counter to a low value (simulating post-rollover)
    fm_tx._counter = 5

    # Build PDU with FV=5 and valid MAC
    sender = SecOCSender(cfg_base, fm_tx)
    payload = os.urandom(msg.payload_len)
    p_wire, _ = sender.build_secured_pdu(payload, msg.data_id, key)
    # P_wire has FV=5 with correct MAC — NO perturbation needed

    # Baseline: receiver at fv_last near max, ROLLOVER_PENDING
    fm_rx_base = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    fm_rx_base.prepare_rollover_pending()
    rx_base = SecOCReceiver(cfg_base, fm_rx_base, key)
    resp_base = rx_base.process(p_wire, msg.data_id)
    v_base = determine(VectorType.BOUNDARY_OUT, resp_base, msg.deadline_ms)
    # Baseline should PASS (correctly blocks rollover candidate from delivery)

    # Mutant: same but with PERMISSIVE rollover policy
    fm_rx_m1 = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    fm_rx_m1.prepare_rollover_pending()
    rx_m1 = SecOCReceiver(cfg_m1, fm_rx_m1, key)
    resp_m1 = rx_m1.process(p_wire, msg.data_id)
    v_m1 = determine(VectorType.BOUNDARY_OUT, resp_m1, msg.deadline_ms)

    return config_killed(v_base, v_m1)


def _test_m3_context(msg_a, msg_b, cfg_base, cfg_m3, key_a, key_b) -> bool:
    """M3: Test crypto context isolation.
    Attacker uses msg_b's leaked key to forge a PDU for msg_a.
    Baseline (separate contexts): key_a ≠ key_b → MAC reject → PASS.
    Mutation (shared context): same key → MAC accept → FAIL → killed.
    """
    # Build PDU for MSG_A's data_id but with MSG_B's key (cross-context forgery)
    fm_tx = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    fm_tx.prepare_sync(fv_start=100)  # Sync with receiver's expected FV
    cfg_tx = copy.deepcopy(cfg_base)
    cfg_tx.A = msg_a.auth_area
    sender = SecOCSender(cfg_tx, fm_tx)
    payload = os.urandom(msg_a.payload_len)
    # Forge: use msg_a's data_id but msg_b's key
    p_wire, _ = sender.build_secured_pdu(payload, msg_a.data_id, key_b)

    # Baseline: receiver for msg_a uses key_a (correct isolation)
    fm_rx_base = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    fm_rx_base.prepare_sync(fv_start=100)
    rx_base = SecOCReceiver(cfg_base, fm_rx_base, key_a)
    resp_base = rx_base.process(p_wire, msg_a.data_id)
    v_base = determine(VectorType.CONFIG, resp_base, msg_a.deadline_ms)
    # MAC computed with key_b, verified with key_a → auth FAIL → correct rejection

    # Mutation: receiver uses key_b (contexts merged — msg_a now uses msg_b's key)
    fm_rx_m3 = FreshnessManager(bit_width=32, trunc_bits=12, window=16)
    fm_rx_m3.prepare_sync(fv_start=100)
    rx_m3 = SecOCReceiver(cfg_m3, fm_rx_m3, key_b)  # Shared key due to weak isolation
    resp_m3 = rx_m3.process(p_wire, msg_a.data_id)
    v_m3 = determine(VectorType.CONFIG, resp_m3, msg_a.deadline_ms)
    # MAC computed with key_b, verified with key_b → auth PASS → illegal delivery

    return config_killed(v_base, v_m3)


def print_coverage(results: list[dict], scenarios: list[dict]):
    """Eq.(42): Coverage breakdown."""
    states_seen = set()
    for r in results:
        states_seen.add(r.get("StateBefore", "UNKNOWN"))
    C_state = len(states_seen) / 4  # 4 states in Eq.(9)

    # Config boundaries covered
    config_values = defaultdict(set)
    for s in scenarios:
        config_values["ell"].add(s["config"].ell)
        config_values["W"].add(s["config"].W)

    # Operator coverage
    operators_seen = set()
    for s in scenarios:
        operators_seen.add(s["perturbation"].ptype.name)

    # Requirement coverage
    vtypes_seen = set()
    for r in results:
        vtypes_seen.add(r.get("VectorType", "UNKNOWN"))

    print(f"  C_state      = {C_state:.2f}  ({len(states_seen)}/4 states covered)")
    print(f"  C_config     = {len(config_values['ell'])} MAC lengths, "
          f"{len(config_values['W'])} window sizes")
    print(f"  C_operator   = {len(operators_seen)} perturbation types covered")
    print(f"  C_requirement = {len(vtypes_seen)} verdict types covered")
    print(f"  (Eq.42 components reported separately — no single composite score)")


if __name__ == "__main__":
    main()
