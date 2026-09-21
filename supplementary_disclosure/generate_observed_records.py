#!/usr/bin/env python3
"""Generate the public supplementary CSV data sets.

The records written by this script are observations of the Python reference
implementation. They are not samples from the TC397 timing model and are not
embedded-hardware measurements.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import math
import platform
import random
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cast_secoc.config import DEFAULT_CONFIG, DEFAULT_MESSAGES
from cast_secoc.freshness import FreshnessManager
from cast_secoc.receiver import SecOCReceiver
from cast_secoc.sender import SecOCSender
from cast_secoc.verdict import VectorType, config_killed, determine


OUT = Path(__file__).resolve().parent
SEED = 20260911
REPETITIONS = 5
TEST_KEY = bytes(16)
FIELDS = [
    "RunId", "VectorId", "Scenario", "MessageAlias", "Repeat",
    "ConfigHash", "InputSeed", "PayloadSha256", "WirePduSha256",
    "StateBefore", "VectorType", "z_auth", "z_fresh", "d_app",
    "a_resync", "nu_state", "Error", "EvidenceCompleteness",
    "Verdict", "HostElapsedNs", "ReceiverTauNs", "DataOrigin",
]

EQUIVALENCE_FIELDS = [
    "CandidateVectorId", "EquivalenceClassId", "RepresentativeVectorId",
    "Retained", "EquivalenceSignatureSha256", "EquivalenceSignature",
    "MessageAlias", "Scenario", "StateBefore", "VectorType",
    "Perturbation", "ConfigHash", "RequirementId", "CoverageObligations",
    "InputSeed", "ReductionReason", "DataOrigin",
]

REGRESSION_FIELDS = [
    "VectorId", "EquivalenceClassId", "Scenario", "MessageAlias",
    "InputSeed", "ConfigHash", "StateBefore", "FvLastBefore",
    "VectorType", "Perturbation", "Setup", "PayloadHex", "WirePduHex",
    "ExpectedAuth", "ExpectedFreshness", "ExpectedDelivery",
    "ExpectedResync", "ExpectedStateUpdate", "ExpectedError",
    "ExpectedVerdict", "RequirementId", "CoverageObligations", "DataOrigin",
]

MUTANT_FIELDS = [
    "MutantId", "Name", "MutationLayer", "Target", "BaselineValue",
    "MutantValue", "RequirementId", "WitnessVectorId", "InputSeed",
    "BaselineConfigHash", "MutantConfigHash", "BaselineVerdict",
    "MutantVerdict", "BaselineAuth", "MutantAuth", "BaselineFreshness",
    "MutantFreshness", "BaselineDelivery", "MutantDelivery",
    "BaselineStateUpdate", "MutantStateUpdate", "LoadRejected",
    "Equivalent", "Killed", "WitnessSpecification", "DataOrigin",
]

SCENARIO_SEMANTICS = {
    "合法基准通信": {
        "perturbation": "NONE",
        "requirement": "REQ-VALID-DELIVERY",
        "setup": "prepare_sync(fv_last=100)",
    },
    "受认证区域内载荷篡改": {
        "perturbation": "XOR_0x01_AT_AUTH_AREA_OFFSET",
        "requirement": "REQ-AUTH-AREA-INTEGRITY",
        "setup": "prepare_sync(fv_last=100)",
    },
    "全零认证器伪造": {
        "perturbation": "REPLACE_TRUNCATED_MAC_WITH_ZERO",
        "requirement": "REQ-MAC-FORGERY-REJECTION",
        "setup": "prepare_sync(fv_last=100)",
    },
    "已接收报文重放": {
        "perturbation": "REPLAY_PREVIOUSLY_ACCEPTED_SECURED_PDU",
        "requirement": "REQ-FRESHNESS-REPLAY-REJECTION",
        "setup": "prepare_sync(fv_last=100); accept witness once; replay same PDU",
    },
    "严格策略下FV回绕候选": {
        "perturbation": "AUTHENTICATED_POST_ROLLOVER_LOW_FV_5",
        "requirement": "REQ-ROLLOVER-GATING",
        "setup": "prepare_rollover_pending(fv_last=2^b-3)",
    },
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical_json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def short_object_hash(value) -> str:
    return sha256_bytes(canonical_json(value).encode("utf-8"))[:16]


def vector_id_text(vector_id: int) -> str:
    return f"V{vector_id:04d}"


def make_config(msg):
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    cfg.A = msg.auth_area
    cfg.msg_id = f"PDU-{chr(65 + DEFAULT_MESSAGES.index(msg))}"
    cfg.data_id = msg.data_id
    return cfg


def prepare_pair(cfg, fv_last: int = 100):
    fm = FreshnessManager(cfg.b, cfg.lambda_, cfg.W)
    fm.prepare_sync(fv_last)
    return fm, SecOCSender(cfg, fm), SecOCReceiver(cfg, fm, TEST_KEY)


def observe(receiver, p_wire: bytes, data_id: int):
    started = time.perf_counter_ns()
    response = receiver.process(p_wire, data_id)
    elapsed = time.perf_counter_ns() - started
    return response, elapsed


def base_record(run_id, vector_id, scenario, alias, repeat, cfg, deadline_ms,
                input_seed, payload, wire, state_before, vector_type, response,
                elapsed):
    return {
        "RunId": run_id,
        "VectorId": vector_id,
        "Scenario": scenario,
        "MessageAlias": alias,
        "Repeat": repeat,
        "ConfigHash": cfg.config_hash,
        "InputSeed": input_seed,
        "PayloadSha256": sha256_bytes(payload),
        "WirePduSha256": sha256_bytes(wire),
        "StateBefore": state_before,
        "VectorType": vector_type.value,
        "z_auth": response["z_auth"],
        "z_fresh": response["z_fresh"],
        "d_app": response["d_app"],
        "a_resync": response["a_resync"],
        "nu_state": response["nu_state"],
        "Error": response.get("e") or "",
        "EvidenceCompleteness": response["eta"],
        "Verdict": determine(vector_type, response, deadline_ms),
        "HostElapsedNs": elapsed,
        "ReceiverTauNs": round(response["tau"] * 1_000_000_000),
        "DataOrigin": "direct_python_execution",
    }


def execute_case(run_id, vector_id, scenario, msg, repeat, input_seed):
    cfg = make_config(msg)
    alias = cfg.msg_id
    rng = random.Random(input_seed)
    payload = rng.randbytes(msg.payload_len)

    if scenario == "合法基准通信":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.VALID
        state_before = "SYNC"
        fv_last_before = 100

    elif scenario == "受认证区域内载荷篡改":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        changed = bytearray(wire)
        changed[cfg.A[0]] ^= 0x01
        wire = bytes(changed)
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.TAMPER
        state_before = "SYNC"
        fv_last_before = 100

    elif scenario == "全零认证器伪造":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        changed = bytearray(wire)
        mac_bytes = cfg.ell // 8
        changed[-mac_bytes:] = bytes(mac_bytes)
        wire = bytes(changed)
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.TAMPER
        state_before = "SYNC"
        fv_last_before = 100

    elif scenario == "已接收报文重放":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        first, _ = observe(receiver, wire, msg.data_id)
        if first["d_app"] != 1:
            raise RuntimeError("replay setup failed: baseline frame was not delivered")
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.REPLAY
        state_before = "SYNC"
        fv_last_before = 101

    elif scenario == "严格策略下FV回绕候选":
        fm_tx = FreshnessManager(cfg.b, cfg.lambda_, cfg.W)
        fm_tx._counter = 5
        sender = SecOCSender(cfg, fm_tx)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        fm_rx = FreshnessManager(cfg.b, cfg.lambda_, cfg.W)
        fm_rx.prepare_rollover_pending()
        receiver = SecOCReceiver(cfg, fm_rx, TEST_KEY)
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.BOUNDARY_OUT
        state_before = "ROLLOVER_PENDING"
        fv_last_before = (1 << cfg.b) - 3

    else:
        raise ValueError(scenario)

    record = base_record(
        run_id, vector_id, scenario, alias, repeat, cfg, msg.deadline_ms, input_seed,
        payload, wire, state_before, vtype, response, elapsed,
    )
    semantics = SCENARIO_SEMANTICS[scenario]
    obligations = [
        f"MESSAGE:{alias}",
        f"STATE:{state_before}",
        f"PERTURBATION:{semantics['perturbation']}",
        f"REQUIREMENT:{semantics['requirement']}",
    ]
    vector = {
        "VectorId": vector_id_text(vector_id),
        "Scenario": scenario,
        "MessageAlias": alias,
        "Repeat": repeat,
        "InputSeed": input_seed,
        "ConfigHash": cfg.config_hash,
        "StateBefore": state_before,
        "FvLastBefore": fv_last_before,
        "VectorType": vtype.value,
        "Perturbation": semantics["perturbation"],
        "Setup": semantics["setup"],
        "PayloadHex": payload.hex(),
        "WirePduHex": wire.hex(),
        "ExpectedAuth": response["z_auth"],
        "ExpectedFreshness": response["z_fresh"],
        "ExpectedDelivery": response["d_app"],
        "ExpectedResync": response["a_resync"],
        "ExpectedStateUpdate": response["nu_state"],
        "ExpectedError": response.get("e") or "",
        "ExpectedVerdict": record["Verdict"],
        "RequirementId": semantics["requirement"],
        "CoverageObligations": "|".join(obligations),
        "DataOrigin": "deterministic_direct_python_execution",
    }
    return record, vector


def write_records(path: Path, records):
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(records)


def write_summary(path: Path, records):
    grouped = defaultdict(list)
    for row in records:
        grouped[row["Scenario"]].append(row)
    fields = [
        "Scenario", "N", "Pass", "Fail", "Inconclusive",
        "AuthPass", "AuthFail", "FreshPass", "FreshFail",
        "Delivered", "Rejected", "Errors", "DataOrigin",
    ]
    rows = []
    for scenario, values in grouped.items():
        rows.append({
            "Scenario": scenario,
            "N": len(values),
            "Pass": sum(v["Verdict"] == "PASS" for v in values),
            "Fail": sum(v["Verdict"] == "FAIL" for v in values),
            "Inconclusive": sum(v["Verdict"] == "INCONCLUSIVE" for v in values),
            "AuthPass": sum(v["z_auth"] == "PASS" for v in values),
            "AuthFail": sum(v["z_auth"] == "FAIL" for v in values),
            "FreshPass": sum(v["z_fresh"] == "PASS" for v in values),
            "FreshFail": sum(v["z_fresh"] == "FAIL" for v in values),
            "Delivered": sum(v["d_app"] == 1 for v in values),
            "Rejected": sum(v["d_app"] == 0 for v in values),
            "Errors": sum(bool(v["Error"]) for v in values),
            "DataOrigin": "derived_from_selected_execution_records",
        })
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def equivalence_signature(vector: dict) -> dict:
    """Observable semantic signature used for the disclosed reduction.

    Payload bytes, repetition index and input seed are deliberately excluded:
    they do not change the covered requirement or the receiver-side semantic
    relation in this fixed representative disclosure subset.
    """
    return {
        "message_alias": vector["MessageAlias"],
        "scenario": vector["Scenario"],
        "state_before": vector["StateBefore"],
        "vector_type": vector["VectorType"],
        "perturbation": vector["Perturbation"],
        "config_hash": vector["ConfigHash"],
        "requirement_id": vector["RequirementId"],
        "coverage_obligations": vector["CoverageObligations"],
    }


def build_equivalence_sets(vectors: list[dict]):
    grouped = defaultdict(list)
    signature_text = {}
    for vector in vectors:
        text = canonical_json(equivalence_signature(vector))
        digest = sha256_bytes(text.encode("utf-8"))
        grouped[digest].append(vector)
        signature_text[digest] = text

    class_ids = {
        digest: f"EC-{index:03d}"
        for index, digest in enumerate(grouped, start=1)
    }
    rows = []
    representatives = []
    for digest, members in grouped.items():
        members = sorted(members, key=lambda item: int(item["VectorId"][1:]))
        representative = members[0]
        class_id = class_ids[digest]
        representative["EquivalenceClassId"] = class_id
        representatives.append(representative)
        for vector in members:
            retained = vector["VectorId"] == representative["VectorId"]
            rows.append({
                "CandidateVectorId": vector["VectorId"],
                "EquivalenceClassId": class_id,
                "RepresentativeVectorId": representative["VectorId"],
                "Retained": str(retained).lower(),
                "EquivalenceSignatureSha256": digest,
                "EquivalenceSignature": signature_text[digest],
                "MessageAlias": vector["MessageAlias"],
                "Scenario": vector["Scenario"],
                "StateBefore": vector["StateBefore"],
                "VectorType": vector["VectorType"],
                "Perturbation": vector["Perturbation"],
                "ConfigHash": vector["ConfigHash"],
                "RequirementId": vector["RequirementId"],
                "CoverageObligations": vector["CoverageObligations"],
                "InputSeed": vector["InputSeed"],
                "ReductionReason": (
                    "lowest VectorId retained as deterministic representative"
                    if retained else
                    "same observable semantic signature as representative"
                ),
                "DataOrigin": "derived_from_disclosed_candidate_vectors",
            })
    return rows, representatives


def write_csv(path: Path, fields: list[str], rows: list[dict]):
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            {field: row.get(field, "") for field in fields}
            for row in rows
        )


def execute_mutants(regression_vectors: list[dict]) -> list[dict]:
    msg_a = DEFAULT_MESSAGES[0]
    msg_c = DEFAULT_MESSAGES[2]
    key_a = bytes(16)
    key_c = bytes([0x11]) * 16
    rows = []

    # M1: the same authenticated rollover witness is blocked by the baseline
    # and incorrectly delivered by a permissive rollover configuration.
    rollover = next(
        vector for vector in regression_vectors
        if vector["MessageAlias"] == "PDU-A"
        and vector["Scenario"] == "严格策略下FV回绕候选"
    )
    cfg_base = make_config(msg_a)
    cfg_m1 = copy.deepcopy(cfg_base)
    cfg_m1.rho = "PERMISSIVE"
    wire = bytes.fromhex(rollover["WirePduHex"])
    fm_base = FreshnessManager(cfg_base.b, cfg_base.lambda_, cfg_base.W)
    fm_base.prepare_rollover_pending()
    resp_base = SecOCReceiver(cfg_base, fm_base, key_a).process(wire, msg_a.data_id)
    fm_mutant = FreshnessManager(cfg_m1.b, cfg_m1.lambda_, cfg_m1.W)
    fm_mutant.prepare_rollover_pending()
    resp_mutant = SecOCReceiver(cfg_m1, fm_mutant, key_a).process(wire, msg_a.data_id)
    verdict_base = determine(VectorType.BOUNDARY_OUT, resp_base, msg_a.deadline_ms)
    verdict_mutant = determine(VectorType.BOUNDARY_OUT, resp_mutant, msg_a.deadline_ms)
    rows.append(mutant_record(
        "M1", "回绕门控缺失", "configuration", "rho",
        "AUTH_RESTRICTED", "PERMISSIVE", "REQ-ROLLOVER-GATING",
        rollover["VectorId"], rollover["InputSeed"], cfg_base.config_hash,
        cfg_m1.config_hash, verdict_base, verdict_mutant, resp_base,
        resp_mutant, False,
        "authenticated low-FV rollover candidate at receiver state ROLLOVER_PENDING",
    ))

    # M2: policy mutation is killed at configuration load; no wire stimulus is
    # required because the declared forgery probability exceeds the threshold.
    cfg_m2_base = make_config(msg_a)
    cfg_m2 = copy.deepcopy(cfg_m2_base)
    cfg_m2.ell = 16
    attempts = 1000
    threshold = 2 ** -32
    baseline_probability = -math.expm1(
        attempts * math.log1p(-(2.0 ** -cfg_m2_base.ell))
    )
    mutant_probability = -math.expm1(
        attempts * math.log1p(-(2.0 ** -cfg_m2.ell))
    )
    load_rejected = mutant_probability > threshold
    policy_base = {"z_auth": "NA", "z_fresh": "NA", "d_app": 0, "nu_state": "UNCHANGED"}
    policy_mutant = dict(policy_base)
    rows.append(mutant_record(
        "M2", "认证器长度策略不符合", "configuration_load", "ell",
        "64", "16", "REQ-MAC-LENGTH-POLICY", "POLICY-M2-001", "",
        cfg_m2_base.config_hash, cfg_m2.config_hash, "PASS", "FAIL",
        policy_base, policy_mutant, load_rejected,
        f"q={attempts}; theta=2^-32; baseline_p={baseline_probability:.12g}; "
        f"mutant_p={mutant_probability:.12g}",
    ))

    # M3: a PDU authenticated with context C's key is rejected by the baseline
    # mapping for PDU-A but accepted after both messages are mapped to key C.
    m3_seed = SEED + 900_003
    payload = random.Random(m3_seed).randbytes(msg_a.payload_len)
    cfg_m3 = make_config(msg_a)
    fm_tx = FreshnessManager(cfg_m3.b, cfg_m3.lambda_, cfg_m3.W)
    fm_tx.prepare_sync(100)
    wire_m3, _ = SecOCSender(cfg_m3, fm_tx).build_secured_pdu(
        payload, msg_a.data_id, key_c,
    )
    fm_base = FreshnessManager(cfg_m3.b, cfg_m3.lambda_, cfg_m3.W)
    fm_base.prepare_sync(100)
    resp_base = SecOCReceiver(cfg_m3, fm_base, key_a).process(wire_m3, msg_a.data_id)
    fm_mutant = FreshnessManager(cfg_m3.b, cfg_m3.lambda_, cfg_m3.W)
    fm_mutant.prepare_sync(100)
    resp_mutant = SecOCReceiver(cfg_m3, fm_mutant, key_c).process(wire_m3, msg_a.data_id)
    verdict_base = determine(VectorType.CONFIG, resp_base, msg_a.deadline_ms)
    verdict_mutant = determine(VectorType.CONFIG, resp_mutant, msg_a.deadline_ms)
    baseline_mapping = {"PDU-A": "key-0", "PDU-C": "key-1"}
    mutant_mapping = {"PDU-A": "key-1", "PDU-C": "key-1"}
    rows.append(mutant_record(
        "M3", "密码上下文隔离不足", "crypto_context_mapping", "kappa/key_ref",
        canonical_json(baseline_mapping), canonical_json(mutant_mapping),
        "REQ-CRYPTO-CONTEXT-ISOLATION", "CROSSCTX-M3-001", m3_seed,
        short_object_hash(baseline_mapping), short_object_hash(mutant_mapping),
        verdict_base, verdict_mutant, resp_base, resp_mutant, False,
        f"target=PDU-A; source-context=PDU-C; payload={payload.hex()}; "
        f"wire={wire_m3.hex()}",
    ))
    return rows


def mutant_record(mutant_id, name, layer, target, baseline_value, mutant_value,
                  requirement_id, witness_id, input_seed, baseline_hash,
                  mutant_hash, baseline_verdict, mutant_verdict, baseline_resp,
                  mutant_resp, load_rejected, witness_specification):
    equivalent = (
        baseline_verdict == mutant_verdict
        and baseline_resp.get("d_app") == mutant_resp.get("d_app")
        and baseline_resp.get("z_auth") == mutant_resp.get("z_auth")
        and not load_rejected
    )
    killed = config_killed(baseline_verdict, mutant_verdict, load_rejected)
    return {
        "MutantId": mutant_id,
        "Name": name,
        "MutationLayer": layer,
        "Target": target,
        "BaselineValue": baseline_value,
        "MutantValue": mutant_value,
        "RequirementId": requirement_id,
        "WitnessVectorId": witness_id,
        "InputSeed": input_seed,
        "BaselineConfigHash": baseline_hash,
        "MutantConfigHash": mutant_hash,
        "BaselineVerdict": baseline_verdict,
        "MutantVerdict": mutant_verdict,
        "BaselineAuth": baseline_resp.get("z_auth", "NA"),
        "MutantAuth": mutant_resp.get("z_auth", "NA"),
        "BaselineFreshness": baseline_resp.get("z_fresh", "NA"),
        "MutantFreshness": mutant_resp.get("z_fresh", "NA"),
        "BaselineDelivery": baseline_resp.get("d_app", 0),
        "MutantDelivery": mutant_resp.get("d_app", 0),
        "BaselineStateUpdate": baseline_resp.get("nu_state", "UNCHANGED"),
        "MutantStateUpdate": mutant_resp.get("nu_state", "UNCHANGED"),
        "LoadRejected": str(load_rejected).lower(),
        "Equivalent": str(equivalent).lower(),
        "Killed": str(killed).lower(),
        "WitnessSpecification": witness_specification,
        "DataOrigin": "direct_python_baseline_mutant_comparison",
    }


def write_config(path: Path):
    messages = []
    for index, msg in enumerate(DEFAULT_MESSAGES):
        messages.append({
            "alias": f"PDU-{chr(65 + index)}",
            "can_id": f"0x{msg.can_id:03X}",
            "data_id": msg.data_id,
            "source": msg.src,
            "destination": msg.dst,
            "payload_bytes": msg.payload_len,
            "period_ms": msg.period_ms,
            "deadline_ms": msg.deadline_ms,
            "risk": msg.risk,
            "authenticated_area": list(msg.auth_area),
            "identifier_status": "anonymized_test_value",
        })
    document = {
        "configuration_scope": "python_reference_prototype",
        "embedded_production_configuration": False,
        "secoc": {
            "mac_truncation_bits": DEFAULT_CONFIG.ell,
            "freshness_transmitted_bits": DEFAULT_CONFIG.lambda_,
            "freshness_full_bits": DEFAULT_CONFIG.b,
            "receive_window": DEFAULT_CONFIG.W,
            "rollover_policy": DEFAULT_CONFIG.rho,
            "timeout_policy": DEFAULT_CONFIG.timeout_policy,
            "timeout_ms": DEFAULT_CONFIG.timeout_ms,
            "persistence_policy": DEFAULT_CONFIG.persist_policy,
            "byte_order": "big_endian",
            "mac_truncation_direction": "leftmost_bytes",
        },
        "messages": messages,
        "test_key": {
            "kind": "public_test_only",
            "length_bits": len(TEST_KEY) * 8,
            "sha256": sha256_bytes(TEST_KEY),
        },
    }
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    for name in ("config", "data", "metadata"):
        (OUT / name).mkdir(parents=True, exist_ok=True)

    generated_at = datetime.now(timezone.utc)
    run_id = generated_at.strftime("PYOBS-%Y%m%dT%H%M%SZ")
    scenarios = [
        "合法基准通信",
        "受认证区域内载荷篡改",
        "全零认证器伪造",
        "已接收报文重放",
        "严格策略下FV回绕候选",
    ]

    records = []
    vectors = []
    vector_id = 0
    for message_index, msg in enumerate(DEFAULT_MESSAGES):
        for scenario_index, scenario in enumerate(scenarios):
            for repeat in range(1, REPETITIONS + 1):
                vector_id += 1
                input_seed = SEED + message_index * 10_000 + scenario_index * 100 + repeat
                record, vector = execute_case(
                    run_id, vector_id, scenario, msg, repeat, input_seed,
                )
                records.append(record)
                vectors.append(vector)

    equivalence_rows, regression_vectors = build_equivalence_sets(vectors)
    mutant_rows = execute_mutants(regression_vectors)

    write_records(OUT / "data/selected_execution_records.csv", records)
    write_summary(OUT / "data/scenario_summary.csv", records)
    write_csv(
        OUT / "data/equivalence_classes.csv",
        EQUIVALENCE_FIELDS,
        equivalence_rows,
    )
    write_csv(
        OUT / "data/fixed_regression_set.csv",
        REGRESSION_FIELDS,
        regression_vectors,
    )
    write_csv(OUT / "data/mutants.csv", MUTANT_FIELDS, mutant_rows)
    write_config(OUT / "config/config_snapshot.json")

    metadata = {
        "run_id": run_id,
        "generated_at_utc": generated_at.isoformat(),
        "record_origin": "direct_python_execution",
        "system_under_test": "CAST-SecOC Python reference prototype",
        "model_generated_timing": False,
        "embedded_hardware_measurement": False,
        "host_elapsed_field": "observed wall-clock duration around SecOCReceiver.process",
        "seed": SEED,
        "record_count": len(records),
        "message_count": len(DEFAULT_MESSAGES),
        "scenario_count": len(scenarios),
        "repetitions_per_message_scenario": REPETITIONS,
        "equivalence_candidate_count": len(equivalence_rows),
        "equivalence_class_count": len(regression_vectors),
        "fixed_regression_vector_count": len(regression_vectors),
        "mutant_count": len(mutant_rows),
        "mutants_killed": sum(row["Killed"] == "true" for row in mutant_rows),
        "equivalence_scope": (
            "125 disclosed deterministic candidate executions; payload bytes, "
            "repeat number and seed are excluded from the semantic signature"
        ),
        "python": sys.version,
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "repository_source_hashes": {
            str(path.relative_to(REPO_ROOT)): file_sha256(path)
            for path in [
                REPO_ROOT / "cast_secoc/config.py",
                REPO_ROOT / "cast_secoc/freshness.py",
                REPO_ROOT / "cast_secoc/sender.py",
                REPO_ROOT / "cast_secoc/receiver.py",
                REPO_ROOT / "cast_secoc/sm4.py",
                REPO_ROOT / "cast_secoc/verdict.py",
            ]
        },
    }
    (OUT / "metadata/run_metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        f"generated {len(records)} directly observed records, "
        f"{len(regression_vectors)} equivalence representatives and "
        f"{len(mutant_rows)} mutant comparisons in {OUT}"
    )


if __name__ == "__main__":
    main()
