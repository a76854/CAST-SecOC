#!/usr/bin/env python3
"""

The records written by this script are observations of the Python reference
implementation. They are not samples from the TC397 timing model and are not
embedded-hardware measurements.
"""

from __future__ import annotations

import copy
import csv
import hashlib
import inspect
import json
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
from cast_secoc.verdict import VectorType, determine


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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


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

    elif scenario == "受认证区域内载荷篡改":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        changed = bytearray(wire)
        changed[cfg.A[0]] ^= 0x01
        wire = bytes(changed)
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.TAMPER
        state_before = "SYNC"

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

    elif scenario == "已接收报文重放":
        fm, sender, receiver = prepare_pair(cfg)
        wire, _ = sender.build_secured_pdu(payload, msg.data_id, TEST_KEY)
        first, _ = observe(receiver, wire, msg.data_id)
        if first["d_app"] != 1:
            raise RuntimeError("replay setup failed: baseline frame was not delivered")
        response, elapsed = observe(receiver, wire, msg.data_id)
        vtype = VectorType.REPLAY
        state_before = "SYNC"

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

    else:
        raise ValueError(scenario)

    return base_record(
        run_id, vector_id, scenario, alias, repeat, cfg, msg.deadline_ms, input_seed,
        payload, wire, state_before, vtype, response, elapsed,
    )


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


def write_excerpts(path: Path):
    from cast_secoc.freshness import FreshnessManager as FM
    from cast_secoc.receiver import SecOCReceiver as RX
    from cast_secoc.verdict import determine as verdict_determine

    sources = [
        ("cast_secoc/freshness.py", FM.reconstruct),
        ("cast_secoc/receiver.py", RX.process),
        ("cast_secoc/verdict.py", verdict_determine),
    ]
    blocks = [
        "CAST-SecOC selected core source excerpts\n",
        "These excerpts are copied verbatim by inspect.getsource from the executed version.\n",
    ]
    for relative, target in sources:
        source_path = REPO_ROOT / relative
        blocks.extend([
            f"\n===== {relative} | sha256={file_sha256(source_path)} =====\n",
            inspect.getsource(target),
        ])
    path.write_text("".join(blocks), encoding="utf-8")


def write_manifest():
    paths = sorted(
        p for p in OUT.rglob("*")
        if p.is_file() and p.name != "MANIFEST.sha256"
        and "__pycache__" not in p.parts
    )
    text = "".join(f"{file_sha256(path)}  {path.relative_to(OUT)}\n" for path in paths)
    (OUT / "MANIFEST.sha256").write_text(text, encoding="utf-8")


def main():
    for name in ("code", "config", "data", "metadata"):
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
    vector_id = 0
    for message_index, msg in enumerate(DEFAULT_MESSAGES):
        for scenario_index, scenario in enumerate(scenarios):
            for repeat in range(1, REPETITIONS + 1):
                vector_id += 1
                input_seed = SEED + message_index * 10_000 + scenario_index * 100 + repeat
                records.append(execute_case(
                    run_id, vector_id, scenario, msg, repeat, input_seed,
                ))

    write_records(OUT / "data/selected_execution_records.csv", records)
    write_summary(OUT / "data/scenario_summary.csv", records)
    write_config(OUT / "config/config_snapshot.json")
    write_excerpts(OUT / "code/selected_core_excerpts.txt")

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
    write_manifest()
    print(f"generated {len(records)} directly observed records in {OUT}")


if __name__ == "__main__":
    main()
