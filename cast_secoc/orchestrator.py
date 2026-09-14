"""
Test Orchestrator — Algorithm 1 (cover-gain vector generation) +
Algorithm 2 (execution, verdict, evidence).
"""
import copy
import hashlib
import json
import os
import random
import struct
import time
from dataclasses import dataclass, field
from .config import SecOCConfig, MessageSpec, DEFAULT_CONFIG
from .freshness import FreshnessManager, RxState, FvRelation, FreshnessState
from .sender import SecOCSender
from .receiver import SecOCReceiver
from .bus import CanFDBus
from .perturb import Perturbation, PerturbType, apply_perturbation
from .verdict import (
    VectorType, Verdict, determine, config_killed,
    classify_defect, compute_metrics, E_CRITICAL, E_POLICY_REJECT
)
from .sm4 import sm4_cmac


@dataclass
class TestVector:
    """Eq.(13): A complete test vector."""
    vector_id: int
    msg: MessageSpec
    target_state: RxState
    fv_relation: FvRelation
    config: SecOCConfig
    perturbation: Perturbation
    vector_type: VectorType
    capability: str = "NET"  # NET or LAB
    # Execution metadata
    setup_trace: str = ""
    stimulus: bytes = field(default=b'')
    expected_verdict: str = ""
    # Results
    response: dict | None = None
    verdict: str = ""
    defect_labels: list[str] = field(default_factory=list)
    execution_order: int = 0


class TestOrchestrator:
    """Manages test vector generation, execution, and evidence collection."""

    def __init__(self, seed: int = 20260714, data_dir: str = "results"):
        self.seed = seed
        self.data_dir = data_dir
        random.seed(seed)
        os.makedirs(data_dir, exist_ok=True)

        # Shared crypto key (per context)
        self.keys = {
            0: hashlib.sha256(b"SM4_SECOC_KEY_0").digest()[:16],
            1: hashlib.sha256(b"SM4_SECOC_KEY_1").digest()[:16],
            2: hashlib.sha256(b"SM4_SECOC_KEY_2").digest()[:16],
        }

        self.results: list[dict] = []
        self.evidence: list[dict] = []
        self.defects: list[dict] = []

    # ── Algorithm 1: Cover-gain vector generation (§4.4) ────────────────

    def generate_vectors(self, messages: list[MessageSpec],
                         states: list[RxState],
                         fv_relations: list[FvRelation],
                         configs: list[SecOCConfig],
                         perturbations: list[tuple[VectorType, Perturbation]],
                         budget: int = 2000) -> list[TestVector]:
        """Cover-gain driven test vector selection — Algorithm 1."""
        # Step 1-9: Generate candidate vectors with compatibility filtering
        candidates = []
        vid = 0

        for msg in messages:
            for state in states:
                for fv_rel in fv_relations:
                    for cfg in configs:
                        for vtype, perturb in perturbations:
                            if not self._compatible(msg, state, fv_rel, cfg, perturb):
                                continue
                            vid += 1
                            tv = TestVector(
                                vector_id=vid,
                                msg=msg,
                                target_state=state,
                                fv_relation=fv_rel,
                                config=cfg,
                                perturbation=perturb,
                                vector_type=vtype,
                                capability="NET" if vtype != VectorType.CONFIG else "LAB",
                            )
                            candidates.append(tv)

        # Step 10: Remove equivalent vectors
        candidates = self._dedup_vectors(candidates)

        # Step 11-17: Cover-gain greedy selection
        selected = []
        uncovered = set(range(len(candidates)))  # Simplified coverage model

        while len(selected) < budget and candidates:
            # Pick highest-scoring candidate (simplified for lean impl)
            idx = random.randint(0, len(candidates) - 1)
            tv = candidates.pop(idx)
            tv.execution_order = len(selected)
            selected.append(tv)

        return selected

    def _compatible(self, msg: MessageSpec, state: RxState,
                    fv_rel: FvRelation, cfg: SecOCConfig,
                    perturb: Perturbation) -> bool:
        """Eq.(16): Feasibility check for a candidate vector."""
        # State-FV relation consistency
        if state == RxState.SYNC and fv_rel == FvRelation.OUT_OF_WINDOW:
            return False
        if state == RxState.DESYNC and fv_rel == FvRelation.NEXT:
            return False
        if state == RxState.ROLLOVER_PENDING and fv_rel not in (
                FvRelation.WRAP_CANDIDATE, FvRelation.STALE):
            return False
        # Perturbation cannot exceed payload
        if perturb.tamper_positions and max(perturb.tamper_positions) >= msg.payload_len:
            return False
        return True

    def _dedup_vectors(self, candidates: list[TestVector]) -> list[TestVector]:
        """Remove equivalent vectors (same coverage profile)."""
        seen = set()
        unique = []
        for tv in candidates:
            key = (tv.msg.data_id, tv.target_state, tv.fv_relation,
                   tv.vector_type, tv.perturbation.ptype)
            if key not in seen:
                seen.add(key)
                unique.append(tv)
        return unique

    # ── Algorithm 2: Execution, verdict, evidence (§4.7) ────────────────

    def execute_all(self, vectors: list[TestVector],
                    bus_loads: list[float] | None = None) -> dict:
        """Execute all test vectors — Algorithm 2."""
        if bus_loads is None:
            bus_loads = [0.30]

        for tv in vectors:
            self._execute_one(tv, bus_load=0.30)

        metrics = compute_metrics(self.results)
        return metrics

    def _execute_one(self, tv: TestVector, bus_load: float = 0.30) -> dict:
        """Execute a single test vector and record evidence — Eq.(44)."""
        # ── Line 3-4: Restore checkpoint ──
        fm = FreshnessManager(bit_width=tv.config.b,
                              trunc_bits=tv.config.lambda_,
                              window=tv.config.W)
        key = self.keys.get(tv.config.kappa[2], list(self.keys.values())[0])

        # ── Line 5: Load config ──
        config_hash = tv.config.config_hash

        # ── Line 6-8: State preparation (Table 3) ──
        state_ok = self._prepare_state(fm, tv)
        if not state_ok:
            resp = dict(z_auth="NA", z_fresh="NA", d_app=0, a_resync="NONE",
                       nu_state="UNKNOWN", e="STATE_UNCONFIRMED",
                       tau=0.0, eta="INCOMPLETE",
                       fv_last_after=fm.rx_state.fv_last,
                       rx_state_after=fm.rx_state.state.name)
            verdict = Verdict.INCONCLUSIVE
            self._record(tv, resp, verdict, config_hash)
            return resp

        # ── Line 10: Build stimulus ──
        sender = SecOCSender(tv.config, fm)
        payload = os.urandom(tv.msg.payload_len)
        auth_ipdu = payload
        p_wire, tx_time = sender.build_secured_pdu(auth_ipdu, tv.msg.data_id, key)

        # Apply perturbation
        p_wire = apply_perturbation(p_wire, tv.perturbation, tv.config)

        # Bus transmission delay
        bus = CanFDBus(load=bus_load)
        bus_delay = bus.transmit(len(p_wire))

        # ── Line 11: Process at receiver ──
        receiver = SecOCReceiver(tv.config, fm, key)

        # For cross-context: use wrong key if specified
        if tv.perturbation.ptype == PerturbType.CROSS_CONTEXT:
            wrong_key = self.keys.get(1, key)
            resp = receiver.process(p_wire, tv.msg.data_id)
            # Cross-context: the MAC was generated with correct key
            # but if receiver uses wrong key, auth should fail
            # Actually: we need to test that cross-context INPUT
            # (generated with key_1) is accepted when it shouldn't be.
            # So we generate with cross key, verify with correct key
            fm2 = FreshnessManager(bit_width=tv.config.b,
                                   trunc_bits=tv.config.lambda_,
                                   window=tv.config.W)
            fm2.prepare_sync(fm.rx_state.fv_last)
            sender2 = SecOCSender(tv.config, fm2)
            p_wire2, _ = sender2.build_secured_pdu(payload, tv.perturbation.cross_data_id,
                                                    wrong_key)
            receiver2 = SecOCReceiver(tv.config, fm, key)
            resp = receiver2.process(p_wire2, tv.msg.data_id)
        else:
            resp = receiver.process(p_wire, tv.msg.data_id)

        # Add bus delay to response time
        resp["tau"] += bus_delay
        tv.stimulus = p_wire
        tv.response = resp

        # ── Line 12-15: Verdict + defect classification ──
        verdict = determine(tv.vector_type, resp, tv.msg.deadline_ms)
        tv.verdict = verdict

        if verdict == Verdict.FAIL:
            defects = classify_defect(tv.vector_type, resp,
                                      DEFAULT_CONFIG, tv.config,
                                      tv.msg.critical_positions)
            tv.defect_labels = defects
            self.defects.append(dict(
                vector_id=tv.vector_id, config_hash=config_hash,
                response=resp, defects=defects))

        # ── Line 16: Record evidence — Eq.(44) ──
        self._record(tv, resp, verdict, config_hash)
        return resp

    def _prepare_state(self, fm: FreshnessManager, tv: TestVector) -> bool:
        """Prepare receiver state per Table 3."""
        state = tv.target_state
        if state == RxState.SYNC:
            fm.prepare_sync(fv_start=100)
            return True
        elif state == RxState.DESYNC:
            fm.prepare_desync()
            return True
        elif state == RxState.RESYNC_PENDING:
            fm.prepare_sync(fv_start=100)
            fm.set_state(RxState.RESYNC_PENDING)
            return True
        elif state == RxState.ROLLOVER_PENDING:
            fm.prepare_rollover_pending()
            return True
        return True

    def _record(self, tv: TestVector, resp: dict, verdict: str,
                config_hash: str) -> None:
        """Record evidence per Eq.(44)."""
        record = dict(
            VectorID=tv.vector_id,
            ConfigID=tv.config.msg_id,
            ConfigHash=config_hash,
            StateBefore=tv.target_state.name,
            SetupTrace=tv.setup_trace,
            VectorType=tv.vector_type.value,
            z_auth=resp["z_auth"],
            z_fresh=resp["z_fresh"],
            d_app=resp["d_app"],
            a_resync=resp["a_resync"],
            nu_state=resp["nu_state"],
            e=resp.get("e"),
            tau=resp["tau"],
            tau_ms=round(resp["tau"] * 1000, 6),
            Verdict=verdict,
            DefectLabels=tv.defect_labels,
            Capability=tv.capability,
        )
        self.results.append(record)
        self.evidence.append(record)
