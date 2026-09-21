"""Generate, execute, evaluate, and record SecOC test vectors."""
import hashlib
import os
import random
from dataclasses import dataclass, field
from .config import SecOCConfig, MessageSpec
from .freshness import FreshnessManager, RxState, FvRelation
from .sender import SecOCSender
from .receiver import SecOCReceiver
from .bus import CanFDBus
from .perturb import Perturbation, PerturbType, apply_perturbation
from .verdict import (
    VectorType, Verdict, determine,
    classify_defect, compute_metrics,
)


@dataclass
class TestVector:
    """A complete executable test vector."""
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

    # ── Cover-gain vector generation ────────────────

    def generate_vectors(self, messages: list[MessageSpec],
                         states: list[RxState],
                         fv_relations: list[FvRelation],
                         configs: list[SecOCConfig],
                         perturbations: list[tuple[VectorType, Perturbation]],
                         budget: int = 2000) -> list[TestVector]:
        """Select vectors by deterministic marginal coverage gain."""
        # Generate candidate vectors with compatibility filtering.
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

        candidates = self._dedup_vectors(candidates)

        selected = []
        covered = set()

        while len(selected) < budget and candidates:
            gains = [len(self._coverage_items(tv) - covered) for tv in candidates]
            idx = max(
                range(len(candidates)),
                key=lambda i: (gains[i], -candidates[i].vector_id),
            )
            tv = candidates.pop(idx)
            tv.execution_order = len(selected)
            selected.append(tv)
            covered.update(self._coverage_items(tv))

        return selected

    @staticmethod
    def _coverage_items(tv: TestVector) -> set[tuple]:
        """Return the individual and pairwise features covered by a vector."""
        state = tv.target_state.name
        relation = tv.fv_relation.name
        perturbation = tv.perturbation.ptype.name
        vector_type = tv.vector_type.value
        return {
            ("message", tv.msg.data_id),
            ("state", state),
            ("freshness_relation", relation),
            ("perturbation", perturbation),
            ("vector_type", vector_type),
            ("mac_bits", tv.config.ell),
            ("window", tv.config.W),
            ("state_relation", state, relation),
            ("message_perturbation", tv.msg.data_id, perturbation),
        }

    def _compatible(self, msg: MessageSpec, state: RxState,
                    fv_rel: FvRelation, cfg: SecOCConfig,
                    perturb: Perturbation) -> bool:
        """Check whether a candidate has a consistent, representable setup."""
        if state == RxState.ROLLOVER_PENDING and fv_rel not in (
                FvRelation.WRAP_CANDIDATE, FvRelation.STALE):
            return False
        try:
            cfg.validate(msg.payload_len)
        except ValueError:
            return False
        if cfg.kappa[2] not in self.keys:
            return False
        if perturb.tamper_positions and max(perturb.tamper_positions) >= msg.payload_len:
            return False
        if (perturb.ptype == PerturbType.REPLAY_HISTORICAL
                and perturb.replay_pdu is None):
            return False
        return True

    def _dedup_vectors(self, candidates: list[TestVector]) -> list[TestVector]:
        """Remove equivalent vectors (same coverage profile)."""
        seen = set()
        unique = []
        for tv in candidates:
            key = (
                tv.msg.data_id,
                tv.target_state,
                tv.fv_relation,
                tv.config.config_hash,
                tv.vector_type,
                tv.perturbation.ptype,
                tuple(tv.perturbation.tamper_positions or []),
                tv.perturbation.forge_mac_type,
                tv.perturbation.fv_offset,
                tv.perturbation.fv_force_value,
                tv.perturbation.window_position,
                tv.perturbation.cross_data_id,
                tv.perturbation.target_load,
            )
            if key not in seen:
                seen.add(key)
                unique.append(tv)
        return unique

    # ── Execution, verdict, evidence ────────────────

    def execute_all(self, vectors: list[TestVector],
                    bus_loads: list[float] | None = None) -> dict:
        """Execute every vector once across the requested bus loads."""
        if bus_loads is None:
            bus_loads = [0.30]
        if not bus_loads:
            raise ValueError("bus_loads must not be empty")

        for index, tv in enumerate(vectors):
            if tv.perturbation.ptype == PerturbType.HIGH_LOAD:
                bus_load = tv.perturbation.target_load
            else:
                bus_load = bus_loads[index % len(bus_loads)]
            self._execute_one(tv, bus_load=bus_load)

        metrics = compute_metrics(self.results)
        return metrics

    def _execute_one(self, tv: TestVector, bus_load: float = 0.30) -> dict:
        """Execute one vector and record its observable response."""
        # Restore the receiver checkpoint.
        fm = FreshnessManager(bit_width=tv.config.b,
                              trunc_bits=tv.config.lambda_,
                              window=tv.config.W)
        key = self.keys[tv.config.kappa[2]]

        # Capture the active configuration identity.
        config_hash = tv.config.config_hash

        # Prepare the requested receiver state.
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

        # Build the secured input.
        case_rng = random.Random(self.seed + tv.vector_id)
        payload = case_rng.randbytes(tv.msg.payload_len)
        auth_ipdu = payload
        authenticated_boundary = tv.perturbation.ptype in {
            PerturbType.WINDOW_BOUNDARY,
            PerturbType.ROLLOVER_CANDIDATE,
        }
        if authenticated_boundary:
            fm_tx = FreshnessManager(tv.config.b, tv.config.lambda_, tv.config.W)
            if tv.perturbation.ptype == PerturbType.WINDOW_BOUNDARY:
                fm_tx._counter = fm.rx_state.fv_last + tv.perturbation.window_position
            else:
                fm_tx._counter = tv.perturbation.window_position
            sender = SecOCSender(tv.config, fm_tx)
        elif tv.fv_relation != FvRelation.NEXT:
            fm_tx = FreshnessManager(tv.config.b, tv.config.lambda_, tv.config.W)
            modulus = 1 << tv.config.b
            if tv.fv_relation == FvRelation.STALE:
                fm_tx._counter = max(0, fm.rx_state.fv_last - 1)
            elif tv.fv_relation == FvRelation.IN_WINDOW_GAP:
                fm_tx._counter = (fm.rx_state.fv_last + min(2, tv.config.W)) % modulus
            elif tv.fv_relation == FvRelation.OUT_OF_WINDOW:
                fm_tx._counter = (fm.rx_state.fv_last + tv.config.W + 1) % modulus
            elif tv.fv_relation == FvRelation.WRAP_CANDIDATE:
                fm_tx._counter = 0
            sender = SecOCSender(tv.config, fm_tx)
        else:
            sender = SecOCSender(tv.config, fm)
        p_wire, _ = sender.build_secured_pdu(auth_ipdu, tv.msg.data_id, key)

        if not authenticated_boundary:
            p_wire = apply_perturbation(p_wire, tv.perturbation, tv.config, case_rng)

        # Bus transmission delay
        bus = CanFDBus(load=bus_load, rng=case_rng)
        bus_delay = bus.transmit(len(p_wire))

        # Process the input at the receiver.
        receiver = SecOCReceiver(tv.config, fm, key)

        # For cross-context: use wrong key if specified
        if tv.perturbation.ptype == PerturbType.CROSS_CONTEXT:
            wrong_key = tv.perturbation.cross_key or self.keys[1]
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
        resp["rx_state_before"] = tv.target_state.name
        tv.stimulus = p_wire
        tv.response = resp

        # Evaluate the response and classify any failure.
        verdict = determine(tv.vector_type, resp, tv.msg.deadline_ms)
        tv.verdict = verdict

        if verdict == Verdict.FAIL:
            defects = classify_defect(
                tv.vector_type, resp, tv.config, tv.msg.critical_positions,
            )
            tv.defect_labels = defects
            self.defects.append(dict(
                vector_id=tv.vector_id, config_hash=config_hash,
                response=resp, defects=defects))

        self._record(tv, resp, verdict, config_hash)
        return resp

    def _prepare_state(self, fm: FreshnessManager, tv: TestVector) -> bool:
        """Prepare the requested receiver state."""
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
        """Record the observable evidence for one vector."""
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
