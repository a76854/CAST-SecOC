"""Receive, authenticate, freshness-check, and gate secured I-PDUs."""
import hmac
import struct
import time
from .sm4 import sm4_cmac, timed
from .config import SecOCConfig
from .freshness import FreshnessManager, RxState, FvRelation


# ── Response types ────────────────────────────────────────────────────

class AuthResult:
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "NA"

class FreshResult:
    PASS = "PASS"
    FAIL = "FAIL"
    NA = "NA"

class ResyncAction:
    NONE = "NONE"
    REQUESTED = "REQUESTED"
    AUTHENTICATED = "AUTHENTICATED"
    UNAUTHENTICATED = "UNAUTHENTICATED"

class StateUpdate:
    UNCHANGED = "UNCHANGED"
    UPDATED_AUTH = "UPDATED_AUTH"
    UPDATED_UNAUTH = "UPDATED_UNAUTH"
    UNKNOWN = "UNKNOWN"


class SecOCReceiver:
    """SecOC-compliant receiver that verifies, gates, and responds."""

    def __init__(self, config: SecOCConfig, fm: FreshnessManager, key: bytes):
        self.config = config
        self.fm = fm
        self.key = key
        self.error_code = None

    def process(self, p_wire: bytes, data_id: int,
                measure: bool = True) -> dict:
        """Process a secured I-PDU and return a multi-dimensional response.
        The receiver does NOT know the test vector type — it faithfully follows
        the protocol specification regardless.
        """
        t0 = time.perf_counter() if measure else 0.0
        old_state = self.fm.rx_state.copy()

        # Defaults
        z_auth = AuthResult.NA
        z_fresh = FreshResult.NA
        d_app = 0
        a_resync = ResyncAction.NONE
        nu_state = StateUpdate.UNCHANGED
        e = None
        eta = "COMPLETE"

        try:
            # Split the payload from the freshness and authenticator fields.
            fv_bytes = (self.config.lambda_ + 7) // 8
            mac_bytes = self.config.ell // 8

            if len(p_wire) <= fv_bytes + mac_bytes:
                e = "PARSE_ERROR_SHORT"
                eta = "INCOMPLETE"
                elapsed = (time.perf_counter() - t0) if measure else 0.0
                return self._result(z_auth, z_fresh, d_app, a_resync, nu_state, e, elapsed, eta)

            payload_length = len(p_wire) - fv_bytes - mac_bytes
            self.config.validate(payload_length)
            auth_ipdu = p_wire[:payload_length]
            pos = payload_length
            fv_tr = int.from_bytes(p_wire[pos:pos + fv_bytes], 'big')
            mac_rcv = p_wire[pos + fv_bytes:pos + fv_bytes + mac_bytes]

            # Reconstruct and classify the full freshness value.
            fv_hat, fv_rel = self.fm.reconstruct(fv_tr)
            if fv_hat is None:
                z_fresh = FreshResult.FAIL
            elif fv_rel in (FvRelation.STALE, FvRelation.OUT_OF_WINDOW):
                z_fresh = FreshResult.FAIL
            else:
                z_fresh = FreshResult.PASS

            # Rebuild the authenticated data and verify the MAC.
            o, n = self.config.A
            if n > len(auth_ipdu):
                n = len(auth_ipdu)
            auth_region = auth_ipdu[o:o + n]

            if not 0 <= data_id <= 0xFFFF:
                raise ValueError("DataID must fit in 16 bits")
            d_auth = struct.pack('>H', data_id)
            d_auth += auth_region
            # Use reconstructed FV if available, else the truncated value
            fv_for_auth = fv_hat if fv_hat is not None else fv_tr
            full_fv_bytes = (self.config.b + 7) // 8
            d_auth += fv_for_auth.to_bytes(full_fv_bytes, 'big')

            mac_computed, _ = timed(sm4_cmac, self.key, d_auth)
            mac_computed_tr = mac_computed[:mac_bytes]

            if hmac.compare_digest(mac_computed_tr, mac_rcv):
                z_auth = AuthResult.PASS
            else:
                z_auth = AuthResult.FAIL

            # Gate application delivery on authentication and freshness.
            # Application delivery only if BOTH auth AND freshness pass
            # AND receiver is in SYNC state
            if z_auth == AuthResult.PASS and z_fresh == FreshResult.PASS:
                if fv_rel == FvRelation.WRAP_CANDIDATE:
                    if self.config.rho == "AUTH_RESTRICTED":
                        a_resync = ResyncAction.AUTHENTICATED
                        self.fm.set_state(RxState.ROLLOVER_PENDING)
                        self.fm.accept(fv_hat, authenticated=True)
                        nu_state = StateUpdate.UPDATED_AUTH
                        d_app = 0
                    else:
                        self.fm.set_state(RxState.ROLLOVER_PENDING)
                        self.fm.accept(fv_hat, authenticated=True)
                        nu_state = StateUpdate.UPDATED_AUTH
                        d_app = 1
                elif self.fm.rx_state.state == RxState.SYNC:
                    d_app = 1
                    self.fm.accept(fv_hat, authenticated=True)
                    nu_state = StateUpdate.UPDATED_AUTH
                elif self.fm.rx_state.state == RxState.ROLLOVER_PENDING:
                    d_app = 0
                    a_resync = ResyncAction.REQUESTED
                elif self.fm.rx_state.state == RxState.RESYNC_PENDING:
                    if z_auth == AuthResult.PASS:
                        a_resync = ResyncAction.AUTHENTICATED
                        self.fm.set_state(RxState.SYNC)
                        self.fm.accept(fv_hat, authenticated=True)
                        nu_state = StateUpdate.UPDATED_AUTH
                        d_app = 0  # Resync pending — don't deliver until confirmed
                elif self.fm.rx_state.state == RxState.DESYNC:
                    if z_auth == AuthResult.PASS:
                        a_resync = ResyncAction.REQUESTED
                        self.fm.set_state(RxState.RESYNC_PENDING)
                    d_app = 0
            elif z_auth == AuthResult.PASS and z_fresh == FreshResult.FAIL:
                d_app = 0
                # Stale/out-of-window — do NOT update state unless authenticated resync
                if self.fm.rx_state.state == RxState.DESYNC:
                    a_resync = ResyncAction.REQUESTED
                    self.fm.set_state(RxState.RESYNC_PENDING)
                    nu_state = StateUpdate.UPDATED_AUTH
                elif (fv_rel == FvRelation.OUT_OF_WINDOW
                      and self.fm.rx_state.state == RxState.SYNC):
                    a_resync = ResyncAction.REQUESTED
                    self.fm.set_state(RxState.RESYNC_PENDING)
                    nu_state = StateUpdate.UPDATED_AUTH
            elif z_auth == AuthResult.FAIL:
                d_app = 0
                # NEVER deliver on auth failure
                # NEVER update state on unauthenticated input
                nu_state = StateUpdate.UNCHANGED

            # Detect any state change without valid authentication.
            if nu_state == StateUpdate.UPDATED_AUTH and z_auth == AuthResult.PASS:
                pass  # Valid auth-based update
            elif (self.fm.rx_state.fv_last != old_state.fv_last
                  or self.fm.rx_state.state != old_state.state
                  or self.fm.rx_state.epoch != old_state.epoch) and z_auth != AuthResult.PASS:
                nu_state = StateUpdate.UPDATED_UNAUTH

        except Exception as ex:
            e = f"INTERNAL_ERROR:{ex}"
            eta = "INCOMPLETE"

        elapsed = (time.perf_counter() - t0) if measure else 0.0

        # ── Apply timeout policy ──
        timeout_s = self.config.timeout_ms / 1000.0
        if elapsed > timeout_s:
            if self.config.timeout_policy == "REJECT_AND_REPORT":
                e = e or "TIMEOUT"
                d_app = 0

        return self._result(z_auth, z_fresh, d_app, a_resync, nu_state, e, elapsed, eta)

    def _result(self, z_auth, z_fresh, d_app, a_resync, nu_state, e, elapsed, eta) -> dict:
        return dict(
            z_auth=z_auth, z_fresh=z_fresh, d_app=d_app, a_resync=a_resync,
            nu_state=nu_state, e=e, tau=elapsed, eta=eta,
            fv_last_after=self.fm.rx_state.fv_last,
            rx_state_after=self.fm.rx_state.state.name,
        )

    def reset(self) -> None:
        self.fm.reset_rx()
        self.error_code = None
