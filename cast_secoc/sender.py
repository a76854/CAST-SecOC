"""
SecOC Sender — Eq.(1)–(4).
Constructs Secured I-PDU from Authentic I-PDU, applies SM4-CMAC,
truncates FV and MAC, measures timing.
"""
import os
import struct
import time
from .sm4 import sm4_cmac, timed
from .config import SecOCConfig
from .freshness import FreshnessManager


class SecOCSender:
    """SecOC-compliant sender that builds and transmits Secured I-PDUs."""

    def __init__(self, config: SecOCConfig, fm: FreshnessManager):
        self.config = config
        self.fm = fm

    def build_secured_pdu(self, auth_ipdu: bytes, data_id: int, key: bytes,
                          measure: bool = True) -> tuple[bytes, float]:
        """Build a Secured I-PDU — Eq.(1).
        Returns (P_wire, elapsed_seconds).
        """
        t0 = time.perf_counter() if measure else 0.0

        # Get fresh FV
        fv_full = self.fm.next_fv()
        fv_tr = self.fm.truncate(fv_full)

        # Build authentication data — Eq.(3)
        o, n = self.config.A
        if n > len(auth_ipdu):
            n = len(auth_ipdu)
        auth_region = auth_ipdu[o:o + n]

        d_auth = struct.pack('>H', data_id & 0xFFFF)
        d_auth += auth_region
        d_auth += struct.pack('>I', fv_full)

        # SM4-CMAC — Eq.(4)
        mac_full, mac_time = timed(sm4_cmac, key, d_auth)

        # Truncate MAC
        ell_bytes = self.config.ell // 8
        mac_tr = mac_full[:ell_bytes]

        # Assemble P_wire — Eq.(1): [Header] || P_auth || [FV_tr] || T_tr
        fv_byte_len = (self.config.lambda_ + 7) // 8
        fv_tr_bytes = fv_tr.to_bytes(fv_byte_len, 'big')
        p_wire = auth_ipdu + fv_tr_bytes + mac_tr

        elapsed = (time.perf_counter() - t0) if measure else mac_time
        return p_wire, elapsed

    def build_authentic_ipdu(self, payload: bytes) -> bytes:
        """Build Authentic I-PDU from raw payload (adds header if needed)."""
        return payload
