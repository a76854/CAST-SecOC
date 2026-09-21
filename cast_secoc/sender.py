"""Build secured I-PDUs with freshness data and a truncated SM4-CMAC."""
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
        """Build a secured I-PDU.
        Returns (P_wire, elapsed_seconds).
        """
        t0 = time.perf_counter() if measure else 0.0
        self.config.validate(len(auth_ipdu))
        if len(key) != 16:
            raise ValueError("SM4 key must be 16 bytes")

        # Get fresh FV
        fv_full = self.fm.next_fv()
        fv_tr = self.fm.truncate(fv_full)

        # Authenticate the configured payload region and full freshness value.
        o, n = self.config.A
        if n > len(auth_ipdu):
            n = len(auth_ipdu)
        auth_region = auth_ipdu[o:o + n]

        if not 0 <= data_id <= 0xFFFF:
            raise ValueError("DataID must fit in 16 bits")
        d_auth = struct.pack('>H', data_id)
        d_auth += auth_region
        full_fv_bytes = (self.config.b + 7) // 8
        d_auth += fv_full.to_bytes(full_fv_bytes, 'big')

        # Compute and truncate SM4-CMAC.
        mac_full, mac_time = timed(sm4_cmac, key, d_auth)

        # Truncate MAC
        ell_bytes = self.config.ell // 8
        mac_tr = mac_full[:ell_bytes]

        # Wire format: authentic I-PDU || transmitted FV || truncated MAC.
        fv_byte_len = (self.config.lambda_ + 7) // 8
        fv_tr_bytes = fv_tr.to_bytes(fv_byte_len, 'big')
        p_wire = auth_ipdu + fv_tr_bytes + mac_tr

        elapsed = (time.perf_counter() - t0) if measure else mac_time
        return p_wire, elapsed

    def build_authentic_ipdu(self, payload: bytes) -> bytes:
        """Build Authentic I-PDU from raw payload (adds header if needed)."""
        return payload
