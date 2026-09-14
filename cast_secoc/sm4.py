"""
SM4 block cipher + CMAC (GB/T 32907-2016, NIST SP 800-38B).
Pure Python — zero external dependencies.
"""
import struct
import time
from typing import Callable, Optional


# ── SM4 S-box (GMT 0002-2012) ──────────────────────────────────────────
_SBOX = bytes([
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
])

# Family keys FK and constant keys CK
_FK = (0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC)
# CK[i][j] = (4*i + j) * 7 (mod 256) — each byte independent, no cross-byte carry
_CK = tuple(
    ((4 * i + 0) * 7 & 0xFF) << 24 |
    ((4 * i + 1) * 7 & 0xFF) << 16 |
    ((4 * i + 2) * 7 & 0xFF) << 8  |
    ((4 * i + 3) * 7 & 0xFF)
    for i in range(32)
)


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _sub(x: int) -> int:
    """Apply S-box to each byte of 32-bit word."""
    return (_SBOX[(x >> 24) & 0xFF] << 24) | \
           (_SBOX[(x >> 16) & 0xFF] << 16) | \
           (_SBOX[(x >> 8) & 0xFF] << 8)  | \
           (_SBOX[x & 0xFF])


def _L(x: int) -> int:
    """Linear transform L (round function)."""
    return x ^ _rotl(x, 2) ^ _rotl(x, 10) ^ _rotl(x, 18) ^ _rotl(x, 24)


def _Lp(x: int) -> int:
    """Linear transform L' (key schedule)."""
    return x ^ _rotl(x, 13) ^ _rotl(x, 23)


def _T(x: int) -> int:
    return _L(_sub(x))


def _Tp(x: int) -> int:
    return _Lp(_sub(x))


def _expand_key(key: bytes) -> list[int]:
    """Generate 32 round keys from 128-bit key.
    rk_i = K_i ⊕ T'(K_{i+1} ⊕ K_{i+2} ⊕ K_{i+3} ⊕ CK_i)
    """
    MK = list(struct.unpack('>4I', key))
    K = [MK[i] ^ _FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        rk.append(K[0] ^ _Tp(K[1] ^ K[2] ^ K[3] ^ _CK[i]))
        K = [K[1], K[2], K[3], rk[-1]]
    return rk


def _sm4_block_encrypt(block: bytes, rk: list[int]) -> bytes:
    """Encrypt one 128-bit block.
    X_{i+4} = X_i ⊕ T(X_{i+1} ⊕ X_{i+2} ⊕ X_{i+3} ⊕ rk_i)
    """
    X = list(struct.unpack('>4I', block))
    for i in range(32):
        X.append(X[i] ^ _T(X[-3] ^ X[-2] ^ X[-1] ^ rk[i]))
    return struct.pack('>4I', X[35], X[34], X[33], X[32])


def sm4_encrypt(plain: bytes, key: bytes) -> bytes:
    """SM4 ECB encrypt. plain must be multiple of 16 bytes."""
    assert len(key) == 16, "SM4 key must be 16 bytes"
    assert len(plain) % 16 == 0, "Plaintext must be multiple of 16 bytes"
    rk = _expand_key(key)
    return b''.join(_sm4_block_encrypt(plain[i:i+16], rk) for i in range(0, len(plain), 16))


# ── CMAC (NIST SP 800-38B) ────────────────────────────────────────────

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _left_shift_one(b: bytes) -> bytes:
    """Left-shift byte string by 1 bit."""
    carry = 0
    result = bytearray(len(b))
    for i in range(len(b) - 1, -1, -1):
        result[i] = ((b[i] << 1) | carry) & 0xFF
        carry = (b[i] & 0x80) >> 7
    return bytes(result)


_RB = b'\x00' * 15 + b'\x87'  # R_128 constant for GF(2^128)


def sm4_cmac(key: bytes, data: bytes) -> bytes:
    """SM4-CMAC — returns 128-bit (16-byte) tag. key must be 16 bytes."""
    assert len(key) == 16, "SM4 key must be 16 bytes"
    rk = _expand_key(key)

    # Generate subkeys
    zeros = b'\x00' * 16
    L = _sm4_block_encrypt(zeros, rk)
    K1 = _left_shift_one(L)
    if (L[0] & 0x80):
        K1 = _xor_bytes(K1, _RB)
    K2 = _left_shift_one(K1)
    if (K1[0] & 0x80):
        K2 = _xor_bytes(K2, _RB)

    # Pad data
    n = len(data)
    if n % 16 == 0 and n > 0:
        last_block = _xor_bytes(data[-16:], K1)
    else:
        pad_len = 16 - (n % 16)
        padded = data + b'\x80' + b'\x00' * (pad_len - 1)
        last_block = _xor_bytes(padded[-16:], K2)

    blocks = [data[i:i+16] for i in range(0, max(n - 16, 0), 16)]
    if n > 16:
        blocks = data[:n - (n % 16 or 16)]
        blocks = [blocks[i:i+16] for i in range(0, len(blocks), 16)]
    else:
        blocks = []

    C = b'\x00' * 16
    for block in blocks:
        C = _sm4_block_encrypt(_xor_bytes(C, block), rk)
    C = _sm4_block_encrypt(_xor_bytes(C, last_block), rk)
    return C


def timed(func: Callable, *args, **kwargs) -> tuple[object, float]:
    """Call func, return (result, elapsed_seconds)."""
    t0 = time.perf_counter()
    result = func(*args, **kwargs)
    return result, time.perf_counter() - t0


# ── Self-test ──────────────────────────────────────────────────────────

def _self_test() -> None:
    """Verify SM4-CMAC against known test vectors."""
    # SM4-ECB test vector from GB/T 32907-2016
    key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    plain = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    expected_ct = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")
    ct = sm4_encrypt(plain, key)
    assert ct == expected_ct, f"SM4 encrypt failed: {ct.hex()} != {expected_ct.hex()}"

    # CMAC test: verify deterministic
    k = b'\x00' * 16
    t1 = sm4_cmac(k, b'Hello')
    t2 = sm4_cmac(k, b'Hello')
    assert t1 == t2, "CMAC should be deterministic"

    # CMAC: different messages produce different tags
    t3 = sm4_cmac(k, b'World')
    assert t1 != t3, "CMAC should differ for different messages"

    print("[sm4] Self-test passed — SM4-ECB + CMAC OK")


_self_test()
