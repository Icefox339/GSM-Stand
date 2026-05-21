"""Core GSM demo algorithms: A3/A8 authentication and A5-like stream cipher.

This module intentionally provides *educational* stand-ins that model the GSM flow:
- A3/A8: derive SRES and Kc from Ki and RAND
- A5: keystream generation and XOR encryption/decryption
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class AuthTriplet:
    rand: bytes
    sres: bytes
    kc: bytes


def a3_a8_comp128_like(ki: bytes, rand: bytes) -> tuple[bytes, bytes]:
    """Return (SRES, Kc) from Ki and RAND.

    Educational COMP128-like derivation using SHA-256 for determinism.
    - SRES: first 4 bytes
    - Kc: next 8 bytes
    """
    digest = hashlib.sha256(ki + rand).digest()
    sres = digest[:4]
    kc = digest[4:12]
    return sres, kc


def a5_keystream(kc: bytes, frame_number: int, length: int) -> bytes:
    """Generate A5-like keystream for a frame number.

    Uses repeated SHA-256(kc || frame || counter) blocks.
    """
    if frame_number < 0:
        raise ValueError("frame_number must be non-negative")
    out = bytearray()
    counter = 0
    while len(out) < length:
        seed = kc + frame_number.to_bytes(4, "big") + counter.to_bytes(4, "big")
        out.extend(hashlib.sha256(seed).digest())
        counter += 1
    return bytes(out[:length])


def a5_encrypt(kc: bytes, frame_number: int, plaintext: bytes) -> bytes:
    ks = a5_keystream(kc, frame_number, len(plaintext))
    return bytes(p ^ k for p, k in zip(plaintext, ks))


def a5_decrypt(kc: bytes, frame_number: int, ciphertext: bytes) -> bytes:
    return a5_encrypt(kc, frame_number, ciphertext)
