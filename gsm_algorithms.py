"""Core GSM demo algorithms for educational auth and encryption flow."""

from __future__ import annotations

import hashlib
import hmac


def a3_a8(ki: bytes, rand: bytes) -> tuple[bytes, bytes]:
    """Возвращает (SRES, Kc) по алгоритму A3/A8 (HMAC-SHA256)."""
    mac = hmac.new(ki, rand, hashlib.sha256).digest()
    sres = mac[:4]
    kc = mac[4:12]
    return sres, kc


class A5Cipher:
    """A5-like CTR шифр (учебная модель без внешних зависимостей)."""

    def __init__(self, kc: bytes):
        if len(kc) != 8:
            raise ValueError("Kc must be 8 bytes")
        self.key = kc.ljust(16, b"\x00")

    def _keystream(self, frame_number: int, length: int) -> bytes:
        if frame_number < 0:
            raise ValueError("frame_number must be non-negative")
        out = bytearray()
        ctr_hi = frame_number & ((1 << 64) - 1)
        ctr_lo = 0
        while len(out) < length:
            counter_block = ctr_hi.to_bytes(8, "big") + ctr_lo.to_bytes(8, "big")
            out.extend(hashlib.sha256(self.key + counter_block).digest())
            ctr_lo = (ctr_lo + 1) & ((1 << 64) - 1)
        return bytes(out[:length])

    def encrypt(self, plaintext: bytes, frame_number: int) -> bytes:
        ks = self._keystream(frame_number, len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, ks))

    def decrypt(self, ciphertext: bytes, frame_number: int) -> bytes:
        return self.encrypt(ciphertext, frame_number)


def a5_encrypt(kc: bytes, frame_number: int, plaintext: bytes) -> bytes:
    return A5Cipher(kc).encrypt(plaintext, frame_number)


def a5_decrypt(kc: bytes, frame_number: int, ciphertext: bytes) -> bytes:
    return A5Cipher(kc).decrypt(ciphertext, frame_number)
