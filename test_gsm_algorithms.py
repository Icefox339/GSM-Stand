from gsm_algorithms import a3_a8_comp128_like, a5_decrypt, a5_encrypt


def test_a3_a8_deterministic():
    ki = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    rand = bytes.fromhex("11223344556677889900AABBCCDDEEFF")
    sres1, kc1 = a3_a8_comp128_like(ki, rand)
    sres2, kc2 = a3_a8_comp128_like(ki, rand)
    assert sres1 == sres2
    assert kc1 == kc2
    assert len(sres1) == 4
    assert len(kc1) == 8


def test_a5_roundtrip():
    kc = bytes.fromhex("0123456789ABCDEF")
    frame = 7
    plain = "gsm secret".encode()
    cipher = a5_encrypt(kc, frame, plain)
    out = a5_decrypt(kc, frame, cipher)
    assert out == plain
