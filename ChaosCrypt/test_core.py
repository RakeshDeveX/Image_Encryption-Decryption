"""Run:  python test_core.py     (checks the engine and the paper's claims)"""
import os
import tempfile
import time

import numpy as np
from PIL import Image, ImageDraw

import imgcrypt_core as core


def make_test_image(h=256, w=256, c=3):
    """Synthetic picture with smooth gradients + shapes (like a real photo: highly correlated)."""
    img = Image.new("RGB", (w, h))
    d = ImageDraw.Draw(img)
    for y in range(h):
        d.line([(0, y), (w, y)], fill=(y * 255 // h, 80, 255 - y * 255 // h))
    d.ellipse([w // 5, h // 5, w * 3 // 5, h * 3 // 5], fill=(240, 200, 30))
    d.rectangle([w // 2, h // 2, w * 9 // 10, h * 9 // 10], fill=(20, 160, 90))
    arr = np.array(img, dtype=np.uint8)
    return arr[:, :, :c] if c != 1 else arr.mean(axis=2).astype(np.uint8)[:, :, None]


def main():
    # 1. S-box sanity (FIPS-197 values)
    assert core.SBOX[0x00] == 0x63 and core.SBOX[0x01] == 0x7C and core.SBOX[0x53] == 0xED
    assert (core.INV_SBOX[core.SBOX] == np.arange(256)).all()
    print("[ok] AES S-box matches FIPS-197")

    # 2. round trips for all modes / channel counts
    for mode in core.MODES:
        for c in (1, 3, 4):
            p = make_test_image(96, 128, c) if c != 4 else np.dstack(
                [make_test_image(96, 128, 3), np.full((96, 128, 1), 255, np.uint8)])
            cph, meta = core.encrypt(p, "correct horse battery", mode)
            assert core.decrypt(cph, meta, "correct horse battery").tobytes() == p.tobytes()
            try:
                core.decrypt(cph, meta, "wrong password")
                raise SystemExit("wrong password was accepted!")
            except core.WrongPasswordError:
                pass
    print("[ok] encrypt -> decrypt round trip (gray/RGB/RGBA, both modes) + wrong password rejected")

    # 3. save as PNG, reload from disk, decrypt
    p = make_test_image(200, 300, 3)
    with tempfile.TemporaryDirectory() as tmp:
        for mode in core.MODES:
            cph, meta = core.encrypt(p, "pw-12345678", mode)
            f = os.path.join(tmp, f"{mode}.png")
            core.save_png(cph, f, meta)
            arr, m2, _ = core.read_any(f)
            assert m2 is not None and core.decrypt(arr, m2, "pw-12345678").tobytes() == p.tobytes()
    print("[ok] PNG save / load / decrypt from disk")

    # 4. tamper detection
    cph, meta = core.encrypt(p, "pw-12345678", "gcm")
    bad = cph.copy(); bad[3, 3, 0] ^= 1
    try:
        core.decrypt(bad, meta, "pw-12345678"); raise SystemExit("tampering not detected")
    except core.WrongPasswordError:
        print("[ok] GCM detects a 1-bit modification")

    # 5. speed
    big = make_test_image(512, 512, 3)
    t = time.time(); core.encrypt(big, "pw-12345678", "chaotic"); t1 = time.time() - t
    t = time.time(); core.encrypt(big, "pw-12345678", "gcm"); t2 = time.time() - t
    print(f"[info] 512x512 RGB: chaotic {t1:.2f}s, gcm {t2:.2f}s (both include scrypt key derivation)")

    # 6. metrics (what the paper reports)
    cph, _ = core.encrypt(big, "pw-12345678", "chaotic")
    rep = core.analyze(big, cph)
    print("\n--- Metrics, chaotic mode (test picture, 512x512 RGB) ---")
    print(core.format_report(rep))

    # 7. The paper's diffusion claim, checked.
    #    (a) paper-style: encrypt P and P' (1 pixel changed) normally -> the plaintext hash changes
    p2 = big.copy(); p2[100, 100, 0] ^= 1
    c1, _ = core.encrypt(big, "pw-12345678", "chaotic")
    c2, _ = core.encrypt(p2, "pw-12345678", "chaotic")
    npcr, uaci = core.npcr_uaci(c1, c2)
    print(f"\n[paper-style test] NPCR {npcr:.4f}%  UACI {uaci:.4f}%   (looks perfect)")
    #    (b) same key material (same hash + IV + salt): what does the cipher itself do?
    iv, salt, hsh = os.urandom(32), os.urandom(16), core.image_hash(big)
    c1, _ = core.encrypt_chaotic(big, "pw-12345678", _iv=iv, _salt=salt, _hash=hsh)
    c2, _ = core.encrypt_chaotic(p2, "pw-12345678", _iv=iv, _salt=salt, _hash=hsh)
    changed = int((c1 != c2).sum())
    print(f"[fixed-key test]  1 plaintext byte flipped -> {changed} cipher byte(s) changed "
          f"out of {c1.size}  (NPCR {changed / c1.size * 100:.5f}%)")


if __name__ == "__main__":
    main()
