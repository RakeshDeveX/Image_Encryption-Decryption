"""
imgcrypt_core.py - encryption engine (no GUI code here, so it is easy to test).

Two modes:
  * "chaotic" - the scheme from Alghamdi, Munir & Ahmad, Entropy 2022, 24, 1344:
                SHA-256(plaintext) ^ key ^ IV -> two logistic-map seeds ->
                row permutation -> AES S-box -> column permutation -> XOR with matrix M2.
  * "gcm"     - AES-256-GCM (standard, authenticated). Use this for real protection.

The cipher image is saved as a PNG; everything needed for decryption except the
password (salt, IV, nonce, tag, shape) is stored inside the PNG text chunk "ICE".
PNG is lossless, so the pixels survive. Never send the result as JPEG!
"""
from __future__ import annotations

import base64
import hashlib
import json
import os

import numpy as np
from PIL import Image, ImageDraw, ImageOps
from PIL.PngImagePlugin import PngInfo

R = 3.99876          # logistic-map control parameter (paper, Algorithm 1)
SCALE = 1e6          # paper: Key * 10^6 mod 256
BURN_IN = 100        # skip the first iterations of the chaotic orbit
META_KEY = "ICE"
MODES = ("chaotic", "gcm")


class CryptoError(Exception):
    """Base error shown to the user."""


class WrongPasswordError(CryptoError):
    """Wrong password, or the image was modified / re-compressed."""


# --------------------------------------------------------------------------- #
# AES S-box (computed, not typed by hand)
# --------------------------------------------------------------------------- #
def _gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _build_sbox() -> np.ndarray:
    sbox = []
    for x in range(256):
        inv = 0
        if x:
            inv = 1
            for _ in range(254):          # x^254 = multiplicative inverse in GF(2^8)
                inv = _gmul(inv, x)
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox.append(s ^ 0x63)
    return np.array(sbox, dtype=np.uint8)


SBOX = _build_sbox()
INV_SBOX = np.empty(256, dtype=np.uint8)
INV_SBOX[SBOX] = np.arange(256, dtype=np.uint8)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_key(password: str, salt: bytes) -> bytes:
    """Password -> 32-byte key (scrypt, memory-hard)."""
    if not password:
        raise CryptoError("Password is empty.")
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 15, r=8, p=1,
                          maxmem=128 * 1024 * 1024, dklen=32)


def image_hash(arr: np.ndarray) -> bytes:
    h = hashlib.sha256()
    h.update(np.array(arr.shape, dtype=np.uint32).tobytes())
    h.update(np.ascontiguousarray(arr).tobytes())
    return h.digest()


def logistic_sequence(x0: float, n: int, r: float = R, burn: int = BURN_IN) -> np.ndarray:
    """x_{n+1} = r * x_n * (1 - x_n)  (Equation 1 of the paper)."""
    x = x0
    for _ in range(burn):
        x = r * x * (1.0 - x)
    out = [0.0] * n
    for i in range(n):
        x = r * x * (1.0 - x)
        out[i] = x
    return np.array(out, dtype=np.float64)


def _seeds(img_hash: bytes, ksym: bytes, iv: bytes) -> tuple[float, float]:
    """Key = Hash ^ ksym ^ IV, split in two 128-bit halves, mapped into (0.0001, 0.9999)."""
    key = bytes(a ^ b ^ c for a, b, c in zip(img_hash, ksym, iv))
    k1 = int.from_bytes(key[:16], "big") / 2 ** 128
    k2 = int.from_bytes(key[16:], "big") / 2 ** 128
    return 0.0001 + 0.9998 * k1, 0.0001 + 0.9998 * k2


def _chaotic_material(x1: float, x2: float, h: int, w: int, c: int):
    seq1 = logistic_sequence(x1, h + w)
    row_p = np.argsort(seq1[:h], kind="stable")
    col_p = np.argsort(seq1[h:h + w], kind="stable")
    seq2 = logistic_sequence(x2, h * w * c)
    m2 = (np.floor(seq2 * SCALE).astype(np.int64) % 256).astype(np.uint8).reshape(h, w, c)
    return row_p, col_p, m2


# --------------------------------------------------------------------------- #
# mode 1: chaotic (the paper)
# --------------------------------------------------------------------------- #
def encrypt_chaotic(arr: np.ndarray, password: str, *, _iv=None, _salt=None, _hash=None):
    h, w, c = arr.shape
    salt = _salt or os.urandom(16)
    iv = _iv or os.urandom(32)
    ksym = derive_key(password, salt)
    img_hash = _hash or image_hash(arr)
    x1, x2 = _seeds(img_hash, ksym, iv)
    row_p, col_p, m2 = _chaotic_material(x1, x2, h, w, c)

    q = arr[row_p, :, :]          # row permutation
    q = SBOX[q]                   # substitution (AES S-box)
    q = q[:, col_p, :]            # column permutation
    cipher = q ^ m2               # XOR with Matrix 2

    # The receiver needs Hash(P). We store it masked so that the file does not
    # leak a hash of your plaintext (which would allow "guess the picture" tests).
    mask = hashlib.sha256(ksym + b"hash-mask" + iv).digest()
    meta = {"v": 1, "mode": "chaotic", "shape": [h, w, c], "salt": _b64(salt),
            "iv": _b64(iv), "hmask": _b64(bytes(a ^ b for a, b in zip(img_hash, mask)))}
    return cipher, meta


def decrypt_chaotic(cipher: np.ndarray, meta: dict, password: str) -> np.ndarray:
    h, w, c = meta["shape"]
    salt, iv = _unb64(meta["salt"]), _unb64(meta["iv"])
    ksym = derive_key(password, salt)
    mask = hashlib.sha256(ksym + b"hash-mask" + iv).digest()
    img_hash = bytes(a ^ b for a, b in zip(_unb64(meta["hmask"]), mask))
    x1, x2 = _seeds(img_hash, ksym, iv)
    row_p, col_p, m2 = _chaotic_material(x1, x2, h, w, c)

    q = cipher ^ m2
    t = np.empty_like(q)
    t[:, col_p, :] = q            # undo column permutation
    t = INV_SBOX[t]               # undo S-box
    plain = np.empty_like(t)
    plain[row_p, :, :] = t        # undo row permutation
    if image_hash(plain) != img_hash:
        raise WrongPasswordError("Wrong password, or the encrypted image was changed.")
    return plain


# --------------------------------------------------------------------------- #
# mode 2: AES-256-GCM (recommended for real use)
# --------------------------------------------------------------------------- #
def _aad(meta: dict) -> bytes:
    return json.dumps({k: meta[k] for k in ("v", "mode", "shape", "salt", "nonce")},
                      sort_keys=True).encode()


def encrypt_gcm(arr: np.ndarray, password: str):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    meta = {"v": 1, "mode": "gcm", "shape": list(arr.shape), "salt": _b64(salt),
            "nonce": _b64(nonce)}
    key = derive_key(password, salt)
    ct_tag = AESGCM(key).encrypt(nonce, np.ascontiguousarray(arr).tobytes(), _aad(meta))
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    meta["tag"] = _b64(tag)
    return np.frombuffer(ct, dtype=np.uint8).reshape(arr.shape).copy(), meta


def decrypt_gcm(cipher: np.ndarray, meta: dict, password: str) -> np.ndarray:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = derive_key(password, _unb64(meta["salt"]))
    try:
        pt = AESGCM(key).decrypt(_unb64(meta["nonce"]),
                                 cipher.tobytes() + _unb64(meta["tag"]), _aad(meta))
    except InvalidTag as exc:
        raise WrongPasswordError("Wrong password, or the encrypted image was changed.") from exc
    return np.frombuffer(pt, dtype=np.uint8).reshape(meta["shape"]).copy()


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def encrypt(arr: np.ndarray, password: str, mode: str = "gcm"):
    if mode == "chaotic":
        return encrypt_chaotic(arr, password)
    if mode == "gcm":
        return encrypt_gcm(arr, password)
    raise CryptoError(f"Unknown mode: {mode}")


def decrypt(cipher: np.ndarray, meta: dict, password: str) -> np.ndarray:
    if list(cipher.shape) != list(meta["shape"]):
        raise CryptoError("Image size does not match the stored data (was it resized?).")
    if meta["mode"] == "chaotic":
        return decrypt_chaotic(cipher, meta, password)
    if meta["mode"] == "gcm":
        return decrypt_gcm(cipher, meta, password)
    raise CryptoError("Unknown mode in image data.")


# --------------------------------------------------------------------------- #
# image I/O
# --------------------------------------------------------------------------- #
def array_to_image(arr: np.ndarray) -> Image.Image:
    return Image.fromarray(arr[:, :, 0] if arr.shape[2] == 1 else arr)


def read_any(path: str):
    """Open a file. Returns (uint8 array HxWxC, meta or None, PIL image for preview)."""
    img = Image.open(path)
    img.load()
    meta = None
    if META_KEY in img.info:
        try:
            meta = json.loads(img.info[META_KEY])
        except ValueError:
            meta = None
    if meta is None:
        img = ImageOps.exif_transpose(img)       # fix phone-photo rotation
    if img.mode not in ("L", "RGB", "RGBA"):
        has_alpha = "A" in img.mode or "transparency" in img.info
        img = img.convert("RGBA" if has_alpha else "RGB")
    arr = np.array(img, dtype=np.uint8)
    if arr.ndim == 2:
        arr = arr[:, :, None]
    return arr, meta, img


def save_png(arr: np.ndarray, path: str, meta: dict | None = None) -> None:
    info = PngInfo()
    if meta is not None:
        info.add_text(META_KEY, json.dumps(meta))
    array_to_image(arr).save(path, "PNG", pnginfo=info)


# --------------------------------------------------------------------------- #
# security / quality metrics (Section 4 of the paper)
# --------------------------------------------------------------------------- #
CHI2_CRIT_005 = 293.25     # chi-square critical value, 255 d.o.f., alpha = 0.05


def entropy(arr: np.ndarray) -> float:
    counts = np.bincount(arr.ravel(), minlength=256).astype(np.float64)
    p = counts[counts > 0] / counts.sum()
    return float(-(p * np.log2(p)).sum())


def chi_square(arr: np.ndarray) -> float:
    counts = np.bincount(arr.ravel(), minlength=256).astype(np.float64)
    e = arr.size / 256.0
    return float(((counts - e) ** 2 / e).sum())


def _corr(a: np.ndarray, b: np.ndarray) -> float:
    a, b = a.astype(np.float64).ravel(), b.astype(np.float64).ravel()
    if a.std() == 0 or b.std() == 0:
        return 0.0
    return float(np.corrcoef(a, b)[0, 1])


def adjacent_correlation(arr: np.ndarray) -> dict:
    return {"horizontal": _corr(arr[:, :-1], arr[:, 1:]),
            "vertical": _corr(arr[:-1, :], arr[1:, :]),
            "diagonal": _corr(arr[:-1, :-1], arr[1:, 1:])}


def npcr_uaci(c1: np.ndarray, c2: np.ndarray) -> tuple[float, float]:
    npcr = float((c1 != c2).mean() * 100)
    uaci = float((np.abs(c1.astype(np.int16) - c2.astype(np.int16)) / 255.0).mean() * 100)
    return npcr, uaci


def mse_psnr(plain: np.ndarray, cipher: np.ndarray) -> tuple[float, float]:
    mse = float(((plain.astype(np.float64) - cipher.astype(np.float64)) ** 2).mean())
    psnr = float(10 * np.log10(255.0 ** 2 / mse)) if mse > 0 else float("inf")
    return mse, psnr


def analyze(plain: np.ndarray, cipher: np.ndarray) -> dict:
    mse, psnr = mse_psnr(plain, cipher)
    return {"entropy_plain": entropy(plain), "entropy_cipher": entropy(cipher),
            "chi2_plain": chi_square(plain), "chi2_cipher": chi_square(cipher),
            "corr_plain": adjacent_correlation(plain),
            "corr_cipher": adjacent_correlation(cipher), "mse": mse, "psnr": psnr}


def format_report(rep: dict) -> str:
    cc, cp = rep["corr_cipher"], rep["corr_plain"]
    chi_ok = "pass" if rep["chi2_cipher"] < CHI2_CRIT_005 else "FAIL"
    return (
        f"Entropy (ideal 8.0)      plain {rep['entropy_plain']:.4f}   cipher {rep['entropy_cipher']:.4f}\n"
        f"Chi-square (<293.25 ok)  plain {rep['chi2_plain']:.0f}   cipher {rep['chi2_cipher']:.1f}  [{chi_ok}]\n"
        f"Correlation H / V / D    plain {cp['horizontal']:.3f} / {cp['vertical']:.3f} / {cp['diagonal']:.3f}\n"
        f"                         cipher {cc['horizontal']:+.4f} / {cc['vertical']:+.4f} / {cc['diagonal']:+.4f}  (ideal 0)\n"
        f"MSE {rep['mse']:.0f}   PSNR {rep['psnr']:.2f} dB (lower = better hiding)"
    )


def histogram_image(arr: np.ndarray, size=(360, 110), bg=(30, 30, 36), fg=(90, 160, 255)) -> Image.Image:
    """Small luminance histogram, drawn with Pillow (no matplotlib needed)."""
    w, h = size
    lum = arr[:, :, :3].mean(axis=2).astype(np.uint8) if arr.shape[2] >= 3 else arr[:, :, 0]
    counts = np.bincount(lum.ravel(), minlength=256).astype(np.float64)
    top = max(counts.max(), 1.0)
    img = Image.new("RGB", size, bg)
    d = ImageDraw.Draw(img)
    for i in range(256):
        x = int(i * (w - 1) / 255)
        bar = int(counts[i] / top * (h - 8))
        d.line([(x, h - 2), (x, h - 2 - bar)], fill=fg, width=max(1, w // 256))
    return img
