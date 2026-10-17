#!/usr/bin/env python3
"""Falcon-512 signer for the Starknet Falcon512Account.

Signature (97 felts): s2 (43) || salt (2) || S4 (9) || K (43), where (salt, s2) is a standard
Falcon-512 signature over the 32-byte little-endian transaction hash (SHAKE-256 hash-to-point of
salt || message), and the rest is verifier data:
- S4: the SHAKE-256 sponge state after its 4th Keccak-f permutation (the verifier recomputes it and
  runs the two halves of the squeeze side by side);
- K: k_i = (c_i - (s2*h)_i - s1_i) / q for the centered s1, so that s1 = c - s2*h - q*K with no
  reduction on chain (the verifier range-checks s1; any other K only gives a larger norm).
The account reads NTT(H) / 128 (`ntt_public_key`) from its key class (scripts/gen_key_class.py).
s2 and K use 16-bit slots (s2_i + 6144, k_i + 2^15), packed so that bitwise masks yield the
verifier's base-2^32 blocks directly (`pack_blocks16`). The salt is drawn uniformly at random until
hash-to-point completes within 8 Keccak permutations (the minimum) and every |k_i| < 2^15; any
standard Falcon verifier accepts (salt, s2).

Key files use the pq-accounts format (falcon.py secret key, pickled). Requires a falcon.py
checkout (https://github.com/tprest/falcon.py).

    falcon512_signer.py keygen --falcon-py PATH --key KEY.json
    echo '{"action":"public-key"}' | falcon512_signer.py --falcon-py PATH --key KEY.json
    echo '{"action":"sign-hash","payload":{"hash":"0x..."}}' | falcon512_signer.py --falcon-py PATH --key KEY.json
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pickle
import sys
from pathlib import Path
from typing import Any

Q = 12289
N = 512
SIG_BOUND_512 = 34034726
STARK_P = 2**251 + 17 * 2**192 + 1
MIN_PERMS = 8  # 7 squeeze blocks hold 476 < 512 candidate words
MID_STATE_FELTS = 9  # 25 lanes, three per felt

RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
       [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def centered(x: int) -> int:
    x %= Q
    return x - Q if x > Q // 2 else x


def pack_public_key(h: list[int]) -> list[int]:
    """29 felts: base-q digits (h_i centered + 6144), 9 per u128 half, 8 in the last slot."""
    d = [centered(x) + 6144 for x in h]
    out = []
    for j in range(29):
        chunk = d[18 * j:18 * j + 18]
        lo = sum(v * Q**t for t, v in enumerate(chunk[:9]))
        hi = sum(v * Q**t for t, v in enumerate(chunk[9:]))
        out.append(lo + (hi << 128))
    return out


BLOCK_FELTS = 43
K_OFF = 1 << 15


def pack_blocks16(d: list[int]) -> list[int]:
    """43 felts from 512 digits in [0, 2^16), as 128 blocks of 4 (block m = d[4m..4m+4]).

    Felt j holds block 3j in the even 16-bit slots of its low 128 bits, block 3j+1 in the odd
    slots, and block 3j+2 in the even slots of its high part; the last felt holds blocks 126, 127.
    A block's digit t sits at bit 32t (+16 for odd slots, +128 for the high part)."""
    assert len(d) == N and all(0 <= v < 1 << 16 for v in d)
    blk = [sum(d[4 * m + t] << (32 * t) for t in range(4)) for m in range(N // 4)]
    out = []
    for j in range(BLOCK_FELTS):
        f = blk[3 * j] + (blk[3 * j + 1] << 16)
        if 3 * j + 2 < len(blk):
            f += blk[3 * j + 2] << 128
        out.append(f)
    return out


def pack_s2(s2: list[int]) -> list[int]:
    return pack_blocks16([x + 6144 for x in s2])


def negacyclic(a: list[int], b: list[int]) -> list[int]:
    r = [0] * N
    for i, x in enumerate(a):
        if x:
            for j, y in enumerate(b):
                if i + j < N:
                    r[i + j] += x * y
                else:
                    r[i + j - N] -= x * y
    return r


def quotients(message_hash: int, salt: bytes, s2: list[int], h: list[int]) -> list[int] | None:
    """k with c - s2*h - q*k = s1 (centered); None if some |k_i| >= 2^15 (resample)."""
    c = hash_to_point_words(message_hash, salt)[0][:N]
    conv = negacyclic(s2, [centered(x) for x in h])
    k = []
    for ci, vi in zip(c, conv):
        diff = ci - vi
        r = centered(diff)
        k.append((diff - r) // Q)
    return k if all(-K_OFF <= x < K_OFF for x in k) else None


def ntt_public_key(h: list[int]) -> list[int]:
    """NTT(H) / 128: centered h in base-2^32 blocks of 4, 128-point negacyclic CT transform over the
    Stark field (psi^128 = -1), times 1/128. Bit-exact with `verifier::transformed_public_key`."""
    p, n = STARK_P, 128
    psi = pow(3, (p - 1) // 256, p)
    zetas = [pow(psi, int(format(k, "07b")[::-1], 2), p) for k in range(n)]
    hc = [centered(x) for x in h]
    a = [sum(hc[4 * j + t] << (32 * t) for t in range(4)) % p for j in range(n)]
    k, ln = 0, n // 2
    while ln >= 1:
        for st in range(0, n, 2 * ln):
            k += 1
            z = zetas[k]
            for j in range(st, st + ln):
                t = z * a[j + ln] % p
                a[j + ln] = (a[j] - t) % p
                a[j] = (a[j] + t) % p
        ln //= 2
    ninv = pow(n, -1, p)
    return [x * ninv % p for x in a]


def hash_to_point_words(message_hash: int, salt: bytes) -> tuple[list[int], int]:
    """Accepted SHAKE-256 words (unreduced, < 5q) and the number of Keccak-f permutations."""
    stream = hashlib.shake_256(salt + message_hash.to_bytes(32, "little")).digest(136 * 12)
    out: list[int] = []
    i = 0
    while len(out) < N:
        w = (stream[i] << 8) | stream[i + 1]
        i += 2
        if w < 5 * Q:
            out.append(w)
    return out, (i - 1) // 136 + 1


def _rol(x: int, r: int) -> int:
    return ((x << r) | (x >> (64 - r))) & M64 if r else x


def keccak_f(a: list[int]) -> list[int]:
    """Keccak-f[1600] (FIPS 202) on 25 little-endian 64-bit lanes."""
    a = a[:]
    for rc in RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], ROT[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)])
             for i in range(25)]
        a[0] ^= rc
    return a


def sponge_state(message_hash: int, salt: bytes, perms: int) -> list[int]:
    """SHAKE-256 state of salt || message after `perms` Keccak-f permutations."""
    block = bytearray(salt + message_hash.to_bytes(32, "little") + b"\x1f" + bytes(136 - 73))
    block[135] |= 0x80
    st = [int.from_bytes(block[8 * i:8 * i + 8], "little") for i in range(17)] + [0] * 8
    for _ in range(perms):
        st = keccak_f(st)
    stream = hashlib.shake_256(salt + message_hash.to_bytes(32, "little")).digest(136 * perms)
    assert b"".join(v.to_bytes(8, "little") for v in st[:17]) == stream[-136:]
    return st


def pack_mid_state(lanes: list[int]) -> list[int]:
    """9 felts: lanes 3j, 3j+1, 3j+2 as base-2^64 digits of felt j."""
    return [sum(v << (64 * t) for t, v in enumerate(lanes[3 * j:3 * j + 3]))
            for j in range(MID_STATE_FELTS)]


def falcon_modules(falcon_py: Path):
    sys.path.insert(0, str(falcon_py))
    import falcon as fpy  # type: ignore
    from ntt import div_zq  # type: ignore
    return fpy, div_zq


def load_key(path: Path) -> tuple[Any, list[int]]:
    data = json.loads(path.read_text())
    return pickle.loads(base64.b64decode(data["secret_pickle_b64"])), [int(v) for v in data["h"]]


def sign_raw(fpy, sk, message_hash: int, grind: bool = True) -> tuple[bytes, list[int]]:
    """(salt, s2) with s1 + s2*h = c mod (q, x^512+1) and ||(s1, s2)||^2 <= beta^2."""
    _f, _g, _F, _G, B0_fft, T_fft = sk
    scheme = fpy.Falcon(N)
    assert scheme.param.sig_bound == SIG_BOUND_512
    while True:
        salt = os.urandom(40)
        words, perms = hash_to_point_words(message_hash, salt)
        if perms == MIN_PERMS or not grind:
            break
    point = [w % Q for w in words]
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        if sum(c * c for c in s[0]) + sum(c * c for c in s[1]) <= SIG_BOUND_512:
            return salt, [centered(c) for c in s[1]]


def encode_signature(message_hash: int, salt: bytes, s2: list[int], h: list[int],
                     k: list[int] | None = None) -> list[int]:
    if k is None:
        k = quotients(message_hash, salt, s2, h)
        assert k is not None, "a quotient is out of range; sign again"
    return (pack_s2(s2) + [int.from_bytes(salt[:20], "little"), int.from_bytes(salt[20:], "little")]
            + pack_mid_state(sponge_state(message_hash, salt, 4))
            + pack_blocks16([x + K_OFF for x in k]))


def sign(fpy, sk, h: list[int], message_hash: int) -> list[int]:
    while True:
        salt, s2 = sign_raw(fpy, sk, message_hash)
        k = quotients(message_hash, salt, s2, h)
        if k is not None:
            return encode_signature(message_hash, salt, s2, h, k)


def keygen(fpy, div_zq, path: Path) -> None:
    sk, _vk = fpy.Falcon(N).keygen()
    f, g = sk[0], sk[1]
    h = div_zq(g, f)
    path.write_text(json.dumps({
        "format": "pq-accounts-falcon-python-v1",
        "scheme": "falcon-512",
        "public_key": [hex(x) for x in pack_public_key(h)],
        "h": h,
        "secret_pickle_b64": base64.b64encode(pickle.dumps(sk)).decode("ascii"),
    }, indent=2) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", nargs="?", choices=["keygen"])
    ap.add_argument("--falcon-py", type=Path, required=True)
    ap.add_argument("--key", type=Path, required=True)
    args = ap.parse_args()
    fpy, div_zq = falcon_modules(args.falcon_py)
    if args.command == "keygen":
        keygen(fpy, div_zq, args.key)
        return
    sk, h = load_key(args.key)
    request = json.loads(sys.stdin.read())
    action = request.get("action")
    if action == "public-key":
        print(json.dumps({"publicKey": [hex(x) for x in pack_public_key(h)]}))
    elif action in {"sign-hash", "sign-transaction", "sign-deploy-account"}:
        message_hash = int(str((request.get("payload") or {})["hash"]), 0)
        print(json.dumps({"signature": [hex(x) for x in sign(fpy, sk, h, message_hash)]}))
    else:
        raise ValueError(f"unsupported action: {action}")


if __name__ == "__main__":
    main()
