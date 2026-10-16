#!/usr/bin/env python3
"""Falcon-512 signer for the Starknet Falcon512Account.

Signature (34 felts): s2 (32) || salt (2), where (salt, s2) is a standard Falcon-512 signature
over the 32-byte little-endian transaction hash (SHAKE-256 hash-to-point of salt || message),
with a uniformly random 40-byte salt as in the specification.

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


def pack_s2(s2: list[int]) -> list[int]:
    """32 felts: base-q digits (s2_i + 6144), 8 per u128 half, low half first."""
    d = [x + 6144 for x in s2]
    assert all(0 <= v < Q for v in d)
    out = []
    for j in range(0, N, 16):
        lo = sum(v * Q**t for t, v in enumerate(d[j:j + 8]))
        hi = sum(v * Q**t for t, v in enumerate(d[j + 8:j + 16]))
        out.append(lo + (hi << 128))
    return out


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


def falcon_modules(falcon_py: Path):
    sys.path.insert(0, str(falcon_py))
    import falcon as fpy  # type: ignore
    from ntt import div_zq  # type: ignore
    return fpy, div_zq


def load_key(path: Path) -> tuple[Any, list[int]]:
    data = json.loads(path.read_text())
    return pickle.loads(base64.b64decode(data["secret_pickle_b64"])), [int(v) for v in data["h"]]


def sign_raw(fpy, sk, message_hash: int) -> tuple[bytes, list[int]]:
    """(salt, s2) with s1 + s2*h = c mod (q, x^512+1) and ||(s1, s2)||^2 <= beta^2."""
    _f, _g, _F, _G, B0_fft, T_fft = sk
    scheme = fpy.Falcon(N)
    assert scheme.param.sig_bound == SIG_BOUND_512
    salt = os.urandom(40)
    words, _perms = hash_to_point_words(message_hash, salt)
    point = [w % Q for w in words]
    while True:
        s = scheme.__sample_preimage__(B0_fft, T_fft, point)
        if sum(c * c for c in s[0]) + sum(c * c for c in s[1]) <= SIG_BOUND_512:
            return salt, [centered(c) for c in s[1]]


def encode_signature(salt: bytes, s2: list[int]) -> list[int]:
    return pack_s2(s2) + [int.from_bytes(salt[:20], "little"), int.from_bytes(salt[20:], "little")]


def sign(fpy, sk, message_hash: int) -> list[int]:
    salt, s2 = sign_raw(fpy, sk, message_hash)
    return encode_signature(salt, s2)


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
        print(json.dumps({"signature": [hex(x) for x in sign(fpy, sk, message_hash)]}))
    else:
        raise ValueError(f"unsupported action: {action}")


if __name__ == "__main__":
    main()
