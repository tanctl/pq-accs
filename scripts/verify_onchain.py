#!/usr/bin/env python3
"""Independently verify a Falcon512Account transaction with the falcon.py reference verifier.

Uses only chain data and falcon.py (https://github.com/tprest/falcon.py): it reads the
transaction's signature and hash, takes the public key from the account's deploy transaction
(constructor calldata), checks that the NTT(H) carried in the signature is the transform of that
key, decodes (salt, s2) into falcon.py's standard compressed signature, and calls
`Falcon(512).verify` on the 32-byte little-endian transaction hash.

    verify_onchain.py --falcon-py PATH --rpc URL --tx TX_HASH --deploy-tx DEPLOY_TX_HASH
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

Q = 12289
N = 512
P = 2**251 + 17 * 2**192 + 1


def rpc(url: str, method: str, params):
    req = urllib.request.Request(url, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
                                 headers={"content-type": "application/json"})
    out = json.load(urllib.request.urlopen(req, timeout=60))
    if "result" not in out:
        raise RuntimeError(out)
    return out["result"]


def base_q_digits(felts: list[int], per_half: int) -> list[int]:
    out = []
    for f in felts:
        for half in (f & ((1 << 128) - 1), f >> 128):
            for _ in range(per_half):
                out.append(half % Q)
                half //= Q
    return out[:N]


RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
      0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
      0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56],
       [27, 20, 39, 8, 14]]
M64 = (1 << 64) - 1


def keccak_f(a: list[int]) -> list[int]:
    rol = lambda x, r: ((x << r) | (x >> (64 - r))) & M64 if r else x  # noqa: E731
    for rc in RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], ROT[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def shake_state_after(data: bytes, perms: int) -> list[int]:
    block = bytearray(data + b"\x1f" + bytes(136 - len(data) - 1))
    block[135] |= 0x80
    st = [int.from_bytes(block[8 * i:8 * i + 8], "little") for i in range(17)] + [0] * 8
    for _ in range(perms):
        st = keccak_f(st)
    rate = b"".join(v.to_bytes(8, "little") for v in st[:17])
    assert rate == hashlib.shake_256(data).digest(136 * perms)[-136:], "Keccak-f mismatch"
    return st


def unpack_blocks16(felts: list[int]) -> list[int]:
    """512 digits from the 43-felt 16-bit slot encoding (see signer.pack_blocks16)."""
    blocks = []
    for j, f in enumerate(felts):
        lo, hi = f & ((1 << 128) - 1), f >> 128
        blocks += [lo, lo >> 16] + ([hi] if j < 42 else [])
    return [(b >> (32 * t)) & 0xffff for b in blocks for t in range(4)]


def ntt128(h: list[int]) -> list[int]:
    """128-point negacyclic transform over the Stark field of centered base-2^32 key blocks."""
    psi = pow(3, (P - 1) // 256, P)
    zetas = [pow(psi, int(format(k, "07b")[::-1], 2), P) for k in range(128)]
    a = [sum(h[4 * j + t] << (32 * t) for t in range(4)) % P for j in range(128)]
    k, ln = 0, 64
    while ln >= 1:
        for st in range(0, 128, 2 * ln):
            k += 1
            for j in range(st, st + ln):
                t = zetas[k] * a[j + ln] % P
                a[j + ln], a[j] = (a[j] - t) % P, (a[j] + t) % P
        ln //= 2
    return a


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--falcon-py", type=Path, required=True)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--tx", required=True)
    ap.add_argument("--deploy-tx", required=True)
    args = ap.parse_args()
    sys.path.insert(0, str(args.falcon_py))
    import falcon  # type: ignore
    from encoding import compress  # type: ignore

    tx = rpc(args.rpc, "starknet_getTransactionByHash", {"transaction_hash": args.tx})
    sig = [int(x, 16) for x in tx["signature"]]
    assert len(sig) in (97, 162, 171), f"expected a 97-, 162- or 171-felt signature, got {len(sig)}"
    dep = rpc(args.rpc, "starknet_getTransactionByHash", {"transaction_hash": args.deploy_tx})
    assert dep["type"] == "DEPLOY_ACCOUNT" and int(dep["contract_address_salt"], 16) >= 0
    pk = [int(x, 16) for x in dep["constructor_calldata"]]
    assert pk[0] == 29, "constructor calldata must be the 29-felt public key array"
    h = [d - 6144 for d in base_q_digits(pk[1:], 9)]

    msg = int(args.tx, 16).to_bytes(32, "little")
    print("account:", tx["sender_address"])
    ntt_ok = True
    if len(sig) == 97:
        s2 = [d - 6144 for d in unpack_blocks16(sig[:43])]
        salt = sig[43].to_bytes(20, "little") + sig[44].to_bytes(20, "little")
        mid = sig[45:54]
    else:
        s2 = [d - 6144 for d in base_q_digits(sig[:32], 8)]
        salt = sig[32].to_bytes(20, "little") + sig[33].to_bytes(20, "little")
        mid = sig[162:] if len(sig) == 171 else None
        ntt_ok = sig[34:162] == ntt128(h)
        print("carried NTT(H) equals the transform of the deployed key:", ntt_ok)
    mid_ok = True
    if mid is not None:
        s4 = shake_state_after(salt + msg, 4)
        mid_ok = mid == [sum(v << (64 * t) for t, v in enumerate(s4[3 * j:3 * j + 3])) for j in range(9)]
        print("carried S4 equals the SHAKE-256 state after 4 permutations:", mid_ok)

    scheme = falcon.Falcon(N)
    enc = compress(s2, scheme.param.sig_bytelen - 41)
    vk = falcon.serialize_poly([x % Q for x in h])
    ok = enc is not False and scheme.verify(vk, msg, bytes([0x30 + 9]) + salt + enc)
    print("falcon.py Falcon-512 verify(tx hash, salt, s2):", ok)
    sys.exit(0 if ok and ntt_ok and mid_ok else 1)


if __name__ == "__main__":
    main()
