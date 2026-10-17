"""Generates src/ntt.cairo. Norm-bounded 4-coefficient packing: Falcon's negacyclic product over Z[X]/(X^512+1) as a
128-point negacyclic NTT over the Stark field in Y = X^4 (Y^128 = -1), each field element
holding 4 base-2^32 digits. Checks the full algorithm in Python, emits straight-line Cairo."""
import random, sys, math
p = 2**251 + 17 * 2**192 + 1
N, n, K, B = 512, 128, 4, 2**32
psi = pow(3, (p - 1) // (2 * n), p)
assert pow(psi, n, p) == p - 1
def brv(x, bits=7): return int(format(x, f'0{bits}b')[::-1], 2)
zetas = [pow(psi, brv(k), p) for k in range(n)]
def fwd(a):
    a = a[:]; k = 0; ln = n // 2; ops = []
    while ln >= 1:
        for st in range(0, n, 2 * ln):
            k += 1; z = zetas[k]
            for j in range(st, st + ln):
                t = z * a[j + ln] % p; a[j + ln] = (a[j] - t) % p; a[j] = (a[j] + t) % p
                ops.append((j, j + ln, z))
        ln //= 2
    return a, ops
def inv(a):
    a = a[:]; ln = 1; ops = []
    while ln < n:
        for st in range(0, n, 2 * ln):
            z = pow(zetas[n // (2 * ln) + st // (2 * ln)], -1, p)
            for j in range(st, st + ln):
                t = a[j]; a[j] = (t + a[j + ln]) % p; a[j + ln] = (t - a[j + ln]) * z % p
                ops.append((j, j + ln, z))
        ln *= 2
    ninv = pow(n, -1, p)
    return [x * ninv % p for x in a], ops, ninv
DOFF = 2**30  # digit offset; |digit| <= ||h||*||s2|| < 2^30 (centered h, ||s2||^2 <= beta^2)
OFFV = sum(DOFF * B**e for e in range(7))
def packed_product(h, s):
    H = [sum(h[K*j+t] * B**t for t in range(K)) % p for j in range(n)]
    S = [sum(s[K*j+t] * B**t for t in range(K)) % p for j in range(n)]
    Hh, fops = fwd(H); Ss, _ = fwd(S)
    V, iops, ninv = inv([x * y % p for x, y in zip(Hh, Ss)])
    d = []
    for m in range(n):
        v = (V[m] + OFFV) % p
        assert v < 2**224
        d.append([((v >> (32 * e)) & (B - 1)) - DOFF for e in range(7)])
    r = [0] * N
    for m in range(n):
        for e in range(7):
            idx = K * m + e
            if idx < N: r[idx] += d[m][e]
            else: r[idx - N] -= d[m][e]
    return r, fops, iops, ninv
def negacyclic(a, b):
    r = [0] * N
    for i in range(N):
        if a[i] == 0: continue
        for j in range(N):
            if i + j < N: r[i + j] += a[i] * b[j]
            else: r[i + j - N] -= a[i] * b[j]
    return r
beta2 = 34034726
random.seed(7)
cases = []
for trial in range(6):
    h = [random.randint(-6144, 6144) for _ in range(N)]
    s = [int(random.gauss(0, 165)) for _ in range(N)]
    cases.append((h, s))
# extremes: |h|=6144 everywhere, s2 at the norm bound concentrated / spread
cases.append(([6144] * N, [5833] + [0] * (N - 1)))
cases.append(([(-1) ** i * 6144 for i in range(N)], [257 * (-1) ** (i // 3) for i in range(N)]))
cases.append(([6144] * N, [257] * N))
for h, s in cases:
    assert sum(x * x for x in s) <= beta2, sum(x*x for x in s)
    r, fops, iops, ninv = packed_product(h, s)
    assert r == negacyclic(h, s)
print(f"python packed product ok on {len(cases)} cases; butterflies {len(fops)}+{len(fops)}+{len(iops)}", file=sys.stderr)

def emit(name, ops, kind, scale=None):
    if kind == "ct":
        L = [f"pub fn {name}(x: Span<felt252>) -> Array<felt252> {{", "    let mut ix = x;"]
        for blk in range(0, n, 16):
            L.append("    let [" + ", ".join(f"a{blk+i}" for i in range(16)) + "] = (*ix.multi_pop_front::<16>().unwrap()).unbox();")
    else:
        L = [f"pub fn {name}(x: Span<felt252>, y: Span<felt252>) -> Array<felt252> {{", "    let mut ix = x;", "    let mut iy = y;"]
        for blk in range(0, n, 16):
            L.append("    let [" + ", ".join(f"x{blk+i}" for i in range(16)) + "] = (*ix.multi_pop_front::<16>().unwrap()).unbox();")
            L.append("    let [" + ", ".join(f"y{blk+i}" for i in range(16)) + "] = (*iy.multi_pop_front::<16>().unwrap()).unbox();")
            for i in range(16): L.append(f"    let a{blk+i} = x{blk+i} * y{blk+i};")
    for (j, k, z) in ops:
        if kind == "ct": L.append(f"    let t = {hex(z)} * a{k}; let a{k} = a{j} - t; let a{j} = a{j} + t;")
        else: L.append(f"    let t = a{j}; let a{j} = t + a{k}; let a{k} = (t - a{k}) * {hex(z)};")
    sc = f" * {hex(scale)}" if scale else ""
    off = f" + {hex(OFFV)}" if kind != "ct" else ""
    L.append("    array![" + ", ".join(f"a{i}{sc}{off}" for i in range(n)) + "]")
    L.append("}")
    return "\n".join(L)
def emit_core(fops, iops):
    """Verification core in one straight-line function: decode s2 (43 felts) into centered blocks
    a0..a127 with ||s2||^2, forward NTT, pointwise product with NTT(H)/128, inverse NTT plus OFFV,
    then s1' from the product blocks, the words and k (43 felts). No intermediate arrays."""
    L = ["/// ||s1'||^2 + ||s2||^2 for the packed s2 and k, the key's NTT(H) / 128 and the first 512",
         "/// accepted words; `None` on a malformed encoding, ||s2||^2 > beta^2 (needed for exactness),",
         "/// or some s1'_i outside [-2^15, 2^15) (see `verifier`).",
         "pub fn falcon_core(",
         "    s2p: Span<felt252>, ntt_h: Span<felt252>, words: Span<u16>, kp: Span<felt252>,",
         ") -> Option<u64> {",
         "    let m = (M_S04, M_S15, M_S26);",
         "    let (mut sq, mut sum, mut bad) = (0, 0, 0);",
         "    let [" + ", ".join(f"f{i}" for i in range(43)) + "] = (*s2p.try_into()?).unbox();"]
    for j in range(42):
        L.append(f"    let (a{3*j}, a{3*j+1}, a{3*j+2}) = s2_felt(f{j}, m, ref sq, ref sum, ref bad);")
    L.append("    let (a126, a127) = s2_last(f42, m, ref sq, ref sum, ref bad);")
    L.append("    if bad != 0 {\n        return None;\n    }")
    L.append("    let n2 = s2_norm(sq, sum);")
    L.append("    if n2 > SIG_BOUND_512 {\n        return None;\n    }")
    for (j, k, z) in fops:
        L.append(f"    let t = {hex(z)} * a{k}; let a{k} = a{j} - t; let a{j} = a{j} + t;")
    L.append("    let mut iy = ntt_h;")
    for blk in range(0, n, 16):
        L.append("    let [" + ", ".join(f"y{blk+i}" for i in range(16)) + "] = (*iy.multi_pop_front::<16>()?).unbox();")
        for i in range(16): L.append(f"    let a{blk+i} = a{blk+i} * y{blk+i};")
    for (j, k, z) in iops:
        L.append(f"    let t = a{j}; let a{j} = t + a{k}; let a{k} = (t - a{k}) * {hex(z)};")
    L.append(f"    let off = {hex(OFFV)};")
    L.append("    let [" + ", ".join(f"g{i}" for i in range(43)) + "] = (*kp.try_into()?).unbox();")
    L.append("    let mut ws = words;")
    L.append("    let mut carry = wrap_carry(a127 + off);")
    L.append("    let (mut acc, mut bad) = (0, 0);")
    L.append("    let (m_even, masks) = (M_EVEN, (M_ODD, M_D02));")
    for j in range(42):
        L.append(f"    s1_felt(g{j}, a{3*j} + off, a{3*j+1} + off, a{3*j+2} + off, ref ws, ref carry, m_even, masks, ref acc, ref bad)?;")
    L.append("    s1_last(g42, a126 + off, a127 + off, ref ws, ref carry, m_even, masks, ref acc, ref bad)?;")
    L.append("    if bad != 0 {\n        return None;\n    }")
    L.append("    let total: felt252 = s1_total(acc) + n2.into();")
    L.append("    total.try_into()")
    L.append("}")
    return "\n".join(L)
_, fops, iops, ninv = packed_product(*cases[0])
out = ["\n".join([
       "//! GENERATED by scripts/gen_ntt.py: 128-point negacyclic NTT over the Stark field (psi^128 = -1)",
       "//! for 4-coefficient base-2^32 blocks, and the verification core around it (`falcon_core`): the",
       "//! inverse adds the digit offset OFFV = sum_e 2^30 * 2^(32e), e < 7, and leaves the 1/128 scale",
       "//! to the stored transform of the public key (`NTT_SCALE`)."]),
       f"pub const NTT_SCALE: felt252 = {hex(ninv)};",
       "use crate::verifier::{\n    M_D02, M_EVEN, M_ODD, M_S04, M_S15, M_S26, SIG_BOUND_512, s1_felt, s1_last,\n    s1_total, s2_felt, s2_last, s2_norm, wrap_carry,\n};",
       emit("ntt128_fwd", fops, "ct"), emit_core(fops, iops)]
open(sys.argv[1], "w").write("\n\n".join(out) + "\n")
