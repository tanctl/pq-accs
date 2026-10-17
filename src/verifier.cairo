//! Falcon-512 verification over the Stark field.
//!
//! Verifies the standard Falcon-512 relation for a signature (salt, s2) on a message hash:
//! c = HashToPoint(salt || message) (SHAKE-256), s1 = c - s2 * h mod (q, x^512 + 1) centered, and
//! ||s1||^2 + ||s2||^2 <= 34,034,726.
//!
//! - s2 * h is computed exactly, as an integer negacyclic convolution, with a 128-point NTT over
//!   the Stark field (1024 | p - 1) on base-2^32 blocks of four coefficients (Y = x^4,
//!   Y^128 = -1). Exactness: with |h_i| <= 6144 and ||s2||^2 <= beta^2 (checked before the
//!   product), every base-2^32 digit of a block product is a signed sum over distinct index pairs,
//!   so |digit| <= ||h|| * ||s2|| < 2^30 by Cauchy-Schwarz; offset digits are in [0, 2^31) and a
//!   block value is an exact integer < 2^224 < p.
//! - s1 needs no reduction: the signature carries k with s1' = c - s2 * h - q * k. Each block of
//!   s1' + 2^15 is formed in the field and must be a u128 whose base-2^32 digits are all below
//!   2^16 (one bitwise AND); since every such term is below 2^31 in absolute value, this means
//!   each s1'_i lies in [-2^15, 2^15). s1' = s1 (mod q) coefficientwise and the centered s1
//!   minimizes every |s1_i|, so ||s1'||^2 + ||s2||^2 <= beta^2 implies the standard check; the
//!   signer's k (that of the centered s1) makes the two equal.
//! - Squared norms are summed on pairs of digits packed 64 bits apart and split once at the end.
//!
//! The account stores commit(NTT(H)) (computed on-chain from the canonical key, so |h_i| <= 6144
//! holds for the committed transform); the signature carries NTT(H).
//!
//! Signature (225 felts): s2 (43) || salt (2, 20 little-endian bytes each) || S4 (9, the SHAKE-256
//! state after the 4th Keccak-f permutation, see `hash_to_point`) || k (43) || NTT(H) (128).
//! s2 and k use 16-bit slots (s2_i + 6144, k_i + 2^15): felt j holds block 3j in the even 16-bit
//! slots of its low 128 bits, block 3j + 1 in the odd ones and block 3j + 2 in the even slots of
//! its high part (zero elsewhere); the last felt holds blocks 126 and 127 only.

use core::poseidon::hades_permutation;
use corelib_imports::bounded_int::bounded_int::div_rem;
use corelib_imports::bounded_int::{BoundedInt, DivRemHelper, UnitInt, upcast};
use crate::hash_to_point::hash_to_point;
use crate::ntt::{ntt128_fwd, ntt128_inv_mul_off};
use crate::packing::unpack_512_u16;

/// The u128 bitwise libfunc: AND, XOR and OR of one operand pair from a single builtin instance.
extern fn bitwise(lhs: u128, rhs: u128) -> (u128, u128, u128) implicits(core::integer::Bitwise) nopanic;

/// Felts in a signature, and the offsets of its parts.
pub const SIGNATURE_FELTS: u32 = 225;
const SALT_AT: usize = 43;
const MID_AT: usize = 45;
const K_AT: usize = 54;
const NTTH_AT: usize = 97;
const BLOCK_FELTS: u32 = 43;
/// Felts in a canonical public key: 29-slot base-q packing of (h_i + 6144), h_i centered.
pub const PUBLIC_KEY_FELTS: u32 = 29;
/// floor(beta^2) for Falcon-512.
pub const SIG_BOUND_512: u64 = 34034726;
const OFF: felt252 = 6144;
const Q_F: felt252 = 12289;
const B1: felt252 = 0x100000000;
const B2: felt252 = 0x10000000000000000;
const B3: felt252 = 0x1000000000000000000000000;
const K_WRAP: felt252 = 0x800000008000000080000000;
/// 6144 in each base-2^32 digit of a block.
const OFF_BLOCK: felt252 = 0x1800000018000000180000001800;
/// 2^15 in both digits of a pair.
const OFF_PAIR: felt252 = 0x80000000000000008000;
/// Per digit t: 2^15 + q * 2^15 + the NTT digit offset (2^31 for t < 3, which also carries the
/// previous block's top digits, 2^30 for t = 3).
const E_OFFSET: felt252 = 0x58010000980100009801000098010000;
/// 512 * 6144^2.
const S2_SQ_OFFSET: felt252 = 19327352832;
const INV_2_16: felt252 = 0x7fff80000000010ffef00000000000000000000000000000000000000000001;
const INV_2_32: felt252 = 0x7fffffff8000010ffffffef0000000000000000000000000000000000000001;
const INV_2_48: felt252 = 0x7fffffffffff810ffffffffffef000000000000000000000000000000000001;
// 16-bit slot masks over a u128 (slot j = bits 16j..16j+16).
const M_S04: u128 = 0x000000000000ffff000000000000ffff;
const M_S15: u128 = 0x00000000ffff000000000000ffff0000;
const M_S26: u128 = 0x0000ffff000000000000ffff00000000;
const M_EVEN: u128 = 0x0000ffff0000ffff0000ffff0000ffff;
const M_ODD: u128 = 0xffff0000ffff0000ffff0000ffff0000;
/// Base-2^32 digits 0 and 2.
const M_D02: u128 = 0x00000000ffffffff00000000ffffffff;

type U128B = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
type L64 = BoundedInt<0, 0xffffffffffffffff>;
type B64 = UnitInt<0x10000000000000000>;
const B64_NZ: NonZero<B64> = 0x10000000000000000;
impl DivRem64 of DivRemHelper<U128B, B64> {
    type DivT = L64;
    type RemT = L64;
}

/// Low 64 bits of a value below 2^192, plus its bits 128..192.
#[inline(always)]
fn slots_0_2(x: felt252) -> felt252 {
    let v: u256 = x.into();
    let (_, s0) = div_rem(upcast::<u128, U128B>(v.low), B64_NZ);
    upcast::<L64, felt252>(s0) + v.high.into()
}

/// s2 blocks (offset digits) of the low 128 bits of a felt: pairs (a0, a2), (a1, a3), (b0, b2),
/// (b1, b3) at 64-bit spacing; returns (A, B, sum of squared pairs).
#[inline(always)]
fn s2_low(lo: u128) -> (felt252, felt252, felt252) {
    let (p0, _, _) = bitwise(lo, M_S04);
    let (p1, _, _) = bitwise(lo, M_S15);
    let (p2, _, _) = bitwise(lo, M_S26);
    let (p0, p1, p2): (felt252, felt252, felt252) = (p0.into(), p1.into(), p2.into());
    let a = p0 + p2;
    let rest = lo.into() - a;
    let pa1 = p2 * INV_2_32;
    let pb0 = p1 * INV_2_16;
    let pb1 = (rest - p1) * INV_2_48;
    (a, rest * INV_2_16, p0 * p0 + pa1 * pa1 + pb0 * pb0 + pb1 * pb1)
}

/// The 128 centered s2 blocks and ||s2||^2, or `None` if a felt has bits outside its slots.
pub fn decode_s2(packed: Span<felt252>) -> Option<(Array<felt252>, u64)> {
    if packed.len() != BLOCK_FELTS {
        return None;
    }
    let mut out: Array<felt252> = array![];
    let mut sq: felt252 = 0; // sum of squared offset-digit pairs: slots 0 and 2 hold sum d^2
    let mut sum: felt252 = 0; // sum of offset blocks: its base-2^32 digits sum to sum d
    let mut it = packed.slice(0, BLOCK_FELTS - 1);
    while let Some(f) = it.pop_front() {
        let v: u256 = (*f).into();
        let (a, b, sab) = s2_low(v.low);
        let (q0, _, _) = bitwise(v.high, M_S04);
        let (q2, _, _) = bitwise(v.high, M_S26);
        let c: felt252 = v.high.into();
        let (q0, q2): (felt252, felt252) = (q0.into(), q2.into());
        if q0 + q2 != c {
            return None;
        }
        let pc1 = q2 * INV_2_32;
        sq += sab + q0 * q0 + pc1 * pc1;
        sum += a + b + c;
        out.append(a - OFF_BLOCK);
        out.append(b - OFF_BLOCK);
        out.append(c - OFF_BLOCK);
    }
    let v: u256 = (*packed.at(BLOCK_FELTS - 1)).into();
    if v.high != 0 {
        return None;
    }
    let (a, b, sab) = s2_low(v.low);
    sq += sab;
    sum += a + b;
    out.append(a - OFF_BLOCK);
    out.append(b - OFF_BLOCK);
    let sum: u128 = sum.try_into().unwrap(); // < 2^119
    let (_, digit_sum) = DivRem::div_rem(sum, 0xffffffff_u128.try_into().unwrap());
    let n2: felt252 = slots_0_2(sq) - digit_sum.into() * 2 * OFF + S2_SQ_OFFSET;
    Some((out, n2.try_into().unwrap())) // < 512 * 59392^2
}

/// One block of s1' + 2^15: its squared centered pairs are added to `acc`; anything nonzero
/// added to `bad` rejects (e not a u128, or a digit of e at or above 2^16).
#[inline(always)]
fn s1_block(
    v: felt252,
    ref carry: felt252,
    c0: u16,
    c1: u16,
    c2: u16,
    c3: u16,
    k: felt252,
    masks: (u128, u128),
    ref acc: felt252,
    ref bad: felt252,
) {
    let (m_odd, m_d02) = masks;
    let vm: u256 = v.into();
    let x: felt252 = vm.low.into() + carry;
    carry = vm.high.into();
    let e: felt252 = c0.into() + c1.into() * B1 + c2.into() * B2 + c3.into() * B3 + E_OFFSET
        - x
        - Q_F * k;
    let e: u128 = match e.try_into() {
        Some(e) => e,
        None => 0xffffffffffffffffffffffffffffffff,
    };
    let (hi, _, _) = bitwise(e, m_odd);
    bad += hi.into();
    let (p0, _, _) = bitwise(e, m_d02);
    let p0: felt252 = p0.into();
    let q0 = p0 - OFF_PAIR;
    let q1 = (e.into() - p0) * INV_2_32 - OFF_PAIR;
    acc += q0 * q0 + q1 * q1;
}

/// The two k blocks of a felt's low 128 bits (even and odd 16-bit slots).
#[inline(always)]
fn k_low(lo: u128) -> (felt252, felt252) {
    let (ka, _, _) = bitwise(lo, M_EVEN);
    let ka: felt252 = ka.into();
    (ka, (lo.into() - ka) * INV_2_16)
}

/// ||s1'||^2 for s1' = c - s2 * h - q * k, from the offset product blocks `v`, the words `c` and
/// the packed k; `None` if k is malformed or some s1'_i is outside [-2^15, 2^15).
fn s1_norm(v: Span<felt252>, c: Span<u16>, kp: Span<felt252>) -> Option<felt252> {
    if kp.len() != BLOCK_FELTS {
        return None;
    }
    let mut ws = c.slice(0, 512);
    let last: u256 = (*v.at(127)).into();
    let mut carry: felt252 = K_WRAP - last.high.into();
    let mut acc: felt252 = 0;
    let mut bad: felt252 = 0; // sum of a few hundred values below 2^128: zero iff each is zero
    let masks = (M_ODD, M_D02);
    let mut iv = v;
    let mut ik = kp.slice(0, BLOCK_FELTS - 1);
    while let Some(f) = ik.pop_front() {
        let kv: u256 = (*f).into();
        let (ka, kb) = k_low(kv.low);
        let (kc, _, _) = bitwise(kv.high, M_EVEN);
        bad += (kv.high - kc).into();
        let [v0, v1, v2] = (*iv.multi_pop_front::<3>().unwrap()).unbox();
        let [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11] = (*ws
            .multi_pop_front::<12>()
            .unwrap())
            .unbox();
        s1_block(v0, ref carry, c0, c1, c2, c3, ka, masks, ref acc, ref bad);
        s1_block(v1, ref carry, c4, c5, c6, c7, kb, masks, ref acc, ref bad);
        s1_block(v2, ref carry, c8, c9, c10, c11, kc.into(), masks, ref acc, ref bad);
    }
    let kv: u256 = (*kp.at(BLOCK_FELTS - 1)).into();
    let (ka, kb) = k_low(kv.low);
    bad += kv.high.into();
    let [v0, v1] = (*iv.multi_pop_front::<2>().unwrap()).unbox();
    let [c0, c1, c2, c3, c4, c5, c6, c7] = (*ws.multi_pop_front::<8>().unwrap()).unbox();
    s1_block(v0, ref carry, c0, c1, c2, c3, ka, masks, ref acc, ref bad);
    s1_block(v1, ref carry, c4, c5, c6, c7, kb, masks, ref acc, ref bad);
    if bad != 0 {
        return None;
    }
    // acc = sum s_a^2 + (sum 2 s_a s_b) * 2^64 + (sum s_b^2) * 2^128 with |s| <= 2^15 over 256
    // pairs; shifting the signed middle term by 2^63 makes every 64-bit slot exact.
    Some(slots_0_2(acc + 0x80000000000000000000000000000000))
}

#[inline(always)]
fn cent(d: u16) -> felt252 {
    d.into() - OFF
}

/// Base-2^32 blocks of the centered coefficients (4 per block), from 512 canonical digits.
fn blocks(d: Span<u16>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut it = d;
    while let Some(x) = it.multi_pop_front::<4>() {
        let [a0, a1, a2, a3] = (*x).unbox();
        out.append(cent(a0) + cent(a1) * B1 + cent(a2) * B2 + cent(a3) * B3);
    }
    out
}

/// NTT(H): the 128 transformed key blocks for a canonical 29-felt public key (h + 6144, base q).
pub fn transformed_public_key(pk: Span<felt252>) -> Option<Array<felt252>> {
    let h = unpack_512_u16(pk)?;
    Some(ntt128_fwd(blocks(h.span()).span()))
}

/// Poseidon sponge over exactly 128 felts (rate 2, capacity 1), unrolled: domain tag and length
/// in the capacity, 64 hades permutations. Same security as `poseidon_hash_span` for a fixed
/// length, without its per-pair loop overhead.
pub fn commit128(x: Span<felt252>) -> felt252 {
    assert(x.len() == 128, 'commit: length');
    let mut it = x;
    let (mut s0, mut s1, mut s2) = (0, 0, 'FALCON_NTTH_V1' + 128);
    while let Some(c) = it.multi_pop_front::<16>() {
        let [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15] = (*c).unbox();
        let (t0, t1, t2) = hades_permutation(s0 + a0, s1 + a1, s2);
        let (t0, t1, t2) = hades_permutation(t0 + a2, t1 + a3, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a4, t1 + a5, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a6, t1 + a7, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a8, t1 + a9, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a10, t1 + a11, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a12, t1 + a13, t2);
        let (t0, t1, t2) = hades_permutation(t0 + a14, t1 + a15, t2);
        s0 = t0;
        s1 = t1;
        s2 = t2;
    }
    let (r, _, _) = hades_permutation(s0 + 1, s1, s2);
    r
}

/// Commitment stored by the account: commit(NTT(H)) for a canonical 29-felt public key.
pub fn public_key_commitment(public_key: Span<felt252>) -> Option<felt252> {
    if public_key.len() != PUBLIC_KEY_FELTS {
        return None;
    }
    Some(commit128(transformed_public_key(public_key)?.span()))
}

/// Verifies `signature` (225 felts) on `message_hash` against `commitment`.
pub fn verify(message_hash: felt252, commitment: felt252, signature: Span<felt252>) -> bool {
    if signature.len() != SIGNATURE_FELTS {
        return false;
    }
    let mid_state = signature.slice(MID_AT, 9);
    let salt_a = *signature.at(SALT_AT);
    let salt_b = *signature.at(SALT_AT + 1);
    let c = match hash_to_point(message_hash, salt_a, salt_b, mid_state) {
        Some(v) => v,
        None => { return false; },
    };
    let ntt_h = signature.slice(NTTH_AT, 128);
    if commit128(ntt_h) != commitment {
        return false;
    }
    let (sb, n2) = match decode_s2(signature.slice(0, BLOCK_FELTS)) {
        Some(v) => v,
        None => { return false; },
    };
    if n2 > SIG_BOUND_512 {
        return false;
    }
    let v = ntt128_inv_mul_off(ntt_h, ntt128_fwd(sb.span()).span());
    let n1 = match s1_norm(v.span(), c.span(), signature.slice(K_AT, BLOCK_FELTS)) {
        Some(n) => n,
        None => { return false; },
    };
    let total: u64 = match (n1 + n2.into()).try_into() {
        Some(t) => t,
        None => { return false; },
    };
    total <= SIG_BOUND_512
}
