//! Falcon-512 verification over the Stark field.
//!
//! Verifies the standard Falcon-512 relation for a signature (salt, s2) on a message hash:
//! c = HashToPoint(salt || message) (SHAKE-256), s1 = c - s2 * h mod (q, x^512 + 1), and
//! ||s1||^2 + ||s2||^2 <= 34,034,726, with s1, s2 taken as centered integers in [-6144, 6144].
//!
//! The ring product s2 * h is computed exactly, as an integer negacyclic convolution, with a
//! 128-point NTT over the Stark field (1024 | p - 1) on base-2^32 blocks of four coefficients
//! (Y = x^4, Y^128 = -1). Exactness: with |h_i| <= 6144 and ||s2||^2 <= beta^2 (checked before the
//! product), every base-2^32 digit of every block product is a signed sum over distinct index
//! pairs, so |digit| <= ||h|| * ||s2|| < 2^30 by Cauchy-Schwarz. Offset digits are in [0, 2^31)
//! and a block value is an exact integer < 2^224 < p. s1 is then recovered with one reduction
//! modulo q per coefficient.
//!
//! The account stores commit(NTT(H)) (computed on-chain from the canonical key, so |h_i| <= 6144
//! holds for the committed transform); the signature carries NTT(H).
//!
//! Signature (171 felts): s2 (32) || salt (2, 20 little-endian bytes each) || NTT(H) (128) ||
//! S4 (9), the SHAKE-256 state after the 4th Keccak-f permutation (see `hash_to_point`).
//! s2 encoding: 8 base-q digits (s2_i + 6144) per u128 half, low half first, two halves per felt;
//! every digit and every top digit is checked < q, so encodings are canonical.

use core::poseidon::hades_permutation;
use corelib_imports::bounded_int::bounded_int::{ConstrainHelper, SubHelper, add, constrain, div_rem, sub};
use corelib_imports::bounded_int::{AddHelper, BoundedInt, DivRemHelper, UnitInt, upcast};
use crate::hash_to_point::hash_to_point;
use crate::ntt::{ntt128_fwd, ntt128_inv_mul_off};
use crate::packing::unpack_512_u16;

/// Felts in a signature.
pub const SIGNATURE_FELTS: u32 = 171;
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

type U128B = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
type L96 = BoundedInt<0, 0xffffffffffffffffffffffff>;
type L64 = BoundedInt<0, 0xffffffffffffffff>;
type D32 = BoundedInt<0, 0xffffffff>;
type W16 = BoundedInt<0, 0xffff>;
type B32 = UnitInt<0x100000000>;
const B32_NZ: NonZero<B32> = 0x100000000;
impl DR128 of DivRemHelper<U128B, B32> {
    type DivT = L96;
    type RemT = D32;
}
impl DR96 of DivRemHelper<L96, B32> {
    type DivT = L64;
    type RemT = D32;
}
impl DR64 of DivRemHelper<L64, B32> {
    type DivT = D32;
    type RemT = D32;
}

type QT = UnitInt<12289>;
const Q_NZ: NonZero<QT> = 12289;
type Rem = BoundedInt<0, 12288>;
type TCT = UnitInt<4294967964>;
const TC: TCT = 4294967964;
impl AddC of AddHelper<W16, TCT> {
    type Result = BoundedInt<4294967964, 4295033499>;
}
impl SubC of SubHelper<BoundedInt<4294967964, 4295033499>, D32> {
    type Result = BoundedInt<669, 4295033499>;
}
impl DivC of DivRemHelper<BoundedInt<669, 4295033499>, QT> {
    type DivT = BoundedInt<0, 349502>;
    type RemT = Rem;
}
#[inline(always)]
fn s1_sq_c(c: u16, d: D32) -> felt252 {
    let (_, rem) = div_rem(sub(add(upcast::<u16, W16>(c), TC), d), Q_NZ);
    let s1: felt252 = upcast::<Rem, felt252>(rem) - OFF;
    s1 * s1
}

type TDT = UnitInt<4294977515>;
const TD: TDT = 4294977515;
impl AddD of AddHelper<W16, TDT> {
    type Result = BoundedInt<4294977515, 4295043050>;
}
impl SubD of SubHelper<BoundedInt<4294977515, 4295043050>, D32> {
    type Result = BoundedInt<10220, 4295043050>;
}
impl DivD of DivRemHelper<BoundedInt<10220, 4295043050>, QT> {
    type DivT = BoundedInt<0, 349503>;
    type RemT = Rem;
}
#[inline(always)]
fn s1_sq_d(c: u16, d: D32) -> felt252 {
    let (_, rem) = div_rem(sub(add(upcast::<u16, W16>(c), TD), d), Q_NZ);
    let s1: felt252 = upcast::<Rem, felt252>(rem) - OFF;
    s1 * s1
}


// s2 encoding: 8 base-q digits (s2_i + 6144) per u128 half, low half first, 2 halves per
// felt, 32 felts. Each half decodes straight into two base-2^32 blocks plus its squared norm.
type X0 = BoundedInt<0, 340282366920938463463374607431768211455>;
type X1 = BoundedInt<0, 27689996494502275487295516920153650>;
type X2 = BoundedInt<0, 2253234314793903123711898195146>;
type X3 = BoundedInt<0, 183353756594833031468133956>;
type X4 = BoundedInt<0, 14920152705251284194656>;
type X5 = BoundedInt<0, 1214106331292317047>;
type X6 = BoundedInt<0, 98796186125178>;
type X7 = BoundedInt<0, 8039399961>;
impl DQ0 of DivRemHelper<X0, QT> {
    type DivT = X1;
    type RemT = Rem;
}
impl DQ1 of DivRemHelper<X1, QT> {
    type DivT = X2;
    type RemT = Rem;
}
impl DQ2 of DivRemHelper<X2, QT> {
    type DivT = X3;
    type RemT = Rem;
}
impl DQ3 of DivRemHelper<X3, QT> {
    type DivT = X4;
    type RemT = Rem;
}
impl DQ4 of DivRemHelper<X4, QT> {
    type DivT = X5;
    type RemT = Rem;
}
impl DQ5 of DivRemHelper<X5, QT> {
    type DivT = X6;
    type RemT = Rem;
}
impl DQ6 of DivRemHelper<X6, QT> {
    type DivT = X7;
    type RemT = Rem;
}
impl Top of ConstrainHelper<X7, 12289> {
    type LowT = Rem;
    type HighT = BoundedInt<12289, 8039399961>;
}

#[inline(always)]
fn dv(d: Rem) -> felt252 {
    upcast::<Rem, felt252>(d) - OFF
}

/// Two blocks and the squared norm of 8 coefficients; `None` if the half is non-canonical.
#[inline(always)]
fn half8(x: u128, ref norm: felt252, ref out: Array<felt252>) -> bool {
    let x0: X0 = upcast(x);
    let (x1, d0) = div_rem(x0, Q_NZ);
    let (x2, d1) = div_rem(x1, Q_NZ);
    let (x3, d2) = div_rem(x2, Q_NZ);
    let (x4, d3) = div_rem(x3, Q_NZ);
    let (x5, d4) = div_rem(x4, Q_NZ);
    let (x6, d5) = div_rem(x5, Q_NZ);
    let (x7, d6) = div_rem(x6, Q_NZ);
    let d7 = match constrain::<X7, 12289>(x7) {
        Ok(v) => v,
        Err(_) => { return false; },
    };
    let (v0, v1, v2, v3) = (dv(d0), dv(d1), dv(d2), dv(d3));
    let (v4, v5, v6, v7) = (dv(d4), dv(d5), dv(d6), dv(d7));
    norm += v0 * v0 + v1 * v1 + v2 * v2 + v3 * v3 + v4 * v4 + v5 * v5 + v6 * v6 + v7 * v7;
    out.append(v0 + v1 * B1 + v2 * B2 + v3 * B3);
    out.append(v4 + v5 * B1 + v6 * B2 + v7 * B3);
    true
}

/// 128 centered s2 blocks from the 32-felt s2 encoding, accumulating ||s2||^2 into `norm`.
pub fn decode_s2_blocks(packed: Span<felt252>, ref norm: felt252) -> Option<Array<felt252>> {
    if packed.len() != 32 {
        return None;
    }
    let mut out: Array<felt252> = array![];
    let mut it = packed;
    while let Some(f) = it.pop_front() {
        let v: u256 = (*f).into();
        if !half8(v.low, ref norm, ref out) || !half8(v.high, ref norm, ref out) {
            return None;
        }
    }
    Some(out)
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

/// Verifies `signature` (171 felts) on `message_hash` against `commitment`.
pub fn verify(message_hash: felt252, commitment: felt252, signature: Span<felt252>) -> bool {
    if signature.len() != SIGNATURE_FELTS {
        return false;
    }
    let mid_state = signature.slice(162, 9);
    let point = match hash_to_point(message_hash, *signature.at(32), *signature.at(33), mid_state) {
        Some(v) => v,
        None => { return false; },
    };
    verify_core(point.span(), commitment, signature.slice(34, 128), signature.slice(0, 32))
}

fn verify_core(
    c: Span<u16>, commit: felt252, ntt_h: Span<felt252>, s2_packed: Span<felt252>,
) -> bool {
    if ntt_h.len() != 128 || commit128(ntt_h) != commit {
        return false;
    }
    let mut norm: felt252 = 0;
    let sb = match decode_s2_blocks(s2_packed, ref norm) {
        Some(v) => v,
        None => { return false; },
    };
    let n2: u64 = norm.try_into().unwrap(); // < 512 * 6144^2
    if n2 > SIG_BOUND_512 {
        return false;
    }
    let v = ntt128_inv_mul_off(ntt_h, ntt128_fwd(sb.span()).span());
    let last: u256 = (*v.at(127)).into();
    let mut carry: felt252 = K_WRAP - last.high.into();
    let mut it_v = v.span();
    let mut it_c = c.slice(0, 512);
    while let Some(vm) = it_v.pop_front() {
        let vm: u256 = (*vm).into();
        let x: u128 = (vm.low.into() + carry).try_into().unwrap();
        let x: U128B = upcast(x);
        carry = vm.high.into();
        let (q1, d0) = div_rem(x, B32_NZ);
        let (q2, d1) = div_rem(q1, B32_NZ);
        let (d3, d2) = div_rem(q2, B32_NZ);
        let [c0, c1, c2, c3] = (*it_c.multi_pop_front::<4>().unwrap()).unbox();
        norm += s1_sq_c(c0, d0) + s1_sq_c(c1, d1) + s1_sq_c(c2, d2) + s1_sq_d(c3, d3);
    }
    let norm: u64 = match norm.try_into() {
        Some(v) => v,
        None => { return false; },
    };
    norm <= SIG_BOUND_512
}
