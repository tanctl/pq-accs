// Portions derived from OpenZeppelin cairo-pq-verifiers (MIT License, Copyright (c) 2026 OpenZeppelin).
//! Falcon-512 hash-to-point with standard SHAKE-256: absorb `salt (40 bytes) || message hash (32
//! bytes, little-endian)`, read the stream as big-endian 16-bit words, accept `word < 5q`.
//!
//! - Accepted words are returned unreduced (< 5q); the verifier only uses them modulo q.
//! - The words of a lane are byte-swapped at once: with E = lane & 0x00ff..00ff, they are the
//!   base-2^16 digits of (65535 * E + lane) / 256 (for a packed lane, both halves together).
//! - Squeeze blocks 0..6 hold 7 * 68 = 476 < 512 words, so they are consumed with no stopping
//!   checks. Returns at least 512 words (the last lane may add up to 3); use the first 512.
//! - The 8-permutation chain A -> S1 -> ... -> S8 runs as two chains of four, side by side in the
//!   packed permutation: (A, S4) -> (S1, S5) -> (S2, S6) -> (S3, S7) -> (S4', S8). S4 is supplied
//!   by the signer and accepted only if it equals the recomputed S4', so every state is exact.

use corelib_imports::bounded_int::bounded_int::{ConstrainHelper, add, constrain, div_rem, mul};
use corelib_imports::bounded_int::{AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, downcast, upcast};
use crate::keccak::keccak_f1600_x2;

const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000;
const INV256: felt252 = 0x7f8000000000010ef0000000000000000000000000000000000000000000001;

/// Felts carrying S4: 25 lanes, three base-2^64 digits per felt.
pub const MID_STATE_FELTS: u32 = 9;

type U128B = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
type L64 = BoundedInt<0, 0xffffffffffffffff>;
type B64 = UnitInt<0x10000000000000000>;
const B64_NZ: NonZero<B64> = 0x10000000000000000;
const B64_ONE: B64 = 0x10000000000000000;
impl DivRemHalves of DivRemHelper<U128B, B64> {
    type DivT = L64;
    type RemT = L64;
}
type HiT = BoundedInt<0, 0xffffffffffffffff0000000000000000>;
impl MulHi of MulHelper<L64, B64> {
    type Result = HiT;
}
impl AddPack of AddHelper<L64, HiT> {
    type Result = U128B;
}
type B32 = UnitInt<0x100000000>;
const B32_NZ: NonZero<B32> = 0x100000000;
type L96 = BoundedInt<0, 0xffffffffffffffffffffffff>;
type L48 = BoundedInt<0, 0xffffffffffff>;
type L32 = BoundedInt<0, 0xffffffff>;
type W16 = BoundedInt<0, 0xffff>;
impl DivRemSalt of DivRemHelper<U128B, B32> {
    type DivT = L96;
    type RemT = L32;
}
impl DivRemSalt96 of DivRemHelper<L96, B64> {
    type DivT = L32;
    type RemT = L64;
}
const PAD_START: L64 = 0x1f;
const PAD_END: L64 = 0x8000000000000000;
type B16 = UnitInt<0x10000>;
const B16_NZ: NonZero<B16> = 0x10000;
impl DivRem64 of DivRemHelper<L64, B16> {
    type DivT = L48;
    type RemT = W16;
}
impl DivRem48 of DivRemHelper<L48, B16> {
    type DivT = L32;
    type RemT = W16;
}
impl DivRem32 of DivRemHelper<L32, B16> {
    type DivT = W16;
    type RemT = W16;
}

/// Rejection bound 5Q = 61445.
impl Accept of ConstrainHelper<W16, 61445> {
    type LowT = BoundedInt<0, 61444>;
    type HighT = BoundedInt<61445, 0xffff>;
}

#[inline(always)]
fn accept(word: W16, ref words: Array<u16>) {
    if let Ok(w) = constrain::<W16, 61445>(word) {
        words.append(upcast(w));
    }
}

/// The word divisor 2^16 and the 64- and 128-bit byte-swap masks.
type K = (NonZero<B16>, u128, u128);

/// The u128 bitwise libfunc: AND, XOR and OR of one operand pair from a single builtin instance.
extern fn bitwise(lhs: u128, rhs: u128) -> (u128, u128, u128) implicits(core::integer::Bitwise) nopanic;

/// Append the accepted words of a byte-swapped lane, in stream order.
#[inline(always)]
fn push_swapped(swapped: L64, k: K, ref words: Array<u16>) {
    let (d, _, _) = k;
    let (r, w0) = div_rem(swapped, d);
    let (r, w1) = div_rem(r, d);
    let (w3, w2) = div_rem(r, d);
    accept(w0, ref words);
    accept(w1, ref words);
    accept(w2, ref words);
    accept(w3, ref words);
}

/// Append the accepted words of one rate lane (< 2^64), in stream order.
#[inline(always)]
fn push_lane(lane: L64, k: K, ref words: Array<u16>) {
    let (_, m64, _) = k;
    let lane: u128 = upcast(lane);
    let (even, _, _) = bitwise(lane, m64);
    let even: felt252 = even.into();
    let swapped: felt252 = (even * 65535 + lane.into()) * INV256;
    push_swapped(downcast(swapped).unwrap(), k, ref words);
}

/// Byte-swap both halves of a packed lane; append the low half's words and stash the high half.
#[inline(always)]
fn push_packed(lane: u128, k: K, ref words: Array<u16>, ref later: Array<L64>) {
    let (_, _, m128) = k;
    let (even, _, _) = bitwise(lane, m128);
    let even: felt252 = even.into();
    let swapped: u128 = ((even * 65535 + lane.into()) * INV256).try_into().unwrap();
    let (h, l) = div_rem(upcast::<u128, U128B>(swapped), B64_NZ);
    push_swapped(l, k, ref words);
    later.append(h);
}

/// Rate lanes of a packed state: block j (low halves) now, block j + 4 (high halves) stashed.
fn push_block_packed(
    state: [u128; 25], k: K, ref words: Array<u16>, ref later: Array<L64>,
) {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, _, _, _, _, _, _, _, _] =
        state;
    push_packed(l0, k, ref words, ref later);
    push_packed(l1, k, ref words, ref later);
    push_packed(l2, k, ref words, ref later);
    push_packed(l3, k, ref words, ref later);
    push_packed(l4, k, ref words, ref later);
    push_packed(l5, k, ref words, ref later);
    push_packed(l6, k, ref words, ref later);
    push_packed(l7, k, ref words, ref later);
    push_packed(l8, k, ref words, ref later);
    push_packed(l9, k, ref words, ref later);
    push_packed(l10, k, ref words, ref later);
    push_packed(l11, k, ref words, ref later);
    push_packed(l12, k, ref words, ref later);
    push_packed(l13, k, ref words, ref later);
    push_packed(l14, k, ref words, ref later);
    push_packed(l15, k, ref words, ref later);
    push_packed(l16, k, ref words, ref later);
}

/// The words of the 17 rate lanes of a block.
fn push_block(lanes: [L64; 17], k: K, ref words: Array<u16>) {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16] = lanes;
    push_lane(l0, k, ref words);
    push_lane(l1, k, ref words);
    push_lane(l2, k, ref words);
    push_lane(l3, k, ref words);
    push_lane(l4, k, ref words);
    push_lane(l5, k, ref words);
    push_lane(l6, k, ref words);
    push_lane(l7, k, ref words);
    push_lane(l8, k, ref words);
    push_lane(l9, k, ref words);
    push_lane(l10, k, ref words);
    push_lane(l11, k, ref words);
    push_lane(l12, k, ref words);
    push_lane(l13, k, ref words);
    push_lane(l14, k, ref words);
    push_lane(l15, k, ref words);
    push_lane(l16, k, ref words);
}

/// The words of 17 stashed (already byte-swapped) lanes.
fn push_block_swapped(lanes: [L64; 17], k: K, ref words: Array<u16>) {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16] = lanes;
    push_swapped(l0, k, ref words);
    push_swapped(l1, k, ref words);
    push_swapped(l2, k, ref words);
    push_swapped(l3, k, ref words);
    push_swapped(l4, k, ref words);
    push_swapped(l5, k, ref words);
    push_swapped(l6, k, ref words);
    push_swapped(l7, k, ref words);
    push_swapped(l8, k, ref words);
    push_swapped(l9, k, ref words);
    push_swapped(l10, k, ref words);
    push_swapped(l11, k, ref words);
    push_swapped(l12, k, ref words);
    push_swapped(l13, k, ref words);
    push_swapped(l14, k, ref words);
    push_swapped(l15, k, ref words);
    push_swapped(l16, k, ref words);
}

/// The 25 lanes of S4 from its 9 felts; `None` unless every felt is < 2^192 and the last one is
/// < 2^64.
fn mid_state_lanes(mid: Span<felt252>) -> Option<[L64; 25]> {
    if mid.len() != MID_STATE_FELTS {
        return None;
    }
    let mut out: Array<L64> = array![];
    let mut it = mid.slice(0, 8);
    while let Some(f) = it.pop_front() {
        let v: u256 = (*f).into();
        let l2: L64 = downcast(v.high)?;
        let (l1, l0) = div_rem(upcast::<u128, U128B>(v.low), B64_NZ);
        out.append(l0);
        out.append(l1);
        out.append(l2);
    }
    let last: u256 = (*mid.at(8)).into();
    if last.high != 0 {
        return None;
    }
    out.append(downcast(last.low)?);
    Some((*out.span().try_into().unwrap()).unbox())
}

/// a + b * 2^64.
#[inline(always)]
fn pack(a: L64, b: L64) -> u128 {
    upcast(add(a, mul(b, B64_ONE)))
}

/// b * 2^64.
#[inline(always)]
fn pack0(b: L64) -> u128 {
    upcast(mul(b, B64_ONE))
}

#[inline(always)]
fn halves(x: u128) -> (L64, L64) {
    div_rem(upcast::<u128, U128B>(x), B64_NZ)
}

/// High halves of a packed state, after checking that its low halves equal `s`.
fn split_check(w: [u128; 25], s: [L64; 25]) -> Option<[L64; 25]> {
    let mut hi: Array<L64> = array![];
    let mut iw = w.span();
    let mut is = s.span();
    while let Some(lane) = iw.pop_front() {
        let (h, l) = halves(*lane);
        if upcast::<L64, u128>(l) != upcast(*is.pop_front().unwrap()) {
            return None;
        }
        hi.append(h);
    }
    Some((*hi.span().try_into().unwrap()).unbox())
}

#[inline(always)]
fn rate(s: [L64; 25]) -> [L64; 17] {
    let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, _, _, _, _, _, _, _, _] =
        s;
    [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16]
}

/// Hash `(message_hash, salt)` to >= 512 unreduced candidate words in [0, 5Q), given the sponge
/// state S4 after the 4th permutation. `None` if either salt felt exceeds 20 bytes or S4 is
/// malformed or wrong.
pub fn hash_to_point(
    message_hash: felt252, salt_a: felt252, salt_b: felt252, mid_state: Span<felt252>,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let s4 = mid_state_lanes(mid_state)?;
    let [
        s0, s1, s2, s3, s4_, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19,
        s20, s21, s22, s23, s24,
    ] =
        s4;
    let mh: u256 = message_hash.into();
    // Absorbed block as little-endian lanes, exactly as in `hash_to_point_shake_512`.
    let (a1, a0) = halves(sa.low);
    let (sbq, sb0) = div_rem(upcast::<u128, U128B>(sb.low), B32_NZ);
    let (sb12, l3) = div_rem(sbq, B64_NZ);
    let (m1, m0) = halves(mh.low);
    let (m3, m2) = halves(mh.high);
    let l2: L64 = downcast(sa.high.into() + upcast::<L32, felt252>(sb0) * 0x100000000).unwrap();
    let l4: L64 = downcast(upcast::<L32, felt252>(sb12) + sb.high.into() * 0x100000000).unwrap();

    // Chains (A -> S4) and (S4 -> S8) side by side.
    let w = keccak_f1600_x2(
        [
            pack(a0, s0), pack(a1, s1), pack(l2, s2), pack(l3, s3), pack(l4, s4_), pack(m0, s5),
            pack(m1, s6), pack(m2, s7), pack(m3, s8), pack(PAD_START, s9), pack0(s10), pack0(s11),
            pack0(s12), pack0(s13), pack0(s14), pack0(s15), pack(PAD_END, s16), pack0(s17),
            pack0(s18), pack0(s19), pack0(s20), pack0(s21), pack0(s22), pack0(s23), pack0(s24),
        ],
    );
    let mut words: Array<u16> = array![];
    let mut later: Array<L64> = array![];
    // Divisor and byte-swap masks in the frame: one instruction per use instead of two.
    let k: K = (B16_NZ, 0x00ff00ff00ff00ff, 0x00ff00ff00ff00ff00ff00ff00ff00ff);
    push_block_packed(w, k, ref words, ref later); // blocks 0 | 4
    let w = keccak_f1600_x2(w);
    push_block_packed(w, k, ref words, ref later); // blocks 1 | 5
    let w = keccak_f1600_x2(w);
    push_block_packed(w, k, ref words, ref later); // blocks 2 | 6
    let w = keccak_f1600_x2(w);
    let s8 = split_check(w, s4)?; // the recomputed S4 must equal the supplied one
    push_block(rate(s4), k, ref words); // block 3
    let mut later = later.span();
    push_block_swapped((*later.multi_pop_front::<17>().unwrap()).unbox(), k, ref words); // block 4
    push_block_swapped((*later.multi_pop_front::<17>().unwrap()).unbox(), k, ref words); // block 5
    push_block_swapped((*later.multi_pop_front::<17>().unwrap()).unbox(), k, ref words); // block 6
    // Block 7 onward, stopping at 512 accepted words.
    let mut state: Span<L64> = s8.span();
    loop {
        let mut lanes = state.slice(0, 17);
        while let Some(lane) = lanes.pop_front() {
            push_lane(*lane, k, ref words);
            if words.len() >= 512 {
                break;
            }
        }
        if words.len() >= 512 {
            break;
        }
        // A 9th permutation (only for unground salts), in the low half.
        let mut st: Array<u128> = array![];
        let mut it = state;
        while let Some(l) = it.pop_front() {
            st.append(upcast(*l));
        }
        let next = keccak_f1600_x2((*st.span().try_into().unwrap()).unbox());
        let mut low: Array<L64> = array![];
        let mut it = next.span();
        while let Some(lane) = it.pop_front() {
            let (_, l) = halves(*lane);
            low.append(l);
        }
        state = low.span();
    }
    Some(words)
}
