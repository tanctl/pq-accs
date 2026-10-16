// Portions derived from OpenZeppelin cairo-pq-verifiers (MIT License, Copyright (c) 2026 OpenZeppelin).
//! Falcon-512 hash-to-point with standard SHAKE-256: absorb `salt (40 bytes) || message hash (32
//! bytes, little-endian)`, read the stream as big-endian 16-bit words, accept `word < 5q`.
//!
//! - Accepted words are returned unreduced (< 5q); the verifier only uses them modulo q.
//! - The four words of a rate lane are byte-swapped at once: with E = lane & 0x00ff00ff00ff00ff,
//!   they are the base-2^16 digits of (65535 * E + lane) / 256.
//! - Squeeze blocks 0..6 hold 7 * 68 = 476 < 512 words, so they are consumed with no per-lane
//!   checks. Returns at least 512 words (the last lane may add up to 3); use the first 512.

use corelib_imports::bounded_int::bounded_int::{ConstrainHelper, constrain, div_rem};
use corelib_imports::bounded_int::{BoundedInt, DivRemHelper, UnitInt, downcast, upcast};
use crate::keccak::keccak_f1600;

const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000;
const INV256: felt252 = 0x7f8000000000010ef0000000000000000000000000000000000000000000001;

type L64 = BoundedInt<0, 0xffffffffffffffff>;
type L48 = BoundedInt<0, 0xffffffffffff>;
type L32 = BoundedInt<0, 0xffffffff>;
type W16 = BoundedInt<0, 0xffff>;
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
fn accept(word: W16, ref coeffs: Array<u16>) {
    if let Ok(w) = constrain::<W16, 61445>(word) {
        coeffs.append(upcast(w));
    }
}

/// Append the accepted words of one rate lane (< 2^64), in stream order.
#[inline(always)]
fn push_lane_raw(lane: u128, ref coeffs: Array<u16>) {
    let even: felt252 = (lane & 0x00ff00ff00ff00ff).into();
    let swapped: felt252 = (even * 65535 + lane.into()) * INV256;
    let swapped: L64 = downcast(swapped).unwrap();
    let (r, w0) = div_rem(swapped, B16_NZ);
    let (r, w1) = div_rem(r, B16_NZ);
    let (w3, w2) = div_rem(r, B16_NZ);
    accept(w0, ref coeffs);
    accept(w1, ref coeffs);
    accept(w2, ref coeffs);
    accept(w3, ref coeffs);
}

/// Hash `(message_hash, salt)` to >= 512 unreduced candidate words in [0, 5Q). `None` if
/// either salt felt exceeds 20 bytes.
pub fn hash_to_point(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let mh: u256 = message_hash.into();
    // Absorbed block as little-endian lanes, exactly as in `hash_to_point_shake_512`.
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let two32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (a1, a0) = DivRem::div_rem(sa.low, two64);
    let (sbq, sb0) = DivRem::div_rem(sb.low, two32);
    let (sb12, l3) = DivRem::div_rem(sbq, two64);
    let (m1, m0) = DivRem::div_rem(mh.low, two64);
    let (m3, m2) = DivRem::div_rem(mh.high, two64);
    let l2: u128 = (sa.high.into() + sb0.into() * 0x100000000).try_into().unwrap();
    let l4: u128 = (sb12.into() + sb.high.into() * 0x100000000).try_into().unwrap();

    let mut state = keccak_f1600(
        [
            a0, a1, l2, l3, l4, m0, m1, m2, m3, 0x1f, 0, 0, 0, 0, 0, 0, 0x8000000000000000, 0, 0, 0,
            0, 0, 0, 0, 0,
        ],
    );
    let mut coeffs: Array<u16> = array![];
    // Blocks 0..6 hold 7 * 68 = 476 < 512 candidates, so 512 accepts can never complete
    // inside them: consume all 17 rate lanes with no per-lane bookkeeping.
    let mut blk = 0;
    while blk != 7 {
        let [l0, l1, l2, l3, l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16, _, _, _, _, _, _, _, _] = state;
        push_lane_raw(l0, ref coeffs);
        push_lane_raw(l1, ref coeffs);
        push_lane_raw(l2, ref coeffs);
        push_lane_raw(l3, ref coeffs);
        push_lane_raw(l4, ref coeffs);
        push_lane_raw(l5, ref coeffs);
        push_lane_raw(l6, ref coeffs);
        push_lane_raw(l7, ref coeffs);
        push_lane_raw(l8, ref coeffs);
        push_lane_raw(l9, ref coeffs);
        push_lane_raw(l10, ref coeffs);
        push_lane_raw(l11, ref coeffs);
        push_lane_raw(l12, ref coeffs);
        push_lane_raw(l13, ref coeffs);
        push_lane_raw(l14, ref coeffs);
        push_lane_raw(l15, ref coeffs);
        push_lane_raw(l16, ref coeffs);
        state = keccak_f1600(state);
        blk += 1;
    }
    loop {
        let mut lanes = state.span().slice(0, 17);
        while let Some(lane) = lanes.pop_front() {
            push_lane_raw(*lane, ref coeffs);
            if coeffs.len() >= 512 {
                break;
            }
        }
        if coeffs.len() >= 512 {
            break;
        }
        state = keccak_f1600(state);
    }
    Some(coeffs)
}
