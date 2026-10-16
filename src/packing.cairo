// Portions derived from OpenZeppelin cairo-pq-verifiers (MIT License, Copyright (c) 2026 OpenZeppelin).
//! Base-Q packing of 512 Z_q coefficients into 29 felt252 slots.
//!
//! Each full slot carries two u128 halves; each half Horner-packs 9 coefficients in base
//! Q = 12289 (Q^9 < 2^128): `half = c0 + Q*(c1 + Q*(c2 + ...))`. 28 full slots hold 18
//! coefficients each; the last slot holds the remaining 8 in its low half.
//!
//! Unpacking is validating: every extracted base-Q digit is < Q by construction, and the
//! residual quotient after the last digit must be zero (each half < Q^9, the last slot
//! < Q^8). The accepted felt vectors are therefore in bijection with coefficient vectors
//! in [0, Q)^512 — no coefficient can be smuggled in a non-canonical encoding.

use corelib_imports::bounded_int::{
    BoundedInt, DivRemHelper, UnitInt, bounded_int_div_rem, downcast, upcast,
};

/// Coefficients per full felt252 slot (two u128 halves of 9).
pub const VALS_PER_FELT: u32 = 18;
/// felt252 slots for 512 coefficients: 28 full slots + 1 slot with 8.
pub const PACKED_SLOTS: u32 = 29;
/// Coefficients in the last slot: 512 - 28*18.
const LAST_SLOT_VALS: u32 = 8;

const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

type PackingZq = BoundedInt<0, 12288>;
type PackingQ = UnitInt<12289>;
type Acc1 = BoundedInt<0, 151019520>;
type Acc2 = BoundedInt<0, 1855878893568>;
type Acc3 = BoundedInt<0, 22806895723069440>;
type Acc4 = BoundedInt<0, 280273941540800360448>;
type Acc5 = BoundedInt<0, 3444286467594895629557760>;
type Acc6 = BoundedInt<0, 42326836400273672391635324928>;
type Acc7 = BoundedInt<0, 520154492522963160020806508052480>;
type Acc8 = BoundedInt<0, 6392178558614694273495691177456939008>;

const PACKING_Q_NZ: NonZero<PackingQ> = 12289;

impl PackingDivRemAcc1Impl of DivRemHelper<Acc1, PackingQ> {
    type DivT = PackingZq;
    type RemT = PackingZq;
}

impl PackingDivRemAcc2Impl of DivRemHelper<Acc2, PackingQ> {
    type DivT = Acc1;
    type RemT = PackingZq;
}

impl PackingDivRemAcc3Impl of DivRemHelper<Acc3, PackingQ> {
    type DivT = Acc2;
    type RemT = PackingZq;
}

impl PackingDivRemAcc4Impl of DivRemHelper<Acc4, PackingQ> {
    type DivT = Acc3;
    type RemT = PackingZq;
}

impl PackingDivRemAcc5Impl of DivRemHelper<Acc5, PackingQ> {
    type DivT = Acc4;
    type RemT = PackingZq;
}

impl PackingDivRemAcc6Impl of DivRemHelper<Acc6, PackingQ> {
    type DivT = Acc5;
    type RemT = PackingZq;
}

impl PackingDivRemAcc7Impl of DivRemHelper<Acc7, PackingQ> {
    type DivT = Acc6;
    type RemT = PackingZq;
}

impl PackingDivRemAcc8Impl of DivRemHelper<Acc8, PackingQ> {
    type DivT = Acc7;
    type RemT = PackingZq;
}

/// Unpack the canonical 29-slot encoding directly into the verifier's `u16` form.
/// Returns `None` on wrong length or any non-canonical slot encoding.
pub fn unpack_512_u16(packed: Span<felt252>) -> Option<Array<u16>> {
    if packed.len() != PACKED_SLOTS {
        return None;
    }
    let mut coeffs: Array<u16> = array![];
    let mut full_slots = packed.slice(0, PACKED_SLOTS - 1);
    while let Some(chunk) = full_slots.multi_pop_front::<7>() {
        let [f0, f1, f2, f3, f4, f5, f6] = (*chunk).unbox();
        if !unpack_full_slot_u16(f0, ref coeffs)
            || !unpack_full_slot_u16(f1, ref coeffs)
            || !unpack_full_slot_u16(f2, ref coeffs)
            || !unpack_full_slot_u16(f3, ref coeffs)
            || !unpack_full_slot_u16(f4, ref coeffs)
            || !unpack_full_slot_u16(f5, ref coeffs)
            || !unpack_full_slot_u16(f6, ref coeffs) {
            return None;
        }
    }
    let last: u256 = (*packed.at(PACKED_SLOTS - 1)).into();
    if last.high != 0 || !unpack_half8_u16(last.low, ref coeffs) {
        return None;
    }
    Some(coeffs)
}

#[inline(always)]
fn unpack_full_slot_u16(felt: felt252, ref coeffs: Array<u16>) -> bool {
    let value: u256 = felt.into();
    unpack_half9_u16(value.low, ref coeffs) && unpack_half9_u16(value.high, ref coeffs)
}

/// Extract nine base-Q digits from a u128 half. Values below Q^9 are canonical;
/// after eight divisions the remaining quotient is the ninth digit.
#[inline(always)]
fn unpack_half9_u16(value: u128, ref coeffs: Array<u16>) -> bool {
    let value: Acc8 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, PACKING_Q_NZ);
    let (rest, d1) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d2) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d3) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d4) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d5) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d6) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d7) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    coeffs.append(upcast(d0));
    coeffs.append(upcast(d1));
    coeffs.append(upcast(d2));
    coeffs.append(upcast(d3));
    coeffs.append(upcast(d4));
    coeffs.append(upcast(d5));
    coeffs.append(upcast(d6));
    coeffs.append(upcast(d7));
    coeffs.append(upcast(rest));
    true
}

/// Extract the final slot's eight digits after checking the value is below Q^8.
#[inline(always)]
fn unpack_half8_u16(value: u128, ref coeffs: Array<u16>) -> bool {
    let value: Acc7 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, PACKING_Q_NZ);
    let (rest, d1) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d2) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d3) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d4) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d5) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    let (rest, d6) = bounded_int_div_rem(rest, PACKING_Q_NZ);
    coeffs.append(upcast(d0));
    coeffs.append(upcast(d1));
    coeffs.append(upcast(d2));
    coeffs.append(upcast(d3));
    coeffs.append(upcast(d4));
    coeffs.append(upcast(d5));
    coeffs.append(upcast(d6));
    coeffs.append(upcast(rest));
    true
}
