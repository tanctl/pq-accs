// Portions derived from OpenZeppelin cairo-pq-verifiers (MIT License, Copyright (c) 2026 OpenZeppelin).
//! Keccak-f[1600] for the Sierra-gas meter.
//!
//! Lanes are u128 values holding 64-bit words (the u128 bitwise builtin's operand width). Each of
//! the 24 rounds is straight-line code over 25 lane locals (round constants inlined):
//! - theta is fused into the rho+pi terms, iota into lane 0;
//! - a rotation by R is one typed `div_rem` by 2^(64-R) plus a typed bounded-int recombine;
//! - chi_i = b_i ^ (~b_{i+1} & b_{i+2}) is computed as (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one
//!   bitwise instance per adjacent pair yields both terms, so chi needs no complement.
//! Lane invariant: every lane value is < 2^64.

use corelib_imports::bounded_int::bounded_int::{add, div_rem, mul};
use corelib_imports::bounded_int::{AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, upcast};

/// The u128 bitwise libfunc: AND, XOR and OR of one operand pair from a single builtin instance
/// (corelib exposes it only through the separate `&`, `^`, `|` operators).
extern fn bitwise(lhs: u128, rhs: u128) -> (u128, u128, u128) implicits(core::integer::Bitwise) nopanic;

type U128B = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;


type D1 = UnitInt<0x8000000000000000>;
const D1_NZ: NonZero<D1> = 0x8000000000000000;
type PowT1 = UnitInt<0x2>;
const POW1: PowT1 = 0x2;
impl DivRem1 of DivRemHelper<U128B, D1> {
    type DivT = BoundedInt<0, 0x1ffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7fffffffffffffff>;
}
impl Mul1 of MulHelper<BoundedInt<0, 0x7fffffffffffffff>, PowT1> {
    type Result = BoundedInt<0, 0xfffffffffffffffe>;
}
impl Add1 of AddHelper<BoundedInt<0, 0xfffffffffffffffe>, BoundedInt<0, 0x1ffffffffffffffff>> {
    type Result = BoundedInt<0, 0x2fffffffffffffffd>;
}
/// rotl by 1 of a lane < 2^64.
#[inline(always)]
fn rot1(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D1_NZ);
    upcast(add(mul(m, POW1), q))
}

type D2 = UnitInt<0x4000000000000000>;
const D2_NZ: NonZero<D2> = 0x4000000000000000;
type PowT2 = UnitInt<0x4>;
const POW2: PowT2 = 0x4;
impl DivRem2 of DivRemHelper<U128B, D2> {
    type DivT = BoundedInt<0, 0x3ffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3fffffffffffffff>;
}
impl Mul2 of MulHelper<BoundedInt<0, 0x3fffffffffffffff>, PowT2> {
    type Result = BoundedInt<0, 0xfffffffffffffffc>;
}
impl Add2 of AddHelper<BoundedInt<0, 0xfffffffffffffffc>, BoundedInt<0, 0x3ffffffffffffffff>> {
    type Result = BoundedInt<0, 0x4fffffffffffffffb>;
}
/// rotl by 2 of a lane < 2^64.
#[inline(always)]
fn rot2(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D2_NZ);
    upcast(add(mul(m, POW2), q))
}

type D3 = UnitInt<0x2000000000000000>;
const D3_NZ: NonZero<D3> = 0x2000000000000000;
type PowT3 = UnitInt<0x8>;
const POW3: PowT3 = 0x8;
impl DivRem3 of DivRemHelper<U128B, D3> {
    type DivT = BoundedInt<0, 0x7ffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1fffffffffffffff>;
}
impl Mul3 of MulHelper<BoundedInt<0, 0x1fffffffffffffff>, PowT3> {
    type Result = BoundedInt<0, 0xfffffffffffffff8>;
}
impl Add3 of AddHelper<BoundedInt<0, 0xfffffffffffffff8>, BoundedInt<0, 0x7ffffffffffffffff>> {
    type Result = BoundedInt<0, 0x8fffffffffffffff7>;
}
/// rotl by 3 of a lane < 2^64.
#[inline(always)]
fn rot3(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D3_NZ);
    upcast(add(mul(m, POW3), q))
}

type D6 = UnitInt<0x400000000000000>;
const D6_NZ: NonZero<D6> = 0x400000000000000;
type PowT6 = UnitInt<0x40>;
const POW6: PowT6 = 0x40;
impl DivRem6 of DivRemHelper<U128B, D6> {
    type DivT = BoundedInt<0, 0x3fffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3ffffffffffffff>;
}
impl Mul6 of MulHelper<BoundedInt<0, 0x3ffffffffffffff>, PowT6> {
    type Result = BoundedInt<0, 0xffffffffffffffc0>;
}
impl Add6 of AddHelper<BoundedInt<0, 0xffffffffffffffc0>, BoundedInt<0, 0x3fffffffffffffffff>> {
    type Result = BoundedInt<0, 0x40ffffffffffffffbf>;
}
/// rotl by 6 of a lane < 2^64.
#[inline(always)]
fn rot6(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D6_NZ);
    upcast(add(mul(m, POW6), q))
}

type D8 = UnitInt<0x100000000000000>;
const D8_NZ: NonZero<D8> = 0x100000000000000;
type PowT8 = UnitInt<0x100>;
const POW8: PowT8 = 0x100;
impl DivRem8 of DivRemHelper<U128B, D8> {
    type DivT = BoundedInt<0, 0xffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xffffffffffffff>;
}
impl Mul8 of MulHelper<BoundedInt<0, 0xffffffffffffff>, PowT8> {
    type Result = BoundedInt<0, 0xffffffffffffff00>;
}
impl Add8 of AddHelper<BoundedInt<0, 0xffffffffffffff00>, BoundedInt<0, 0xffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x100fffffffffffffeff>;
}
/// rotl by 8 of a lane < 2^64.
#[inline(always)]
fn rot8(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D8_NZ);
    upcast(add(mul(m, POW8), q))
}

type D10 = UnitInt<0x40000000000000>;
const D10_NZ: NonZero<D10> = 0x40000000000000;
type PowT10 = UnitInt<0x400>;
const POW10: PowT10 = 0x400;
impl DivRem10 of DivRemHelper<U128B, D10> {
    type DivT = BoundedInt<0, 0x3ffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3fffffffffffff>;
}
impl Mul10 of MulHelper<BoundedInt<0, 0x3fffffffffffff>, PowT10> {
    type Result = BoundedInt<0, 0xfffffffffffffc00>;
}
impl Add10 of AddHelper<BoundedInt<0, 0xfffffffffffffc00>, BoundedInt<0, 0x3ffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x400fffffffffffffbff>;
}
/// rotl by 10 of a lane < 2^64.
#[inline(always)]
fn rot10(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D10_NZ);
    upcast(add(mul(m, POW10), q))
}

type D14 = UnitInt<0x4000000000000>;
const D14_NZ: NonZero<D14> = 0x4000000000000;
type PowT14 = UnitInt<0x4000>;
const POW14: PowT14 = 0x4000;
impl DivRem14 of DivRemHelper<U128B, D14> {
    type DivT = BoundedInt<0, 0x3fffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3ffffffffffff>;
}
impl Mul14 of MulHelper<BoundedInt<0, 0x3ffffffffffff>, PowT14> {
    type Result = BoundedInt<0, 0xffffffffffffc000>;
}
impl Add14 of AddHelper<BoundedInt<0, 0xffffffffffffc000>, BoundedInt<0, 0x3fffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x4000ffffffffffffbfff>;
}
/// rotl by 14 of a lane < 2^64.
#[inline(always)]
fn rot14(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D14_NZ);
    upcast(add(mul(m, POW14), q))
}

type D15 = UnitInt<0x2000000000000>;
const D15_NZ: NonZero<D15> = 0x2000000000000;
type PowT15 = UnitInt<0x8000>;
const POW15: PowT15 = 0x8000;
impl DivRem15 of DivRemHelper<U128B, D15> {
    type DivT = BoundedInt<0, 0x7fffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1ffffffffffff>;
}
impl Mul15 of MulHelper<BoundedInt<0, 0x1ffffffffffff>, PowT15> {
    type Result = BoundedInt<0, 0xffffffffffff8000>;
}
impl Add15 of AddHelper<BoundedInt<0, 0xffffffffffff8000>, BoundedInt<0, 0x7fffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x8000ffffffffffff7fff>;
}
/// rotl by 15 of a lane < 2^64.
#[inline(always)]
fn rot15(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D15_NZ);
    upcast(add(mul(m, POW15), q))
}

type D18 = UnitInt<0x400000000000>;
const D18_NZ: NonZero<D18> = 0x400000000000;
type PowT18 = UnitInt<0x40000>;
const POW18: PowT18 = 0x40000;
impl DivRem18 of DivRemHelper<U128B, D18> {
    type DivT = BoundedInt<0, 0x3ffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3fffffffffff>;
}
impl Mul18 of MulHelper<BoundedInt<0, 0x3fffffffffff>, PowT18> {
    type Result = BoundedInt<0, 0xfffffffffffc0000>;
}
impl Add18 of AddHelper<BoundedInt<0, 0xfffffffffffc0000>, BoundedInt<0, 0x3ffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x40000fffffffffffbffff>;
}
/// rotl by 18 of a lane < 2^64.
#[inline(always)]
fn rot18(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D18_NZ);
    upcast(add(mul(m, POW18), q))
}

type D20 = UnitInt<0x100000000000>;
const D20_NZ: NonZero<D20> = 0x100000000000;
type PowT20 = UnitInt<0x100000>;
const POW20: PowT20 = 0x100000;
impl DivRem20 of DivRemHelper<U128B, D20> {
    type DivT = BoundedInt<0, 0xfffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xfffffffffff>;
}
impl Mul20 of MulHelper<BoundedInt<0, 0xfffffffffff>, PowT20> {
    type Result = BoundedInt<0, 0xfffffffffff00000>;
}
impl Add20 of AddHelper<BoundedInt<0, 0xfffffffffff00000>, BoundedInt<0, 0xfffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x100000ffffffffffefffff>;
}
/// rotl by 20 of a lane < 2^64.
#[inline(always)]
fn rot20(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D20_NZ);
    upcast(add(mul(m, POW20), q))
}

type D21 = UnitInt<0x80000000000>;
const D21_NZ: NonZero<D21> = 0x80000000000;
type PowT21 = UnitInt<0x200000>;
const POW21: PowT21 = 0x200000;
impl DivRem21 of DivRemHelper<U128B, D21> {
    type DivT = BoundedInt<0, 0x1fffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7ffffffffff>;
}
impl Mul21 of MulHelper<BoundedInt<0, 0x7ffffffffff>, PowT21> {
    type Result = BoundedInt<0, 0xffffffffffe00000>;
}
impl Add21 of AddHelper<BoundedInt<0, 0xffffffffffe00000>, BoundedInt<0, 0x1fffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x200000ffffffffffdfffff>;
}
/// rotl by 21 of a lane < 2^64.
#[inline(always)]
fn rot21(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D21_NZ);
    upcast(add(mul(m, POW21), q))
}

type D25 = UnitInt<0x8000000000>;
const D25_NZ: NonZero<D25> = 0x8000000000;
type PowT25 = UnitInt<0x2000000>;
const POW25: PowT25 = 0x2000000;
impl DivRem25 of DivRemHelper<U128B, D25> {
    type DivT = BoundedInt<0, 0x1ffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7fffffffff>;
}
impl Mul25 of MulHelper<BoundedInt<0, 0x7fffffffff>, PowT25> {
    type Result = BoundedInt<0, 0xfffffffffe000000>;
}
impl Add25 of AddHelper<BoundedInt<0, 0xfffffffffe000000>, BoundedInt<0, 0x1ffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x2000000fffffffffdffffff>;
}
/// rotl by 25 of a lane < 2^64.
#[inline(always)]
fn rot25(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D25_NZ);
    upcast(add(mul(m, POW25), q))
}

type D27 = UnitInt<0x2000000000>;
const D27_NZ: NonZero<D27> = 0x2000000000;
type PowT27 = UnitInt<0x8000000>;
const POW27: PowT27 = 0x8000000;
impl DivRem27 of DivRemHelper<U128B, D27> {
    type DivT = BoundedInt<0, 0x7ffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1fffffffff>;
}
impl Mul27 of MulHelper<BoundedInt<0, 0x1fffffffff>, PowT27> {
    type Result = BoundedInt<0, 0xfffffffff8000000>;
}
impl Add27 of AddHelper<BoundedInt<0, 0xfffffffff8000000>, BoundedInt<0, 0x7ffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x8000000fffffffff7ffffff>;
}
/// rotl by 27 of a lane < 2^64.
#[inline(always)]
fn rot27(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D27_NZ);
    upcast(add(mul(m, POW27), q))
}

type D28 = UnitInt<0x1000000000>;
const D28_NZ: NonZero<D28> = 0x1000000000;
type PowT28 = UnitInt<0x10000000>;
const POW28: PowT28 = 0x10000000;
impl DivRem28 of DivRemHelper<U128B, D28> {
    type DivT = BoundedInt<0, 0xfffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xfffffffff>;
}
impl Mul28 of MulHelper<BoundedInt<0, 0xfffffffff>, PowT28> {
    type Result = BoundedInt<0, 0xfffffffff0000000>;
}
impl Add28 of AddHelper<BoundedInt<0, 0xfffffffff0000000>, BoundedInt<0, 0xfffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x10000000ffffffffefffffff>;
}
/// rotl by 28 of a lane < 2^64.
#[inline(always)]
fn rot28(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D28_NZ);
    upcast(add(mul(m, POW28), q))
}

type D36 = UnitInt<0x10000000>;
const D36_NZ: NonZero<D36> = 0x10000000;
type PowT36 = UnitInt<0x1000000000>;
const POW36: PowT36 = 0x1000000000;
impl DivRem36 of DivRemHelper<U128B, D36> {
    type DivT = BoundedInt<0, 0xfffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xfffffff>;
}
impl Mul36 of MulHelper<BoundedInt<0, 0xfffffff>, PowT36> {
    type Result = BoundedInt<0, 0xfffffff000000000>;
}
impl Add36 of AddHelper<BoundedInt<0, 0xfffffff000000000>, BoundedInt<0, 0xfffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x1000000000ffffffefffffffff>;
}
/// rotl by 36 of a lane < 2^64.
#[inline(always)]
fn rot36(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D36_NZ);
    upcast(add(mul(m, POW36), q))
}

type D39 = UnitInt<0x2000000>;
const D39_NZ: NonZero<D39> = 0x2000000;
type PowT39 = UnitInt<0x8000000000>;
const POW39: PowT39 = 0x8000000000;
impl DivRem39 of DivRemHelper<U128B, D39> {
    type DivT = BoundedInt<0, 0x7fffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1ffffff>;
}
impl Mul39 of MulHelper<BoundedInt<0, 0x1ffffff>, PowT39> {
    type Result = BoundedInt<0, 0xffffff8000000000>;
}
impl Add39 of AddHelper<BoundedInt<0, 0xffffff8000000000>, BoundedInt<0, 0x7fffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x8000000000ffffff7fffffffff>;
}
/// rotl by 39 of a lane < 2^64.
#[inline(always)]
fn rot39(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D39_NZ);
    upcast(add(mul(m, POW39), q))
}

type D41 = UnitInt<0x800000>;
const D41_NZ: NonZero<D41> = 0x800000;
type PowT41 = UnitInt<0x20000000000>;
const POW41: PowT41 = 0x20000000000;
impl DivRem41 of DivRemHelper<U128B, D41> {
    type DivT = BoundedInt<0, 0x1ffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7fffff>;
}
impl Mul41 of MulHelper<BoundedInt<0, 0x7fffff>, PowT41> {
    type Result = BoundedInt<0, 0xfffffe0000000000>;
}
impl Add41 of AddHelper<BoundedInt<0, 0xfffffe0000000000>, BoundedInt<0, 0x1ffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x20000000000fffffdffffffffff>;
}
/// rotl by 41 of a lane < 2^64.
#[inline(always)]
fn rot41(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D41_NZ);
    upcast(add(mul(m, POW41), q))
}

type D43 = UnitInt<0x200000>;
const D43_NZ: NonZero<D43> = 0x200000;
type PowT43 = UnitInt<0x80000000000>;
const POW43: PowT43 = 0x80000000000;
impl DivRem43 of DivRemHelper<U128B, D43> {
    type DivT = BoundedInt<0, 0x7ffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1fffff>;
}
impl Mul43 of MulHelper<BoundedInt<0, 0x1fffff>, PowT43> {
    type Result = BoundedInt<0, 0xfffff80000000000>;
}
impl Add43 of AddHelper<BoundedInt<0, 0xfffff80000000000>, BoundedInt<0, 0x7ffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x80000000000fffff7ffffffffff>;
}
/// rotl by 43 of a lane < 2^64.
#[inline(always)]
fn rot43(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D43_NZ);
    upcast(add(mul(m, POW43), q))
}

type D44 = UnitInt<0x100000>;
const D44_NZ: NonZero<D44> = 0x100000;
type PowT44 = UnitInt<0x100000000000>;
const POW44: PowT44 = 0x100000000000;
impl DivRem44 of DivRemHelper<U128B, D44> {
    type DivT = BoundedInt<0, 0xfffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xfffff>;
}
impl Mul44 of MulHelper<BoundedInt<0, 0xfffff>, PowT44> {
    type Result = BoundedInt<0, 0xfffff00000000000>;
}
impl Add44 of AddHelper<BoundedInt<0, 0xfffff00000000000>, BoundedInt<0, 0xfffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x100000000000ffffefffffffffff>;
}
/// rotl by 44 of a lane < 2^64.
#[inline(always)]
fn rot44(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D44_NZ);
    upcast(add(mul(m, POW44), q))
}

type D45 = UnitInt<0x80000>;
const D45_NZ: NonZero<D45> = 0x80000;
type PowT45 = UnitInt<0x200000000000>;
const POW45: PowT45 = 0x200000000000;
impl DivRem45 of DivRemHelper<U128B, D45> {
    type DivT = BoundedInt<0, 0x1fffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7ffff>;
}
impl Mul45 of MulHelper<BoundedInt<0, 0x7ffff>, PowT45> {
    type Result = BoundedInt<0, 0xffffe00000000000>;
}
impl Add45 of AddHelper<BoundedInt<0, 0xffffe00000000000>, BoundedInt<0, 0x1fffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x200000000000ffffdfffffffffff>;
}
/// rotl by 45 of a lane < 2^64.
#[inline(always)]
fn rot45(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D45_NZ);
    upcast(add(mul(m, POW45), q))
}

type D55 = UnitInt<0x200>;
const D55_NZ: NonZero<D55> = 0x200;
type PowT55 = UnitInt<0x80000000000000>;
const POW55: PowT55 = 0x80000000000000;
impl DivRem55 of DivRemHelper<U128B, D55> {
    type DivT = BoundedInt<0, 0x7fffffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x1ff>;
}
impl Mul55 of MulHelper<BoundedInt<0, 0x1ff>, PowT55> {
    type Result = BoundedInt<0, 0xff80000000000000>;
}
impl Add55 of AddHelper<BoundedInt<0, 0xff80000000000000>, BoundedInt<0, 0x7fffffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x80000000000000ff7fffffffffffff>;
}
/// rotl by 55 of a lane < 2^64.
#[inline(always)]
fn rot55(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D55_NZ);
    upcast(add(mul(m, POW55), q))
}

type D56 = UnitInt<0x100>;
const D56_NZ: NonZero<D56> = 0x100;
type PowT56 = UnitInt<0x100000000000000>;
const POW56: PowT56 = 0x100000000000000;
impl DivRem56 of DivRemHelper<U128B, D56> {
    type DivT = BoundedInt<0, 0xffffffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0xff>;
}
impl Mul56 of MulHelper<BoundedInt<0, 0xff>, PowT56> {
    type Result = BoundedInt<0, 0xff00000000000000>;
}
impl Add56 of AddHelper<BoundedInt<0, 0xff00000000000000>, BoundedInt<0, 0xffffffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x100000000000000feffffffffffffff>;
}
/// rotl by 56 of a lane < 2^64.
#[inline(always)]
fn rot56(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D56_NZ);
    upcast(add(mul(m, POW56), q))
}

type D61 = UnitInt<0x8>;
const D61_NZ: NonZero<D61> = 0x8;
type PowT61 = UnitInt<0x2000000000000000>;
const POW61: PowT61 = 0x2000000000000000;
impl DivRem61 of DivRemHelper<U128B, D61> {
    type DivT = BoundedInt<0, 0x1fffffffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x7>;
}
impl Mul61 of MulHelper<BoundedInt<0, 0x7>, PowT61> {
    type Result = BoundedInt<0, 0xe000000000000000>;
}
impl Add61 of AddHelper<BoundedInt<0, 0xe000000000000000>, BoundedInt<0, 0x1fffffffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x2000000000000000dfffffffffffffff>;
}
/// rotl by 61 of a lane < 2^64.
#[inline(always)]
fn rot61(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D61_NZ);
    upcast(add(mul(m, POW61), q))
}

type D62 = UnitInt<0x4>;
const D62_NZ: NonZero<D62> = 0x4;
type PowT62 = UnitInt<0x4000000000000000>;
const POW62: PowT62 = 0x4000000000000000;
impl DivRem62 of DivRemHelper<U128B, D62> {
    type DivT = BoundedInt<0, 0x3fffffffffffffffffffffffffffffff>;
    type RemT = BoundedInt<0, 0x3>;
}
impl Mul62 of MulHelper<BoundedInt<0, 0x3>, PowT62> {
    type Result = BoundedInt<0, 0xc000000000000000>;
}
impl Add62 of AddHelper<BoundedInt<0, 0xc000000000000000>, BoundedInt<0, 0x3fffffffffffffffffffffffffffffff>> {
    type Result = BoundedInt<0, 0x4000000000000000bfffffffffffffff>;
}
/// rotl by 62 of a lane < 2^64.
#[inline(always)]
fn rot62(x: u128) -> u128 {
    let (q, m) = div_rem(upcast::<u128, U128B>(x), D62_NZ);
    upcast(add(mul(m, POW62), q))
}


pub fn keccak_f1600(state: [u128; 25]) -> [u128; 25] {
    let [s00, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24] = state;
    // round 0
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x1;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 1
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8082;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 2
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x800000000000808a;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 3
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000080008000;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 4
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x808b;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 5
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x80000001;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 6
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000080008081;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 7
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000008009;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 8
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8a;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 9
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x88;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 10
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x80008009;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 11
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000a;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 12
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000808b;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 13
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x800000000000008b;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 14
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000008089;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 15
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000008003;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 16
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000008002;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 17
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000000080;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 18
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x800a;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 19
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x800000008000000a;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 20
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000080008081;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 21
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000000008080;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 22
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x80000001;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    // round 23
        // theta: column parities and the per-column mixing term d[x] = c[x-1] ^ rotl(c[x+1], 1).
        let c0 = s00 ^ s05 ^ s10 ^ s15 ^ s20;
        let c1 = s01 ^ s06 ^ s11 ^ s16 ^ s21;
        let c2 = s02 ^ s07 ^ s12 ^ s17 ^ s22;
        let c3 = s03 ^ s08 ^ s13 ^ s18 ^ s23;
        let c4 = s04 ^ s09 ^ s14 ^ s19 ^ s24;
        let d0 = c4 ^ rot1(c1);
        let d1 = c0 ^ rot1(c2);
        let d2 = c1 ^ rot1(c3);
        let d3 = c2 ^ rot1(c4);
        let d4 = c3 ^ rot1(c0);

        // theta (fused) + rho + pi, straight into destination order.
        let b00 = s00 ^ d0;
        let b01 = rot44(s06 ^ d1);
        let b02 = rot43(s12 ^ d2);
        let b03 = rot21(s18 ^ d3);
        let b04 = rot14(s24 ^ d4);
        let b05 = rot28(s03 ^ d3);
        let b06 = rot20(s09 ^ d4);
        let b07 = rot3(s10 ^ d0);
        let b08 = rot45(s16 ^ d1);
        let b09 = rot61(s22 ^ d2);
        let b10 = rot1(s01 ^ d1);
        let b11 = rot6(s07 ^ d2);
        let b12 = rot25(s13 ^ d3);
        let b13 = rot8(s19 ^ d4);
        let b14 = rot18(s20 ^ d0);
        let b15 = rot27(s04 ^ d4);
        let b16 = rot36(s05 ^ d0);
        let b17 = rot10(s11 ^ d1);
        let b18 = rot15(s17 ^ d2);
        let b19 = rot56(s23 ^ d3);
        let b20 = rot62(s02 ^ d2);
        let b21 = rot55(s08 ^ d3);
        let b22 = rot39(s14 ^ d4);
        let b23 = rot41(s15 ^ d0);
        let b24 = rot2(s21 ^ d1);

        // chi_i = (b_i ^ b_{i+1}) ^ (b_{i+1} | b_{i+2}): one bitwise instance per adjacent pair
        // yields both terms (XOR for output i, OR for output i-1), so no NOT is needed.
        let (_, x00, o00) = bitwise(b00, b01);
        let (_, x01, o01) = bitwise(b01, b02);
        let (_, x02, o02) = bitwise(b02, b03);
        let (_, x03, o03) = bitwise(b03, b04);
        let (_, x04, o04) = bitwise(b04, b00);
        let (_, x10, o10) = bitwise(b05, b06);
        let (_, x11, o11) = bitwise(b06, b07);
        let (_, x12, o12) = bitwise(b07, b08);
        let (_, x13, o13) = bitwise(b08, b09);
        let (_, x14, o14) = bitwise(b09, b05);
        let (_, x20, o20) = bitwise(b10, b11);
        let (_, x21, o21) = bitwise(b11, b12);
        let (_, x22, o22) = bitwise(b12, b13);
        let (_, x23, o23) = bitwise(b13, b14);
        let (_, x24, o24) = bitwise(b14, b10);
        let (_, x30, o30) = bitwise(b15, b16);
        let (_, x31, o31) = bitwise(b16, b17);
        let (_, x32, o32) = bitwise(b17, b18);
        let (_, x33, o33) = bitwise(b18, b19);
        let (_, x34, o34) = bitwise(b19, b15);
        let (_, x40, o40) = bitwise(b20, b21);
        let (_, x41, o41) = bitwise(b21, b22);
        let (_, x42, o42) = bitwise(b22, b23);
        let (_, x43, o43) = bitwise(b23, b24);
        let (_, x44, o44) = bitwise(b24, b20);
        let s00 = x00 ^ o01 ^ 0x8000000080008008;
        let s01 = x01 ^ o02;
        let s02 = x02 ^ o03;
        let s03 = x03 ^ o04;
        let s04 = x04 ^ o00;
        let s05 = x10 ^ o11;
        let s06 = x11 ^ o12;
        let s07 = x12 ^ o13;
        let s08 = x13 ^ o14;
        let s09 = x14 ^ o10;
        let s10 = x20 ^ o21;
        let s11 = x21 ^ o22;
        let s12 = x22 ^ o23;
        let s13 = x23 ^ o24;
        let s14 = x24 ^ o20;
        let s15 = x30 ^ o31;
        let s16 = x31 ^ o32;
        let s17 = x32 ^ o33;
        let s18 = x33 ^ o34;
        let s19 = x34 ^ o30;
        let s20 = x40 ^ o41;
        let s21 = x41 ^ o42;
        let s22 = x42 ^ o43;
        let s23 = x43 ^ o44;
        let s24 = x44 ^ o40;
    [s00, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24]
}

