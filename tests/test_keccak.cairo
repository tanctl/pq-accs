use falcon512_account::keccak::keccak_f1600_x2;
use super::fixtures;

/// Lane k = a_k + b_k * 2^64.
fn pack(a: Array<u128>, b: Array<u128>) -> [u128; 25] {
    let mut out: Array<u128> = array![];
    let mut i = 0;
    while i != 25 {
        out.append(*a.at(i) + *b.at(i) * 0x10000000000000000);
        i += 1;
    }
    let s = out.span();
    [
        *s[0], *s[1], *s[2], *s[3], *s[4], *s[5], *s[6], *s[7], *s[8], *s[9], *s[10], *s[11],
        *s[12], *s[13], *s[14], *s[15], *s[16], *s[17], *s[18], *s[19], *s[20], *s[21], *s[22],
        *s[23], *s[24],
    ]
}

fn check(i: Array<u128>, j: Array<u128>, oi: Array<u128>, oj: Array<u128>) {
    let out = keccak_f1600_x2(pack(i, j));
    assert!(out.span() == pack(oi, oj).span());
}

/// Both halves against the FIPS 202 reference, in every pairing of the three KAT inputs.
#[test]
fn keccak_f1600_x2_matches_fips202_reference() {
    check(
        fixtures::keccak_in_0(),
        fixtures::keccak_in_1(),
        fixtures::keccak_out_0(),
        fixtures::keccak_out_1(),
    );
    check(
        fixtures::keccak_in_1(),
        fixtures::keccak_in_2(),
        fixtures::keccak_out_1(),
        fixtures::keccak_out_2(),
    );
    check(
        fixtures::keccak_in_2(),
        fixtures::keccak_in_0(),
        fixtures::keccak_out_2(),
        fixtures::keccak_out_0(),
    );
    check(
        fixtures::keccak_in_2(),
        fixtures::keccak_in_2(),
        fixtures::keccak_out_2(),
        fixtures::keccak_out_2(),
    );
}
