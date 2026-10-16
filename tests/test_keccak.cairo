use falcon512_account::keccak::keccak_f1600;
use super::fixtures;

fn to25(a: Array<u128>) -> [u128; 25] {
    let s = a.span();
    [
        *s[0], *s[1], *s[2], *s[3], *s[4], *s[5], *s[6], *s[7], *s[8], *s[9], *s[10], *s[11], *s[12],
        *s[13], *s[14], *s[15], *s[16], *s[17], *s[18], *s[19], *s[20], *s[21], *s[22], *s[23], *s[24],
    ]
}

#[test]
fn keccak_f1600_matches_fips202_reference() {
    assert!(keccak_f1600(to25(fixtures::keccak_in_0())).span() == fixtures::keccak_out_0().span());
    assert!(keccak_f1600(to25(fixtures::keccak_in_1())).span() == fixtures::keccak_out_1().span());
    assert!(keccak_f1600(to25(fixtures::keccak_in_2())).span() == fixtures::keccak_out_2().span());
}
