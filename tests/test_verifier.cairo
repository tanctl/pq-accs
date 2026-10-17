use falcon512_account::verifier::{public_key_commitment, verify};
use super::fixtures;

fn commitment() -> felt252 {
    public_key_commitment(fixtures::public_key().span()).unwrap()
}

/// Every case's expectation comes from falcon.py's reference `verify` (or is a format error).
#[test]
fn verifier_matches_reference_on_all_cases() {
    let c = commitment();
    let expected = fixtures::case_expected();
    let mut i = 0;
    while i != fixtures::N_CASES {
        let (msg, sig) = fixtures::case(i);
        assert!(verify(msg, c, sig.span()) == *expected.at(i), "case {}", i);
        i += 1;
    }
}

#[test]
fn valid_signatures_fail_under_another_key() {
    let other = public_key_commitment(fixtures::other_public_key().span()).unwrap();
    let mut i = 0;
    while i != 6 {
        let (msg, sig) = fixtures::case(i);
        assert!(!verify(msg, other, sig.span()));
        i += 1;
    }
}

#[test]
fn rejects_non_canonical_public_key() {
    let mut pk = fixtures::public_key();
    let mut bad: Array<felt252> = array![];
    // low u128 half set to exactly q^9: one past the largest canonical 9-digit half
    let v: u256 = (*pk.at(0)).into();
    bad.append(v.high.into() * 0x100000000000000000000000000000000 + 6392178558614694273495691177456939009);
    let mut i = 1;
    while i != 29 {
        bad.append(*pk.at(i));
        i += 1;
    }
    assert!(public_key_commitment(bad.span()).is_none());
    let _ = pk.pop_front();
    assert!(public_key_commitment(pk.span()).is_none());
}

#[test]
fn bench_verify() {
    let (msg, sig) = fixtures::case(0);
    assert!(verify(msg, commitment(), sig.span()));
}
