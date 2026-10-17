use falcon512_account::verifier::{transformed_public_key, verify};
use super::fixtures;

/// Every case's expectation comes from falcon.py's reference `verify` (or is a format error).
#[test]
fn verifier_matches_reference_on_all_cases() {
    let ntt_h = fixtures::ntt_h();
    let expected = fixtures::case_expected();
    let mut i = 0;
    while i != fixtures::N_CASES {
        let (msg, sig) = fixtures::case(i);
        assert!(verify(msg, ntt_h.span(), sig.span()) == *expected.at(i), "case {}", i);
        i += 1;
    }
}

#[test]
fn valid_signatures_fail_under_another_key() {
    let other = fixtures::other_ntt_h();
    let mut i = 0;
    while i != 6 {
        let (msg, sig) = fixtures::case(i);
        assert!(!verify(msg, other.span(), sig.span()));
        i += 1;
    }
}

#[test]
fn transform_matches_signer_and_rejects_non_canonical_key() {
    assert!(transformed_public_key(fixtures::public_key().span()).unwrap() == fixtures::ntt_h());
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
    assert!(transformed_public_key(bad.span()).is_none());
    let _ = pk.pop_front();
    assert!(transformed_public_key(pk.span()).is_none());
}

#[test]
fn bench_verify() {
    let (msg, sig) = fixtures::case(0);
    assert!(verify(msg, fixtures::ntt_h().span(), sig.span()));
}
