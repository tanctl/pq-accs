use falcon512_account::hash_to_point::hash_to_point;
use super::fixtures;

#[test]
fn hash_to_point_8_permutations_matches_shake256() {
    let w = hash_to_point(fixtures::h2p_8_msg(), fixtures::h2p_8_salt_a(), fixtures::h2p_8_salt_b())
        .unwrap();
    assert!(w.span().slice(0, 512) == fixtures::h2p_8_words().span());
}

#[test]
fn hash_to_point_9_permutations_matches_shake256() {
    let w = hash_to_point(fixtures::h2p_9_msg(), fixtures::h2p_9_salt_a(), fixtures::h2p_9_salt_b())
        .unwrap();
    assert!(w.span().slice(0, 512) == fixtures::h2p_9_words().span());
}

#[test]
fn hash_to_point_rejects_oversized_salt() {
    assert!(hash_to_point(1, 0x10000000000000000000000000000000000000000, 0).is_none());
    assert!(hash_to_point(1, 0, 0x10000000000000000000000000000000000000000).is_none());
}
