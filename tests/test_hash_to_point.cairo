use falcon512_account::hash_to_point::hash_to_point;
use super::fixtures;

#[test]
fn hash_to_point_8_permutations_matches_shake256() {
    let w = hash_to_point(
        fixtures::h2p_8_msg(),
        fixtures::h2p_8_salt_a(),
        fixtures::h2p_8_salt_b(),
        fixtures::h2p_8_mid().span(),
    )
        .unwrap();
    assert!(w.span().slice(0, 512) == fixtures::h2p_8_words().span());
}

#[test]
fn hash_to_point_9_permutations_matches_shake256() {
    let w = hash_to_point(
        fixtures::h2p_9_msg(),
        fixtures::h2p_9_salt_a(),
        fixtures::h2p_9_salt_b(),
        fixtures::h2p_9_mid().span(),
    )
        .unwrap();
    assert!(w.span().slice(0, 512) == fixtures::h2p_9_words().span());
}

#[test]
fn hash_to_point_rejects_oversized_salt() {
    let mid = fixtures::h2p_8_mid();
    assert!(hash_to_point(1, 0x10000000000000000000000000000000000000000, 0, mid.span()).is_none());
    assert!(hash_to_point(1, 0, 0x10000000000000000000000000000000000000000, mid.span()).is_none());
}

/// Every lane of the supplied S4 is checked: flip one bit in each of the 25 lanes in turn.
#[test]
fn hash_to_point_rejects_any_wrong_mid_state_lane() {
    let mid = fixtures::h2p_8_mid();
    let mut lane: u32 = 0;
    while lane != 25 {
        let mut bad: Array<felt252> = array![];
        let mut j = 0;
        while j != 9 {
            let mut v = *mid.at(j);
            if j == lane / 3 {
                let mut bit: felt252 = 1;
                let mut t = 0;
                while t != (lane % 3) * 64 + lane {
                    bit *= 2;
                    t += 1;
                }
                let x: u256 = v.into();
                let b: u256 = bit.into();
                v = (x ^ b).try_into().unwrap();
            }
            bad.append(v);
            j += 1;
        }
        assert!(
            hash_to_point(
                fixtures::h2p_8_msg(),
                fixtures::h2p_8_salt_a(),
                fixtures::h2p_8_salt_b(),
                bad.span(),
            )
                .is_none(),
            "lane {}",
            lane,
        );
        lane += 1;
    }
}

#[test]
fn hash_to_point_rejects_malformed_mid_state() {
    let (m, a, b) = (fixtures::h2p_8_msg(), fixtures::h2p_8_salt_a(), fixtures::h2p_8_salt_b());
    let mid = fixtures::h2p_8_mid();
    // wrong length
    assert!(hash_to_point(m, a, b, mid.span().slice(0, 8)).is_none());
    // a felt >= 2^192, and a last felt >= 2^64
    let mut bad = array![*mid.at(0) + 0x1000000000000000000000000000000000000000000000000];
    bad.append_span(mid.span().slice(1, 8));
    assert!(hash_to_point(m, a, b, bad.span()).is_none());
    let mut bad: Array<felt252> = array![];
    bad.append_span(mid.span().slice(0, 8));
    bad.append(*mid.at(8) + 0x10000000000000000);
    assert!(hash_to_point(m, a, b, bad.span()).is_none());
}
