use falcon512_account::account::{
    IFalcon512AccountDispatcher, IFalcon512AccountDispatcherTrait, ISRC5_ID, ISRC6_ID,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_signature_global,
    start_cheat_transaction_hash_global,
};
use super::fixtures;

fn deploy() -> IFalcon512AccountDispatcher {
    let class = declare("Falcon512Account").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![];
    fixtures::public_key().serialize(ref calldata);
    let (address, _) = class.deploy(@calldata).unwrap();
    IFalcon512AccountDispatcher { contract_address: address }
}

#[test]
fn constructor_stores_public_key_and_interfaces() {
    let a = deploy();
    assert!(a.get_public_key() == fixtures::public_key());
    assert!(a.supports_interface(ISRC5_ID) && a.supports_interface(ISRC6_ID));
    assert!(!a.supports_interface(0x1234));
}

#[test]
fn is_valid_signature() {
    let a = deploy();
    let (msg, sig) = fixtures::case(0);
    assert!(a.is_valid_signature(msg, sig.clone()) == starknet::VALIDATED);
    assert!(a.is_valid_signature(msg + 1, sig) == 0);
}

#[test]
fn validate_accepts_signed_transaction() {
    let a = deploy();
    let (msg, sig) = fixtures::case(1);
    start_cheat_transaction_hash_global(msg);
    start_cheat_signature_global(sig.span());
    assert!(a.__validate__(array![]) == starknet::VALIDATED);
}

#[test]
#[should_panic]
fn validate_rejects_bad_signature() {
    let a = deploy();
    let (msg, sig) = fixtures::case(1);
    start_cheat_transaction_hash_global(msg + 1);
    start_cheat_signature_global(sig.span());
    a.__validate__(array![]);
}

#[test]
#[should_panic]
fn constructor_rejects_non_canonical_key() {
    let class = declare("Falcon512Account").unwrap().contract_class();
    let mut pk = fixtures::public_key();
    let _ = pk.pop_front();
    let mut calldata: Array<felt252> = array![];
    pk.serialize(ref calldata);
    let (_address, _) = class.deploy(@calldata).unwrap();
}
