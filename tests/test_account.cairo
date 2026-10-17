use falcon512_account::account::{
    IFalcon512AccountDispatcher, IFalcon512AccountDispatcherTrait, ISRC5_ID, ISRC6_ID,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_signature_global,
    start_cheat_transaction_hash_global,
};
use starknet::ClassHash;
use super::fixtures;

fn key_class(name: ByteArray) -> ClassHash {
    *declare(name).unwrap().contract_class().class_hash
}

fn deploy_with(key: ClassHash) -> Result<IFalcon512AccountDispatcher, Array<felt252>> {
    let class = declare("Falcon512Account").unwrap().contract_class();
    let mut calldata: Array<felt252> = array![];
    fixtures::public_key().serialize(ref calldata);
    key.serialize(ref calldata);
    let (address, _) = class.deploy(@calldata)?;
    Ok(IFalcon512AccountDispatcher { contract_address: address })
}

fn deploy() -> IFalcon512AccountDispatcher {
    deploy_with(key_class("Falcon512KeyFixture")).unwrap()
}

#[test]
fn constructor_stores_key_class_and_interfaces() {
    let key = key_class("Falcon512KeyFixture");
    let a = deploy_with(key).unwrap();
    assert!(a.get_key_class() == key);
    assert!(a.supports_interface(ISRC5_ID) && a.supports_interface(ISRC6_ID));
    assert!(!a.supports_interface(0x1234));
}

#[test]
fn constructor_rejects_key_class_of_another_key() {
    assert!(deploy_with(key_class("Falcon512KeyOther")).is_err());
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
