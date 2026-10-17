// Portions derived from OpenZeppelin cairo-pq-verifiers (MIT License, Copyright (c) 2026 OpenZeppelin).
//! Falcon-512 account (SNIP-6 / SRC5).
//!
//! The constructor takes the canonical 29-felt public key and stores only its commitment
//! commit(NTT(H)); every signature carries NTT(H) (see `verifier`). Transaction flow mirrors the
//! OpenZeppelin account: `__execute__` only from the protocol, transaction version >= 1, and
//! `__validate__` / `__validate_declare__` / `__validate_deploy__` verify the transaction hash.

use starknet::account::Call;

pub const ISRC5_ID: felt252 = 0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055;
pub const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;

#[starknet::interface]
pub trait IFalcon512Account<TState> {
    fn __execute__(self: @TState, calls: Array<Call>);
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn __validate_deploy__(
        self: @TState,
        class_hash: felt252,
        contract_address_salt: felt252,
        public_key: Array<felt252>,
    ) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
    fn get_public_key_commitment(self: @TState) -> felt252;
}

#[starknet::contract(account)]
pub mod Falcon512Account {
    use core::num::traits::Zero;
    use starknet::SyscallResultTrait;
    use starknet::account::Call;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use crate::verifier;
    use super::{ISRC5_ID, ISRC6_ID};

    const MIN_TRANSACTION_VERSION: u256 = 1;
    const QUERY_OFFSET: u256 = 0x100000000000000000000000000000000;

    #[storage]
    struct Storage {
        public_key_commitment: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: Array<felt252>) {
        let commitment = verifier::public_key_commitment(public_key.span())
            .expect('Falcon: invalid public key');
        self.public_key_commitment.write(commitment);
    }

    #[abi(embed_v0)]
    impl AccountImpl of super::IFalcon512Account<ContractState> {
        fn __execute__(self: @ContractState, calls: Array<Call>) {
            assert(starknet::get_caller_address().is_zero(), 'Account: invalid caller');
            assert_valid_tx_version();
            for call in calls.span() {
                let Call { to, selector, calldata } = *call;
                starknet::syscalls::call_contract_syscall(to, selector, calldata).unwrap_syscall();
            }
        }

        fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
            let _ = calls;
            self.validate_transaction()
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let _ = class_hash;
            self.validate_transaction()
        }

        fn __validate_deploy__(
            self: @ContractState,
            class_hash: felt252,
            contract_address_salt: felt252,
            public_key: Array<felt252>,
        ) -> felt252 {
            let _ = (class_hash, contract_address_salt, public_key);
            self.validate_transaction()
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if verifier::verify(hash, self.public_key_commitment.read(), signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            interface_id == ISRC5_ID || interface_id == ISRC6_ID
        }

        fn get_public_key_commitment(self: @ContractState) -> felt252 {
            self.public_key_commitment.read()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn validate_transaction(self: @ContractState) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            let valid = verifier::verify(
                tx_info.transaction_hash, self.public_key_commitment.read(), tx_info.signature,
            );
            assert(valid, 'Account: invalid signature');
            starknet::VALIDATED
        }
    }

    fn assert_valid_tx_version() {
        let tx_version: u256 = starknet::get_tx_info().unbox().version.into();
        if tx_version >= QUERY_OFFSET {
            assert(QUERY_OFFSET + MIN_TRANSACTION_VERSION <= tx_version, 'Account: invalid tx version');
        } else {
            assert(MIN_TRANSACTION_VERSION <= tx_version, 'Account: invalid tx version');
        }
    }
}
