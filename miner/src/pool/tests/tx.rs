// Copyright 2018-2020 Origo Foundation.
// This file is part of Origo Network.

// Origo Network is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Origo Network is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Origo Network.  If not, see <http://www.gnu.org/licenses/>.

use ethereum_types::{U256, H256, H160,  Address};
use ethkey::{Random, Generator};
use rustc_hex::FromHex;
use types::transaction::{self, Transaction, SignedTransaction, UnverifiedTransaction};

use pool::{verifier, VerifiedTransaction};

use ff::PrimeField;
use zcash_primitives::transaction::components::{OutputDescription, SpendDescription, GROTH_PROOF_SIZE};
use sapling_crypto::{
	jubjub::{edwards, Unknown, JubjubBls12},
	redjubjub::{PublicKey, Signature},
};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use std::thread::sleep;
use std::intrinsics::transmute;

#[derive(Clone)]
pub struct Tx {
	pub nonce: u64,
	pub gas: u64,
	pub gas_price: u64,
}

#[derive(Clone)]
pub struct PrivateTx {
	// The nonce should be used for private
	pub gas: u64,
	pub gas_price: u64,
	pub nullifiers: Vec<u8>,
	pub balance: i64,
	pub action: transaction::Action,
}

impl Default for Tx {
	fn default() -> Self {
		Tx {
			nonce: 123,
			gas: 21_000,
			gas_price: 1_000_000,
		}
	}
}

impl Default for PrivateTx {
	fn default() -> Self {
		PrivateTx {
			gas: 21_000,
			gas_price: 1,
			nullifiers: vec![],
			balance: 10.into(),
			action: transaction::Action::Create,
		}
	}
}

impl Tx {
	pub fn gas_price(gas_price: u64) -> Self {
		Tx {
			gas_price,
			..Default::default()
		}
	}

	pub fn signed(self) -> SignedTransaction {
		let keypair = Random.generate().unwrap();
		self.unsigned().sign(keypair.secret(), None)
	}

	pub fn signed_pair(self) -> (SignedTransaction, SignedTransaction) {
		let (tx1, tx2, _) = self.signed_triple();
		(tx1, tx2)
	}

	pub fn signed_triple(mut self) -> (SignedTransaction, SignedTransaction, SignedTransaction) {
		let keypair = Random.generate().unwrap();
		let tx1 = self.clone().unsigned().sign(keypair.secret(), None);
		self.nonce += 1;
		let tx2 = self.clone().unsigned().sign(keypair.secret(), None);
		self.nonce += 1;
		let tx3 = self.unsigned().sign(keypair.secret(), None);

		(tx1, tx2, tx3)
	}

	pub fn signed_replacement(mut self) -> (SignedTransaction, SignedTransaction) {
		let keypair = Random.generate().unwrap();
		let tx1 = self.clone().unsigned().sign(keypair.secret(), None);
		self.gas_price += 1_000_000;
		let tx2 = self.unsigned().sign(keypair.secret(), None);

		(tx1, tx2)
	}

	pub fn unsigned(self) -> Transaction {
		Transaction {
			action: transaction::Action::Create,
			value: U256::from(1_000_000_000),
			data: "3331600055".from_hex().unwrap(),
			gas: self.gas.into(),
			gas_price: self.gas_price.into(),
			nonce: self.nonce.into(),
			private: None,
		}
	}

	pub fn big_one(self) -> SignedTransaction {
		let keypair = Random.generate().unwrap();
		let tx = Transaction {
			action: transaction::Action::Create,
			value: U256::from(100),
			data: include_str!("../res/big_transaction.data").from_hex().unwrap(),
			gas: self.gas.into(),
			gas_price: self.gas_price.into(),
			nonce: self.nonce.into(),
			private: None,
		};
		tx.sign(keypair.secret(), None)
	}
}

impl PrivateTx {
	pub fn instance(nullifiers: Vec<u8>, gas_price: u64, action: transaction::Action) -> Self {
		PrivateTx {
			nullifiers,
			gas_price,
			action,
			..Default::default()
		}
	}

	pub fn signed(self) -> SignedTransaction {
		match self.action {
			transaction::Action::PublicToPrivate => {
				let keypair = Random.generate().unwrap();
				self.unsigned().sign(keypair.secret(), None)
			}
			_ => self.unsigned().sign_for_private(0),
		}
	}

	pub fn signed_pair(mut self) -> (SignedTransaction, SignedTransaction) {
		let keypair = Random.generate().unwrap();
		let tx1 = match self.action {
			transaction::Action::PublicToPrivate => self.clone().unsigned().sign(keypair.secret(), None),
			_ => self.clone().unsigned().sign_for_private(0),
		};
		self.balance += 10;
		let tx2 = match self.action {
			transaction::Action::PublicToPrivate => self.clone().unsigned().sign(keypair.secret(), None),
			_ => self.clone().unsigned().sign_for_private(0),
		};
		(tx1, tx2)
	}

	pub fn unsigned(self) -> Transaction {
		let mut spends: Vec<SpendDescription> = vec![];
		for nullifier in self.nullifiers {
			let spend = SpendDescription {
				cv : edwards::Point::zero(),
				anchor : Fr::from_repr(FrRepr::from(0)).unwrap(),
				nullifier: [nullifier.clone(); 32],
				rk: PublicKey::read(&[0u8; 64][..], &JubjubBls12::new()).unwrap(),
				zkproof: [1u8; GROTH_PROOF_SIZE],
				spend_auth_sig: Some(Signature::read(&[0u8; 64][..]).unwrap()),
			};
			spends.push(spend);
		}

		Transaction {
			action: self.action,
			value: U256::from(100),
			data: "3331600055".from_hex().unwrap(),
			gas: self.gas.into(),
			gas_price: self.gas_price.into(),
			nonce: 123.into(),
			private: Some(transaction::PrivateTransaction {
				spends: spends,
				outputs: vec!{},
				balancing_value: self.balance,
				binding_sig: [1u8; 64]}),
		}
	}
}

pub trait TxExt: Sized {
	type Out;
	type Verified;
	type Hash;

	fn hash(&self) -> Self::Hash;

	fn local(self) -> Self::Out;

	fn retracted(self) -> Self::Out;

	fn unverified(self) -> Self::Out;

	fn verified(self) -> Self::Verified;
}

impl<A, B, O, V, H> TxExt for (A, B) where
	A: TxExt<Out=O, Verified=V, Hash=H>,
	B: TxExt<Out=O, Verified=V, Hash=H>,
{
	type Out = (O, O);
	type Verified = (V, V);
	type Hash = (H, H);

	fn hash(&self) -> Self::Hash { (self.0.hash(), self.1.hash()) }
	fn local(self) -> Self::Out { (self.0.local(), self.1.local()) }
	fn retracted(self) -> Self::Out { (self.0.retracted(), self.1.retracted()) }
	fn unverified(self) -> Self::Out { (self.0.unverified(), self.1.unverified()) }
	fn verified(self) -> Self::Verified { (self.0.verified(), self.1.verified()) }
}

impl TxExt for SignedTransaction {
	type Out = verifier::Transaction;
	type Verified = VerifiedTransaction;
	type Hash = H256;

	fn hash(&self) -> Self::Hash {
		UnverifiedTransaction::hash(self)
	}

	fn local(self) -> Self::Out {
		verifier::Transaction::Local(self.into())
	}

	fn retracted(self) -> Self::Out {
		verifier::Transaction::Retracted(self.into())
	}

	fn unverified(self) -> Self::Out {
		verifier::Transaction::Unverified(self.into())
	}

	fn verified(self) -> Self::Verified {
		VerifiedTransaction::from_pending_block_transaction(self)
	}
}

impl TxExt for Vec<SignedTransaction> {
	type Out = Vec<verifier::Transaction>;
	type Verified = Vec<VerifiedTransaction>;
	type Hash = Vec<H256>;

	fn hash(&self) -> Self::Hash {
		self.iter().map(|tx| tx.hash()).collect()
	}

	fn local(self) -> Self::Out {
		self.into_iter().map(Into::into).map(verifier::Transaction::Local).collect()
	}

	fn retracted(self) -> Self::Out {
		self.into_iter().map(Into::into).map(verifier::Transaction::Retracted).collect()
	}

	fn unverified(self) -> Self::Out {
		self.into_iter().map(Into::into).map(verifier::Transaction::Unverified).collect()
	}

	fn verified(self) -> Self::Verified {
		self.into_iter().map(VerifiedTransaction::from_pending_block_transaction).collect()
	}
}

pub trait PairExt {
	type Type;

	fn into_vec(self) -> Vec<Self::Type>;
}

impl<A> PairExt for (A, A) {
	type Type = A;
	fn into_vec(self) -> Vec<A> {
		vec![self.0, self.1]
	}
}
