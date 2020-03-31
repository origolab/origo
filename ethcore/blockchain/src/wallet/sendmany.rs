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

use pairing::bls12_381::{Bls12, Fr, FrRepr};

use ff::PrimeField;

use ethereum_types::U256;
use sapling_crypto::{
	jubjub::fs::Fs,
	primitives::{Diversifier, Note, PaymentAddress},
};
use std::cmp::Eq;
use std::collections::LinkedList;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use zcash_primitives::{
	merkle_tree::{CommitmentTree, CommitmentTreeWitness},
	note_encryption::Memo,
	sapling::Node,
};

use crate::wallet::key_store::{
	decode_destination, decode_payment_address, KeyStore, TxDestination,
};
use crate::wallet::transaction_builder::{Error, ErrorKind, TransactionBuilder};
use crate::wallet::wallet::Wallet;
use crate::wallet::wallet_types::{
	SaplingCommitmentTreeWitness, SaplingExpandedSpendingKey, SaplingExtendedSpendingKey,
	SaplingIncomingViewingKey, SaplingNote, SaplingOutgoingViewingKey, SaplingPaymentAddress,
	SaplingWitness, TxHash,
};
use common_types::transaction::{Transaction as CommonTransaction, CONVERSION_FACTOR};
use std::sync::RwLock;

/// SpendDescriptionInfo contains all the information required to generate a SpendDescription.
pub struct SpendDescriptionInfo {
	pub expsk: SaplingExpandedSpendingKey,
	pub diversifier: Diversifier,
	pub note: SaplingNote,
	pub alpha: Fs,
	/// Anchor refers to the output Sapling treestate of a previous block.
	pub anchor: Fr,
	pub witness: CommitmentTreeWitness<Node>,
}

/// OutputDescriptionInfo contains all the required information to create a OutputDescription.
pub struct OutputDescriptionInfo {
	pub ovk: SaplingOutgoingViewingKey,
	pub to: PaymentAddress<Bls12>,
	pub note: SaplingNote,
	/// Memo represents a 512-byte memo field associated with note.
	/// It is used by agreement between the sender and recipient of the note.
	pub memo: Memo,
}

#[derive(Clone)]
pub struct SaplingNoteData {
	// The address for the note.
	pub address: SaplingPaymentAddress,
	// The decryption note data.
	pub note: SaplingNote,
	// The decryption note memo.
	pub memo: Memo,
	// The note witness for the note.
	pub witnesses: LinkedList<SaplingWitness>,
	// The block number for the block to create the note.
	pub createHeight: u64,
	// The current block number when create the transaction using the note.
	pub spendHeight: Option<u64>,
	// The block number for the block to confirm the transaction using the note.
	pub confirmHeight: Option<u64>,
	pub ivk: SaplingIncomingViewingKey,
	pub nullifier: Option<U256>,
	// The hash for the transaction to create the note.
	pub hash: TxHash,
	// The note index in the transaction's output.
	pub index: usize,
}

impl SaplingNoteData {
	pub fn new(
		address: SaplingPaymentAddress,
		note: SaplingNote,
		memo: Memo,
		block_number: u64,
		ivk: SaplingIncomingViewingKey,
		nullifier: U256,
		hash: TxHash,
		number: usize,
	) -> Self {
		SaplingNoteData {
			address,
			note,
			memo,
			witnesses: LinkedList::new(),
			createHeight: block_number,
			spendHeight: None,
			confirmHeight: None,
			ivk: ivk,
			nullifier: Some(nullifier),
			hash,
			index: number,
		}
	}
	pub fn push_front(&mut self, witness: SaplingWitness) {
		self.witnesses.push_front(witness);
	}

	pub fn pop_back(&mut self) {
		self.witnesses.pop_back();
	}

	pub fn front(&self) -> Option<SaplingWitness> {
		self.witnesses.front().map(|head| head.clone())
	}
}

#[derive(Clone)]
pub struct SaplingNoteEntry {
	pub hash: TxHash,
	pub index: usize,
	/// PaymentAddress not sure is Bls12
	pub address: PaymentAddress<Bls12>,
	pub witness: SaplingWitness,
	pub note: Note<Bls12>,
	pub memo: Memo,
	pub confirmation: i64,
}

pub type CAmount = u64;

pub type SendManyRecipient = (String, U256, String);

pub struct SendMany {
	pub main_wallet: Arc<RwLock<Wallet>>,
}

pub struct SendManyInputs {
	/// Could be private or public address.
	pub from: String,
	// The amount of value the comes from public account.
	pub value_from_public: U256,
	/// Private Recipients.
	pub shield_to: Vec<SendManyRecipient>,
	/// Public recipients, at most 1.
	pub to: Vec<SendManyRecipient>,
	pub min_conf: u32,
	pub gas_price: U256,
	pub nonce: U256,
	pub gas: U256,
	pub data: Vec<u8>,
	pub chain_id: u64,
}

impl SendMany {
	pub fn new(wallet: Arc<RwLock<Wallet>>) -> SendMany {
		SendMany {
			main_wallet: wallet,
		}
	}

	pub fn pre_send_many(
		&mut self,
		inputs: &SendManyInputs,
		pass: String,
	) -> Result<CommonTransaction, Error> {
		let mut key_store = &self.main_wallet.read().unwrap().key_store;
		let (payment_address, spending_key_option) =
			key_store.decode_z_destination(&inputs.from, pass);

		//TODO
		let next_block_height = 0;
		{
			let builder = TransactionBuilder::new(
				inputs.gas_price,
				inputs.nonce,
				inputs.gas,
				inputs.data.clone(),
				inputs.chain_id,
			);
			let expsk: Option<SaplingExpandedSpendingKey> = spending_key_option
				.and_then(|spending_key: SaplingExtendedSpendingKey| Some(spending_key.expsk));

			if (expsk.is_none()) {
				return Err(Error(ErrorKind::NoPrivateKey));
			}

			let mut sendmany_operation = SendManyOperation::new(
				inputs.value_from_public,
				builder,
				self.main_wallet.clone(),
				inputs.from.clone(),
				inputs.to.clone(),
				inputs.shield_to.clone(),
				inputs.min_conf,
				expsk.unwrap(),
			);

			sendmany_operation.main_impl(inputs.gas, inputs.gas_price)
		}
	}
}

pub struct SendManyOperation {
	/// The amount of value the comes from public account.
	value_from_public: U256,
	t_outputs_: Vec<SendManyRecipient>,
	z_outputs_: Vec<SendManyRecipient>,
	transaction_builder_: TransactionBuilder,
	wallet: Arc<RwLock<Wallet>>,
	spendingkey_: SaplingExpandedSpendingKey,
	mindepth: u32,
	fromaddress_: String,
}

impl SendManyOperation {
	fn new(
		value_from_public: U256,
		builder: TransactionBuilder,
		wallet: Arc<RwLock<Wallet>>,
		fromaddress: String,
		t_outputs: Vec<SendManyRecipient>,
		z_outputs: Vec<SendManyRecipient>,
		min_depth: u32,
		spendingkey_: SaplingExpandedSpendingKey,
	) -> Self {
		SendManyOperation {
			value_from_public,
			transaction_builder_: builder,
			wallet,
			fromaddress_: fromaddress,
			t_outputs_: t_outputs,
			z_outputs_: z_outputs,
			mindepth: min_depth,
			spendingkey_: spendingkey_,
		}
	}

	fn find_unspent_notes(&mut self, target_amout: U256) -> Result<Vec<SaplingNoteEntry>, Error> {
		let wallet = self.wallet.read().unwrap();
		let sapling_entries = wallet.get_filtered_address_notes(&self.fromaddress_);
		let mut input_sapling_notes: Vec<SaplingNoteEntry> = vec![];
		let mut sum: U256 = U256::from(0);
		for entry in sapling_entries.iter() {
			input_sapling_notes.push((*entry).clone());
			sum = sum + U256::from(entry.note.value) * CONVERSION_FACTOR;
			if sum >= target_amout {
				break;
			}
		}
		if sum < target_amout {
			return Err(Error(ErrorKind::InsufficientBalance(sum.to_string())));
		} else {
			Ok(input_sapling_notes)
		}
		//TODO, sort from bigger value to small value
	}

	pub fn main_impl(&mut self, gas: U256, gas_price: U256) -> Result<CommonTransaction, Error> {
		let mut target_amount = self.z_outputs_.iter().fold(U256::from(0), |mut total: U256, recipient| {
			total += recipient.1;
			total
		});
		target_amount += self.t_outputs_.iter().fold(U256::from(0), |mut total: U256, recipient| {
			total += recipient.1;
			total
		});

		// Add transparent inputs.
		if !self.value_from_public.is_zero() {
			self.transaction_builder_
				.set_public_input(self.value_from_public);
		} else {
			// Add sapling spends.
			let input_sapling_notes = self.find_unspent_notes(target_amount + gas * gas_price)?;
			for saplingNoteEntry in input_sapling_notes.iter() {
				let anchor = saplingNoteEntry.witness.root();
				let witness = saplingNoteEntry.witness.path();
				self.transaction_builder_.add_sapling_spend(
					self.spendingkey_.clone(),
					saplingNoteEntry.address.diversifier.clone(),
					saplingNoteEntry.note.clone(),
					Fr::from(anchor),
					witness.unwrap(),
				)?;
			}
		}

		let ovk = self.spendingkey_.ovk;
		for (address, value, memo) in self.z_outputs_.iter() {
			let to = decode_payment_address(address);
			if to.is_some() {
				self.transaction_builder_.add_sapling_output(
					ovk.clone(),
					to.unwrap(),
					&value,
					&memo,
				)?;
			} else {
				println!("decode_payment_address failed, address = {0}", address);
			}
		}

		// Add transparent outputs.
		for (address, amount, _) in self.t_outputs_.iter() {
			let addr = decode_destination(address);
			self.transaction_builder_
				.set_public_output(addr.unwrap(), &amount);
			// There should be only one public output.
			break;
		}

		self.transaction_builder_.build()
	}
}
