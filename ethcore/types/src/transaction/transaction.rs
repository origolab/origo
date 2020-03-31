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

//! Transaction data structure.

use std::ops::Deref;

use ethereum_types::{Address, H160, H256, H512, U256};
use ethjson;
use ethkey::{self, public_to_address, recover, Public, Secret, Signature};
use hash::keccak;
use heapsize::HeapSizeOf;
use ff::PrimeField;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use rlp::{self, DecoderError, Encodable, Rlp, RlpStream};
use sapling_crypto::{
	jubjub::{edwards, JubjubBls12, Unknown},
	redjubjub::PublicKey,
};
use std::fmt;
use zcash_primitives::transaction::components::{
	OutputDescription, SpendDescription, GROTH_PROOF_SIZE,
};

use ethkey::{Generator, Random};

use ids::BlockId::Hash;
use std::collections::HashSet;
use std::sync::atomic::Ordering::AcqRel;
use transaction::error;
use transaction::error::PrivateTxError;
use zcash_primitives::merkle_tree::Hashable;

type Bytes = Vec<u8>;
type BlockNumber = u64;

/// Fake address for unsigned transactions as defined by EIP-86.
pub const UNSIGNED_SENDER: Address = H160([0xff; 20]);

/// System sender address for internal state updates.
pub const SYSTEM_ADDRESS: Address = H160([
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfe,
]);

/// Private address used in executive.
pub const PRIVATE_EXECUTIVE_ADDRESS: Address = H160([
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xfd,
]);
/// Conversion factor between public value and private balancing_value: 10^9.
pub const CONVERSION_FACTOR: U256 = U256([0x3B9ACA00, 0x0, 0x0, 0x0]);

/// Max value allowed to send: (2^63-1) * (10^9)
pub const MAX_VALUE_ALLOWED: U256 = U256([0xFFFFFFFFC4653600, 0x1DCD64FF, 0x0, 0x0]);

/// Transaction action type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
	/// Create creates new contract.
	Create,
	/// Calls contract at given address.
	/// In the case of a transfer, this is the receiver's address.'
	Call(Address),
	/// Transfers balance from private to private.
	PrivateToPrivate,
	/// Transfers balance from public to private.
	PublicToPrivate,
	/// Call contract from private input.
	/// In the case of a transfer, transfers to receiver's address from private input.
	PrivateCall(Address),
}

impl Action {
	pub fn is_input_private(&self) -> bool {
		match self {
			Action::PrivateToPrivate | Action::PrivateCall(_) => true,
			_ => false,
		}
	}
}

impl Default for Action {
	fn default() -> Action {
		Action::Create
	}
}

impl rlp::Decodable for Action {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		if rlp.is_empty() {
			Ok(Action::Create)
		} else if rlp.size() == 20 {
			Ok(Action::Call(rlp.as_val()?))
		} else if rlp.size() == 1 {
			let b: u8 = rlp.as_val()?;
			match b {
				1u8 => Ok(Action::PrivateToPrivate),
				2u8 => Ok(Action::PublicToPrivate),
				_ => Err(DecoderError::Custom("Invalid action.")),
			}
		} else if rlp.size() == 21 {
			let bytes: Vec<u8> = rlp.as_val()?;
			if bytes[0] == 3 {
				Ok(Action::PrivateCall(Address::from(&bytes[1..21])))
			} else {
				Err(DecoderError::Custom("Invalid action."))
			}
		} else {
			Err(DecoderError::RlpInvalidLength)
		}
	}
}

impl rlp::Encodable for Action {
	fn rlp_append(&self, s: &mut RlpStream) {
		match *self {
			Action::Create => s.append_internal(&""),
			Action::Call(ref addr) => s.append_internal(addr),
			Action::PrivateToPrivate => s.append_internal(&1u8),
			Action::PublicToPrivate => s.append_internal(&2u8),
			Action::PrivateCall(ref addr) => {
				let mut bytes = [3u8; 21];
				bytes[1..21].copy_from_slice(addr.as_ref());
				s.append_internal(&&bytes[..])
			}
		};
	}
}

/// Transaction activation condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
	/// Valid at this block number or later.
	Number(BlockNumber),
	/// Valid at this unix time or later.
	Timestamp(u64),
}

/// Replay protection logic for v part of transaction's signature
pub mod signature {
	/// Adds chain id into v
	pub fn add_chain_replay_protection(v: u64, chain_id: Option<u64>) -> u64 {
		v + if let Some(n) = chain_id {
			35 + n * 2
		} else {
			27
		}
	}

	/// Returns refined v
	/// 0 if `v` would have been 27 under "Electrum" notation, 1 if 28 or 4 if invalid.
	pub fn check_replay_protection(v: u64) -> u8 {
		match v {
			v if v == 27 => 0,
			v if v == 28 => 1,
			v if v >= 35 => ((v - 1) % 2) as u8,
			_ => 4,
		}
	}
}

/// Private transaction data.
#[derive(Clone)]
pub struct PrivateTransaction {
	pub spends: Vec<SpendDescription>,
	pub outputs: Vec<OutputDescription>,
	pub balancing_value: i64,
	pub binding_sig: [u8; 64],
}

impl fmt::Debug for PrivateTransaction {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		// fmt only supports array of max 32 length. So binding_sig is splitted into two parts.
		write!(
			f,
			"spends: {:?}, outputs: {:?}, balancing_value: {:?}, binding_sig: {:?} {:?}",
			self.spends,
			self.outputs,
			self.balancing_value,
			&&self.binding_sig[..32],
			&&self.binding_sig[32..],
		)
	}
}

impl PartialEq for PrivateTransaction {
	fn eq(&self, other: &Self) -> bool {
		self.spends == other.spends
			&& self.outputs == other.outputs
			&& self.balancing_value == other.balancing_value
			&& &self.binding_sig[..] == &other.binding_sig[..]
	}
}
impl Eq for PrivateTransaction {}

impl rlp::Decodable for PrivateTransaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		let u_bv: u64 = d.val_at(2)?;
		let binding_sig: H512 = d.val_at(3)?;
		let spends_vec: Vec<SpendDescription> = d.list_at(0)?;
		let outputs_vec: Vec<OutputDescription> = d.list_at(1)?;
		Ok(PrivateTransaction {
			spends: spends_vec,
			outputs: outputs_vec,
			balancing_value: u_bv as i64,
			binding_sig: binding_sig.into(),
		})
	}
}

impl rlp::Encodable for PrivateTransaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(4);
		s.append_list(&self.spends);
		s.append_list(&self.outputs);

		// Encodable is not implemented for i64 so we cast it u64.
		let bv_u = self.balancing_value.clone() as u64;
		s.append(&bv_u);

		let sig_h512 = H512::from(self.binding_sig);
		s.append(&sig_h512);
	}
}

impl PrivateTransaction {
	pub fn rlp_append_unsigned(&self, s: &mut RlpStream) {
		s.begin_list(4);
		s.begin_list(self.spends.len());
		for spend in self.spends.iter() {
			spend.rlp_append_unsigned(s);
		}
		s.append_list(&self.outputs);
		let bv_u = self.balancing_value.clone() as u64;
		s.append(&bv_u);
		s.append_empty_data();
	}
	// Create a dummy PrivateTransaction for testing purpose.
	pub fn create_private(nullifiers: Vec<u8>) -> Self {
		let mut spends: Vec<SpendDescription> = vec![];
		for nullifier in nullifiers {
			let spend = SpendDescription {
				cv: edwards::Point::zero(),
				anchor: Fr::from_repr(FrRepr::default()).unwrap(),
				nullifier: [nullifier.clone(); 32],
				rk: PublicKey::read(&[0u8; 64][..], &JubjubBls12::new()).unwrap(),
				zkproof: [1u8; GROTH_PROOF_SIZE],
				spend_auth_sig: Some(
					sapling_crypto::redjubjub::Signature::read(&[0u8; 64][..]).unwrap(),
				),
			};
			spends.push(spend);
		}

		PrivateTransaction {
			spends: spends,
			outputs: vec![],
			balancing_value: 10,
			binding_sig: [1u8; 64],
		}
	}
}

/// A set of information describing an externally-originating message call
/// or contract creation operation.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
	/// Nonce.
	pub nonce: U256,
	/// Gas price.
	pub gas_price: U256,
	/// Gas paid up front for transaction execution.
	pub gas: U256,
	/// Action, can be either call or contract create.
	pub action: Action,
	/// Transfered value.
	pub value: U256,
	/// Transaction data.
	pub data: Bytes,
	/// For private transaction.
	pub private: Option<PrivateTransaction>,
}

impl Transaction {
	/// Append object with a without signature into RLP stream
	pub fn rlp_append_unsigned_transaction(&self, s: &mut RlpStream, chain_id: Option<u64>) {
		let offset = if self.is_private() { 1 } else { 0 };
		s.begin_list(if chain_id.is_none() { 6 } else { 9 } + offset);
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		if let Some(ref private) = self.private {
			private.rlp_append_unsigned(s);
		}
		if let Some(n) = chain_id {
			s.append(&n);
			s.append(&0u8);
			s.append(&0u8);
		}
	}

	/// If this transaction involves private transaction.
	pub fn is_private(&self) -> bool {
		match self.private {
			Some(_) => true,
			None => false,
		}
	}

	/// If the transaction is private to private
	pub fn is_privacy(&self) -> bool {
		self.action == Action::PrivateToPrivate
	}

	/// If the transaction is public to private transaction
	pub fn is_shield(&self) -> bool {
		self.action == Action::PublicToPrivate
	}

	/// If the transaction is private to public
	pub fn is_unshield(&self) -> bool {
		match self.action {
			Action::PrivateCall(_) => true,
			_ => false,
		}
	}

	/// Get all the nullifier for the private transaction.
	pub fn get_nullifier_set(&self) -> HashSet<U256> {
		if let Some(ref private) = self.private {
			private
				.spends
				.iter()
				.map(|spend| U256::from(spend.nullifier))
				.collect::<HashSet<_>>()
		} else {
			HashSet::new()
		}
	}

	/// Get all the commitment notes for the private transaction.
	pub fn get_commitment_notes(&self) -> Vec<Fr> {
		if let Some(ref private) = self.private {
			private
				.outputs
				.iter()
				.map(|output| output.cmu)
				.collect::<Vec<_>>()
		} else {
			Vec::new()
		}
	}

	/// Get all the anchors for the private transaction.
	pub fn get_commitment_anchors(&self) -> Vec<Fr> {
		if let Some(ref private) = self.private {
			private
				.spends
				.iter()
				.map(|spend| spend.anchor)
				.collect::<Vec<_>>()
		} else {
			Vec::new()
		}
	}

	pub fn v_shielded_spend(&self) -> Vec<SpendDescription> {
		match self.private {
			Some(ref tx) => tx.spends.clone(),
			None => Vec::new(),
		}
	}

	pub fn v_shielded_output(&self) -> Vec<OutputDescription> {
		match self.private {
			Some(ref tx) => tx.outputs.clone(),
			None => Vec::new(),
		}
	}

	pub fn balancing_value(&self) -> i64 {
		match self.private {
			Some(ref tx) => tx.balancing_value,
			None => 0,
		}
	}

	pub fn binding_sig(&self) -> [u8; 64] {
		match self.private {
			Some(ref tx) => tx.binding_sig,
			None => [0; 64],
		}
	}
}

impl HeapSizeOf for Transaction {
	fn heap_size_of_children(&self) -> usize {
		self.data.heap_size_of_children()
	}
}

impl From<ethjson::state::Transaction> for SignedTransaction {
	fn from(t: ethjson::state::Transaction) -> Self {
		let to: Option<ethjson::hash::Address> = t.to.into();
		let secret = t.secret.map(|s| Secret::from(s.0));
		let tx = Transaction {
			nonce: t.nonce.into(),
			gas_price: t.gas_price.into(),
			gas: t.gas_limit.into(),
			action: match to {
				Some(to) => Action::Call(to.into()),
				None => Action::Create,
			},
			value: t.value.into(),
			data: t.data.into(),
			// TODO(xin): populate private.
			private: None,
		};
		match secret {
			Some(s) => tx.sign(&s, None),
			None => tx.null_sign(1),
		}
	}
}

impl From<ethjson::transaction::Transaction> for UnverifiedTransaction {
	fn from(t: ethjson::transaction::Transaction) -> Self {
		let to: Option<ethjson::hash::Address> = t.to.into();
		UnverifiedTransaction {
			unsigned: Transaction {
				nonce: t.nonce.into(),
				gas_price: t.gas_price.into(),
				gas: t.gas_limit.into(),
				action: match to {
					Some(to) => Action::Call(to.into()),
					None => Action::Create,
				},
				value: t.value.into(),
				data: t.data.into(),
				// TODO(xin): populate private.
				private: None,
			},
			r: t.r.into(),
			s: t.s.into(),
			v: t.v.into(),
			hash: 0.into(),
		}
		.compute_hash()
	}
}

impl Transaction {
	/// Create a transaction involved private field in unit test.
	pub fn create_private(nullifiers: Vec<u8>, nonce: U256, action: Action) -> Self {
		let mut spends: Vec<SpendDescription> = vec![];
		for nullifier in nullifiers {
			let spend = SpendDescription {
				cv: edwards::Point::zero(),
				anchor: Fr::from_repr(FrRepr::default()).unwrap(),
				nullifier: [nullifier.clone(); 32],
				rk: PublicKey::read(&[0u8; 64][..], &JubjubBls12::new()).unwrap(),
				zkproof: [1u8; GROTH_PROOF_SIZE],
				spend_auth_sig: Some(
					sapling_crypto::redjubjub::Signature::read(&[0u8; 64][..]).unwrap(),
				),
			};
			spends.push(spend);
		}

		let output1 = OutputDescription {
			cv: edwards::Point::zero(),
			cmu: Fr::from_repr(FrRepr::default()).unwrap(),
			ephemeral_key: edwards::Point::zero(),
			enc_ciphertext: [0u8; 580],
			out_ciphertext: [0u8; 80],
			zkproof: [0u8; GROTH_PROOF_SIZE],
		};

		let output2 = OutputDescription {
			cv: edwards::Point::zero(),
			cmu: Fr::from_repr(FrRepr::default()).unwrap(),
			ephemeral_key: edwards::Point::zero(),
			enc_ciphertext: [0u8; 580],
			out_ciphertext: [0u8; 80],
			zkproof: [0u8; GROTH_PROOF_SIZE],
		};

		Transaction {
			action: action,
			value: U256::zero(),
			data: b"Hello!".to_vec(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: nonce,
			private: Some(PrivateTransaction {
				spends: spends,
				outputs: vec![output1, output2],
				balancing_value: 0,
				binding_sig: [1u8; 64],
			}),
		}
	}

	/// create transaction for executor to settle
	pub fn create_executive_transaction(
		nullifiers: Vec<u8>,
		nonce: U256,
		action: Action,
		value: U256,
		gas: U256,
		gas_price: U256,
	) -> Self {
		let mut spends: Vec<SpendDescription> = vec![];
		for nullifier in nullifiers {
			let spend = SpendDescription {
				cv: edwards::Point::zero(),
				anchor: Fr::from_repr(FrRepr::default()).unwrap(),
				nullifier: [nullifier.clone(); 32],
				rk: PublicKey::read(&[0u8; 64][..], &JubjubBls12::new()).unwrap(),
				zkproof: [1u8; GROTH_PROOF_SIZE],
				spend_auth_sig: Some(
					sapling_crypto::redjubjub::Signature::read(&[0u8; 64][..]).unwrap(),
				),
			};
			spends.push(spend);
		}

		Transaction {
			action: action,
			value: value,
			data: b"".to_vec(),
			gas: gas,
			gas_price: gas_price,
			nonce: nonce,
			private: Some(PrivateTransaction {
				spends: spends,
				outputs: vec![],
				balancing_value: 10,
				binding_sig: [1u8; 64],
			}),
		}
	}

	/// The message hash of the transaction.
	pub fn hash(&self, chain_id: Option<u64>) -> H256 {
		let mut stream = RlpStream::new();
		self.rlp_append_unsigned_transaction(&mut stream, chain_id);
		keccak(stream.as_raw())
	}

	/// Signs the transaction as coming from `sender`.
	pub fn sign(self, secret: &Secret, chain_id: Option<u64>) -> SignedTransaction {
		let sig = ::ethkey::sign(secret, &self.hash(chain_id))
			.expect("data is valid and context has signing capabilities; qed");
		SignedTransaction::new(self.with_signature(sig, chain_id))
			.expect("secret is valid so it's recoverable")
	}

	/// Signs the private transaction as coming from `sender`.
	pub fn sign_for_private(self, chain_id: u64) -> SignedTransaction {
		let unverifiedTransaction = UnverifiedTransaction {
			unsigned: self,
			v: chain_id,
			r: U256::zero(),
			s: U256::zero(),
			hash: 0.into(),
		}
		.compute_hash();
		// Use the transaction hash for sender field.
		// Because the private transaction has no sender and in the miner pool,
		// all transactions will be stored in the transaction queue by the same sender field.
		// Therefore, we replace the sender field with the distinct transaction hash and would not
		// increase the nonce for this mocked sender.
		let mut address = H160::new();
		address
			.0
			.copy_from_slice(&unverifiedTransaction.hash[12..32]);
		SignedTransaction {
			transaction: unverifiedTransaction,
			sender: address,
			public: None,
		}
	}

	/// Signs the transaction with signature.
	pub fn with_signature(self, sig: Signature, chain_id: Option<u64>) -> UnverifiedTransaction {
		UnverifiedTransaction {
			unsigned: self,
			r: sig.r().into(),
			s: sig.s().into(),
			v: signature::add_chain_replay_protection(sig.v() as u64, chain_id),
			hash: 0.into(),
		}
		.compute_hash()
	}

	/// Useful for test incorrectly signed transactions.
	#[cfg(test)]
	pub fn invalid_sign(self) -> UnverifiedTransaction {
		UnverifiedTransaction {
			unsigned: self,
			r: U256::one(),
			s: U256::one(),
			v: 0,
			hash: 0.into(),
		}
		.compute_hash()
	}

	/// Specify the sender; this won't survive the serialize/deserialize process, but can be cloned.
	pub fn fake_sign(self, from: Address) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransaction {
				unsigned: self,
				r: U256::one(),
				s: U256::one(),
				v: 0,
				hash: 0.into(),
			}
			.compute_hash(),
			sender: from,
			public: None,
		}
	}

	/// Add EIP-86 compatible empty signature.
	pub fn null_sign(self, chain_id: u64) -> SignedTransaction {
		SignedTransaction {
			transaction: UnverifiedTransaction {
				unsigned: self,
				r: U256::zero(),
				s: U256::zero(),
				v: chain_id,
				hash: 0.into(),
			}
			.compute_hash(),
			sender: UNSIGNED_SENDER,
			public: None,
		}
	}
}

/// Signed transaction information without verified signature.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UnverifiedTransaction {
	/// Plain Transaction.
	pub unsigned: Transaction,
	/// The V field of the signature; the LS bit described which half of the curve our point falls
	/// in. The MS bits describe which chain this transaction is for. If 27/28, its for all chains.
	v: u64,
	/// The R field of the signature; helps describe the point on the curve.
	r: U256,
	/// The S field of the signature; helps describe the point on the curve.
	s: U256,
	/// Hash of the transaction
	hash: H256,
}

impl HeapSizeOf for UnverifiedTransaction {
	fn heap_size_of_children(&self) -> usize {
		self.unsigned.heap_size_of_children()
	}
}

impl Deref for UnverifiedTransaction {
	type Target = Transaction;

	fn deref(&self) -> &Self::Target {
		&self.unsigned
	}
}

impl rlp::Decodable for UnverifiedTransaction {
	fn decode(d: &Rlp) -> Result<Self, DecoderError> {
		if d.item_count()? != 9 && d.item_count()? != 10 {
			return Err(DecoderError::RlpIncorrectListLen);
		}
		let mut offset = 0;
		let mut private: Option<PrivateTransaction> = None;
		if d.item_count()? == 10 {
			private = Some(d.val_at(6)?);
			offset += 1;
		}
		let hash = keccak(d.as_raw());
		let mut action = d.val_at(3)?;

		Ok(UnverifiedTransaction {
			unsigned: Transaction {
				nonce: d.val_at(0)?,
				gas_price: d.val_at(1)?,
				gas: d.val_at(2)?,
				action: action,
				value: d.val_at(4)?,
				data: d.val_at(5)?,
				private: private,
			},
			v: d.val_at(6 + offset)?,
			r: d.val_at(7 + offset)?,
			s: d.val_at(8 + offset)?,
			hash: hash,
		})
	}
}

impl rlp::Encodable for UnverifiedTransaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		self.rlp_append_sealed_transaction(s)
	}
}

impl UnverifiedTransaction {
	/// Used to compute hash of created transactions
	fn compute_hash(mut self) -> UnverifiedTransaction {
		let hash = keccak(&*self.rlp_bytes());
		self.hash = hash;
		self
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.r.is_zero() && self.s.is_zero()
	}

	/// Append object with a signature into RLP stream
	fn rlp_append_sealed_transaction(&self, s: &mut RlpStream) {
		s.begin_list(9 + if self.is_private() { 1 } else { 0 });
		s.append(&self.nonce);
		s.append(&self.gas_price);
		s.append(&self.gas);
		s.append(&self.action);
		s.append(&self.value);
		s.append(&self.data);
		//println!("in rlp_append_sealed_transaction");
		if self.is_private() {
			//println!("in rlp_append_sealed_transaction 2");
			s.append(self.private.as_ref().unwrap());
		}
		s.append(&self.v);
		s.append(&self.r);
		s.append(&self.s);
	}

	///	Reference to unsigned part of this transaction.
	pub fn as_unsigned(&self) -> &Transaction {
		&self.unsigned
	}

	/// Returns standardized `v` value (0, 1 or 4 (invalid))
	pub fn standard_v(&self) -> u8 {
		signature::check_replay_protection(self.v)
	}

	/// The `v` value that appears in the RLP.
	pub fn original_v(&self) -> u64 {
		self.v
	}

	/// The chain ID, or `None` if this is a global transaction.
	pub fn chain_id(&self) -> Option<u64> {
		match self.v {
			v if self.is_unsigned() => Some(v),
			v if v >= 35 => Some((v - 35) / 2),
			_ => None,
		}
	}

	/// Construct a signature object from the sig.
	pub fn signature(&self) -> Signature {
		Signature::from_rsv(&self.r.into(), &self.s.into(), self.standard_v())
	}

	/// Checks whether the signature has a low 's' value.
	pub fn check_low_s(&self) -> Result<(), ethkey::Error> {
		if !self.signature().is_low_s() {
			Err(ethkey::Error::InvalidSignature.into())
		} else {
			Ok(())
		}
	}

	/// Get the hash of this transaction (keccak of the RLP).
	pub fn hash(&self) -> H256 {
		self.hash
	}

	/// Recovers the public key of the sender.
	pub fn recover_public(&self) -> Result<Public, ethkey::Error> {
		Ok(recover(
			&self.signature(),
			&self.unsigned.hash(self.chain_id()),
		)?)
	}

	/// Verify basic signature params. Does not attempt sender recovery.
	pub fn verify_basic(
		&self,
		check_low_s: bool,
		chain_id: Option<u64>,
		allow_empty_signature: bool,
	) -> Result<(), error::Error> {
		if self.action.is_input_private() {
			// Signature should be empty for tx with private input.
			if !self.is_unsigned() {
				return Err(ethkey::Error::InvalidSignature.into());
			}
		} else if allow_empty_signature && self.is_unsigned() {
			// EIP-86: Transactions of this form MUST have gasprice = 0, nonce = 0, value = 0,
			// and do NOT increment the nonce of account 0.
			if !(self.gas_price.is_zero() && self.value.is_zero() && self.nonce.is_zero()) {
				return Err(ethkey::Error::InvalidSignature.into());
			}
		} else {
			// Other transactions should have valid signature.
			if check_low_s {
				self.check_low_s()?;
			}
			if self.is_unsigned() {
				return Err(ethkey::Error::InvalidSignature.into());
			}
		}

		match (self.chain_id(), chain_id) {
			(None, _) => {}
			(Some(n), Some(m)) if n == m => {}
			_ => return Err(error::Error::InvalidChainId),
		};
		Ok(())
	}

	/// Verify basic format of private transaction.
	/// Does not perform heavy computation like ZKP or signature verification.
	pub fn verify_private_tx_basic(&self) -> Result<(), error::Error> {
		if !self.is_private() {
			return Err(error::Error::InvalidPrivateTx(
				error::PrivateTxError::InvalidAction,
			));
		}
		let private_tx = self.private.as_ref().unwrap();

		// Action shouldn't be call or create when private field is represented.
		match self.action {
			Action::PublicToPrivate | Action::PrivateToPrivate | Action::PrivateCall(_) => (),
			_ =>
				return Err(error::Error::InvalidPrivateTx(
					PrivateTxError::InvalidAction,
				)),
		}

		// Check nonce.
		if self.action.is_input_private() {
			if !self.nonce.is_zero() {
				return Err(error::Error::InvalidPrivateTx(PrivateTxError::InvalidNonce));
			}
		}

		// Check value.
		if self.is_privacy() {
			// Private to Private transaction shouldn't involve public balance transfer.
			if !self.value.is_zero() {
				return Err(error::Error::InvalidPrivateTx(PrivateTxError::InvalidValue));
			}
		}

		// Check balancing value.
		// TODO(xin): check overflow.
		if self.action == Action::PublicToPrivate {
			if self.value > MAX_VALUE_ALLOWED {
				return Err(error::Error::InvalidPrivateTx(PrivateTxError::InvalidValue));
			}
			// Transfer value from public to private, balancing_value should equal to negative of value.
			// The gas fee is separately deducted from public account.
			if self.balancing_value().is_positive() || U256::from(-self.balancing_value()) * CONVERSION_FACTOR != self.value   {
				return Err(error::Error::InvalidPrivateTx(
					error::PrivateTxError::InvalidBalancingValue,
				));
			}
		} else {
			// Transfer value from private, balancing_value should equal to the amount of value transfers to public,
			// plus the gas fee(gas_price * gas).
			if U256::from(self.balancing_value()) * CONVERSION_FACTOR != self.gas_price * self.gas + self.value {
				return Err(error::Error::InvalidPrivateTx(
					PrivateTxError::InvalidBalancingValue,
				));
			}
		}

		// Check number of spends.
		if self.action == Action::PublicToPrivate {
			// No private inputs are allowed when public input is represented.
			if !private_tx.spends.is_empty() {
				return Err(error::Error::InvalidPrivateTx(
					PrivateTxError::InvalidNumberOfSpends,
				));
			}
		} else {
			if private_tx.spends.is_empty() {
				return Err(error::Error::InvalidPrivateTx(
					PrivateTxError::InvalidNumberOfSpends,
				));
			}
		}

		// Check nullifier and anchor.
		if !private_tx.spends.is_empty() {
			let anchor = &private_tx.spends[0].anchor;
			let mut nullifier_set = HashSet::new();
			for spend in private_tx.spends.iter() {
				if nullifier_set.contains(&spend.nullifier) {
					return Err(error::Error::InvalidPrivateTx(
						PrivateTxError::DuplicatedNullifier,
					));
				}
				nullifier_set.insert(spend.nullifier.clone());
			}
		}
		Ok(())
	}
}

/// A `UnverifiedTransaction` with successfully recovered `sender`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SignedTransaction {
	pub transaction: UnverifiedTransaction,
	sender: Address,
	public: Option<Public>,
}

impl HeapSizeOf for SignedTransaction {
	fn heap_size_of_children(&self) -> usize {
		self.transaction.heap_size_of_children()
	}
}

impl rlp::Encodable for SignedTransaction {
	fn rlp_append(&self, s: &mut RlpStream) {
		self.transaction.rlp_append_sealed_transaction(s)
	}
}

impl Deref for SignedTransaction {
	type Target = UnverifiedTransaction;
	fn deref(&self) -> &Self::Target {
		&self.transaction
	}
}

impl From<SignedTransaction> for UnverifiedTransaction {
	fn from(tx: SignedTransaction) -> Self {
		tx.transaction
	}
}

impl SignedTransaction {
	/// Try to verify transaction and recover sender.
	pub fn new(transaction: UnverifiedTransaction) -> Result<Self, ethkey::Error> {
		if transaction.action.is_input_private() {
			// Currently tx with private input is unsigned.
			// But we need to assign a unique sender for each tx, such that it could be handled correctly
			// in transaction pool. The sender is recovered in the same way as sign_for_private.
			Ok(transaction.unsigned.sign_for_private(transaction.v))
		} else if transaction.is_unsigned() {
			Ok(SignedTransaction {
				transaction: transaction,
				sender: UNSIGNED_SENDER,
				public: None,
			})
		} else {
			let public = transaction.recover_public()?;
			let sender = public_to_address(&public);
			Ok(SignedTransaction {
				transaction: transaction,
				sender: sender,
				public: Some(public),
			})
		}
	}

	/// Returns transaction sender.
	pub fn sender(&self) -> Address {
		self.sender
	}

	/// Returns a public key of the sender.
	pub fn public_key(&self) -> Option<Public> {
		self.public
	}

	/// Checks is signature is empty.
	pub fn is_unsigned(&self) -> bool {
		self.transaction.is_unsigned()
	}

	/// Deconstructs this transaction back into `UnverifiedTransaction`
	pub fn deconstruct(self) -> (UnverifiedTransaction, Address, Option<Public>) {
		(self.transaction, self.sender, self.public)
	}
}

/// Signed Transaction that is a part of canon blockchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalizedTransaction {
	/// Signed part.
	pub signed: UnverifiedTransaction,
	/// Block number.
	pub block_number: BlockNumber,
	/// Block hash.
	pub block_hash: H256,
	/// Transaction index within block.
	pub transaction_index: usize,
	/// Cached sender
	pub cached_sender: Option<Address>,
}

impl LocalizedTransaction {
	/// Returns transaction sender.
	/// Panics if `LocalizedTransaction` is constructed using invalid `UnverifiedTransaction`.
	pub fn sender(&mut self) -> Address {
		if let Some(sender) = self.cached_sender {
			return sender;
		}
		if self.is_unsigned() {
			return UNSIGNED_SENDER.clone();
		}
		let sender = public_to_address(&self.recover_public()
			.expect("LocalizedTransaction is always constructed from transaction from blockchain; Blockchain only stores verified transactions; qed"));
		self.cached_sender = Some(sender);
		sender
	}

	pub fn v_shielded_spend(&self) -> Vec<SpendDescription> {
		match self.private {
			Some(ref tx) => tx.spends.clone(),
			None => Vec::new(),
		}
	}

	pub fn v_shielded_output(&self) -> Vec<OutputDescription> {
		match self.private {
			Some(ref tx) => tx.outputs.clone(),
			None => Vec::new(),
		}
	}

	//TODO
	pub fn is_coin_base(&self) -> bool {
		false
	}

	pub fn binding_sig(&self) -> [u8; 64] {
		match self.private {
			Some(ref tx) => tx.binding_sig,
			None => [0; 64],
		}
	}

	pub fn balancing_value(&self) -> i64 {
		match self.private {
			Some(ref tx) => tx.balancing_value,
			None => 0,
		}
	}
}

impl Deref for LocalizedTransaction {
	type Target = UnverifiedTransaction;

	fn deref(&self) -> &Self::Target {
		&self.signed
	}
}

/// Queued transaction with additional information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingTransaction {
	/// Signed transaction data.
	pub transaction: SignedTransaction,
	/// To be activated at this condition. `None` for immediately.
	pub condition: Option<Condition>,
}

impl PendingTransaction {
	/// Create a new pending transaction from signed transaction.
	pub fn new(signed: SignedTransaction, condition: Option<Condition>) -> Self {
		PendingTransaction {
			transaction: signed,
			condition: condition,
		}
	}

	pub fn v_shielded_spend(&self) -> Vec<SpendDescription> {
		match self.private {
			Some(ref tx) => tx.spends.clone(),
			None => Vec::new(),
		}
	}

	pub fn v_shielded_output(&self) -> Vec<OutputDescription> {
		match self.private {
			Some(ref tx) => tx.outputs.clone(),
			None => Vec::new(),
		}
	}

	//TODO
	pub fn is_coin_base(&self) -> bool {
		false
	}
}

impl Deref for PendingTransaction {
	type Target = SignedTransaction;

	fn deref(&self) -> &SignedTransaction {
		&self.transaction
	}
}

impl From<SignedTransaction> for PendingTransaction {
	fn from(t: SignedTransaction) -> Self {
		PendingTransaction {
			transaction: t,
			condition: None,
		}
	}
}

#[derive(Clone)]
pub enum SyncTransaction {
	InPool(PendingTransaction),

	InBlock(LocalizedTransaction),
}

impl SyncTransaction {
	pub fn hash(&self) -> H256 {
		match *self {
			SyncTransaction::InPool(ref tx) => tx.hash(),
			SyncTransaction::InBlock(ref tx) => tx.hash(),
		}
	}
	pub fn v_shielded_output(&self) -> Vec<OutputDescription> {
		match *self {
			SyncTransaction::InPool(ref tx) => tx.v_shielded_output(),
			SyncTransaction::InBlock(ref tx) => tx.v_shielded_output(),
		}
	}

	pub fn v_shielded_spend(&self) -> Vec<SpendDescription> {
		match *self {
			SyncTransaction::InPool(ref tx) => tx.v_shielded_spend(),
			SyncTransaction::InBlock(ref tx) => tx.v_shielded_spend(),
		}
	}

	pub fn is_coin_base(&self) -> bool {
		match *self {
			SyncTransaction::InPool(ref tx) => tx.is_coin_base(),
			SyncTransaction::InBlock(ref tx) => tx.is_coin_base(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use ethereum_types::U256;
	use ethkey::verify_address;
	use hash::keccak;
	use zcash_primitives::sapling::Node;

	const TEST_CHAIN_ID: u64 = 100;

	#[test]
	#[ignore]
	// TODO(Kui): After update the transaction struct, reopen
	fn sender_test() {
		let bytes = ::rustc_hex::FromHex::from_hex("f85f800182520894095e7baea6a6c7c4c2dfeb977efac326af552d870a801ba048b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353a0efffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804").unwrap();
		let t: UnverifiedTransaction =
			rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
		assert_eq!(t.data, b"");
		assert_eq!(t.gas, U256::from(0x5208u64));
		assert_eq!(t.gas_price, U256::from(0x01u64));
		assert_eq!(t.nonce, U256::from(0x00u64));
		if let Action::Call(ref to) = t.action {
			assert_eq!(*to, "095e7baea6a6c7c4c2dfeb977efac326af552d87".into());
		} else {
			panic!();
		}
		assert_eq!(t.value, U256::from(0x0au64));
		assert_eq!(
			public_to_address(&t.recover_public().unwrap()),
			"0f65fe9276bc9a24ae7083ae28e2660ef72df99e".into()
		);
		assert_eq!(t.chain_id(), None);
		assert!(!t.is_private());
	}

	#[test]
	fn signing_eip155_zero_chainid() {
		use ethkey::{Generator, Random};

		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
			private: None,
		};

		let hash = t.hash(Some(0));
		let sig = ::ethkey::sign(&key.secret(), &hash).unwrap();
		let u = t.with_signature(sig, Some(0));

		assert!(SignedTransaction::new(u).is_ok());
	}

	#[test]
	fn signing() {
		use ethkey::{Generator, Random};

		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
			private: None,
		}
		.sign(&key.secret(), None);
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn fake_signing() {
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
			private: None,
		}
		.fake_sign(Address::from(0x69));
		assert_eq!(Address::from(0x69), t.sender());
		assert_eq!(t.chain_id(), None);

		let t = t.clone();
		assert_eq!(Address::from(0x69), t.sender());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn should_recover_from_chain_specific_signing() {
		use ethkey::{Generator, Random};
		let key = Random.generate().unwrap();
		let t = Transaction {
			action: Action::Create,
			nonce: U256::from(42),
			gas_price: U256::from(3000),
			gas: U256::from(50_000),
			value: U256::from(1),
			data: b"Hello!".to_vec(),
			private: None,
		}
		.sign(&key.secret(), Some(69));
		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id(), Some(69));
	}

	#[test]
	#[ignore]
	// TODO(Kui): After update the transaction struct, reopen
	fn should_agree_with_vitalik() {
		use rustc_hex::FromHex;

		let test_vector = |tx_data: &str, address: &'static str| {
			let signed =
				rlp::decode(&FromHex::from_hex(tx_data).unwrap()).expect("decoding tx data failed");
			let signed = SignedTransaction::new(signed).unwrap();
			assert_eq!(signed.sender(), address.into());
			println!("chainid: {:?}", signed.chain_id());
		};

		test_vector("f864808504a817c800825208943535353535353535353535353535353535353535808025a0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116da0044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d", "0xf0f6f18bca1b28cd68e4357452947e021241e9ce");
		test_vector("f864018504a817c80182a410943535353535353535353535353535353535353535018025a0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bcaa0489efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6", "0x23ef145a395ea3fa3deb533b8a9e1b4c6c25d112");
		test_vector("f864028504a817c80282f618943535353535353535353535353535353535353535088025a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5a02d7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5", "0x2e485e0c23b4c3c542628a5f672eeab0ad4888be");
		test_vector("f865038504a817c803830148209435353535353535353535353535353535353535351b8025a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4e0a02a80e1ef1d7842f27f2e6be0972bb708b9a135c38860dbe73c27c3486c34f4de", "0x82a88539669a3fd524d669e858935de5e5410cf0");
		test_vector("f865048504a817c80483019a28943535353535353535353535353535353535353535408025a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c063a013600b294191fc92924bb3ce4b969c1e7e2bab8f4c93c3fc6d0a51733df3c060", "0xf9358f2538fd5ccfeb848b64a96b743fcc930554");
		test_vector("f865058504a817c8058301ec309435353535353535353535353535353535353535357d8025a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1a04eebf77a833b30520287ddd9478ff51abbdffa30aa90a8d655dba0e8a79ce0c1", "0xa8f7aba377317440bc5b26198a363ad22af1f3a4");
		test_vector("f866068504a817c80683023e3894353535353535353535353535353535353535353581d88025a06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2fa06455bf8ea6e7463a1046a0b52804526e119b4bf5136279614e0b1e8e296a4e2d", "0xf1f571dc362a0e5b2696b8e775f8491d3e50de35");
		test_vector("f867078504a817c807830290409435353535353535353535353535353535353535358201578025a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021a052f1a9b320cab38e5da8a8f97989383aab0a49165fc91c737310e4f7e9821021", "0xd37922162ab7cea97c97a87551ed02c9a38b7332");
		test_vector("f867088504a817c8088302e2489435353535353535353535353535353535353535358202008025a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c12a064b1702d9298fee62dfeccc57d322a463ad55ca201256d01f62b45b2e1c21c10", "0x9bddad43f934d313c2b79ca28a432dd2b7281029");
		test_vector("f867098504a817c809830334509435353535353535353535353535353535353535358202d98025a052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afba052f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb", "0x3c24d7329e92f84f08556ceb6df1cdb0104ca49f");
	}

	#[test]
	fn encode_decode_private_transaction() {
		// TODO(xin): Finish the tests.
		let ct = PrivateTransaction {
			spends: vec![],
			outputs: vec![],
			balancing_value: -10,
			binding_sig: [1u8; 64],
		};
		let encoded = ::rlp::encode(&ct);
		let ct2: PrivateTransaction = rlp::decode(&encoded).unwrap();
		assert_eq!(ct, ct2);
	}

	#[test]
	#[ignore]
	fn test_create_private() {
		// TODO(xin): To check this test.
		let ct = PrivateTransaction::create_private(vec![0]);
		let encoded = ::rlp::encode(&ct);
		let ct2: PrivateTransaction = rlp::decode(&encoded).unwrap();
		assert_eq!(ct, ct2);
	}

	#[test]
	fn encode_decode_tx_with_private() {
		let transaction_list = [
			Transaction::create_private(vec![0], U256::zero(), Action::PrivateToPrivate),
			Transaction::create_private(vec![0], U256::zero(), Action::PublicToPrivate),
			Transaction::create_private(
				vec![0],
				U256::zero(),
				Action::PrivateCall(Address::from("0000000000000000000000000000000000000005")),
			),
		];

		for transaction in transaction_list.iter() {
			let mut t = UnverifiedTransaction {
				unsigned: transaction.clone(),
				r: U256::one(),
				s: U256::one(),
				v: 0,
				hash: 0.into(),
			};
			let prev_hash = t.hash.clone();

			t.unsigned.private = Some(PrivateTransaction {
				spends: vec![],
				outputs: vec![],
				balancing_value: -10,
				binding_sig: [1u8; 64],
			});
			t = t.compute_hash();
			// Adding private should change hash.
			assert!(t.hash != prev_hash);
			let encoded = ::rlp::encode(&t);
			let t2: UnverifiedTransaction = rlp::decode(&encoded).unwrap();
			assert_eq!(t, t2);
			assert_eq!(t2.unsigned.private.unwrap().balancing_value, -10);
		}
	}

	#[test]
	fn encode_decode_action() {
		let address = Address::from("0000000000000000000000000000000000000005");
		let actions = vec![
			Action::Create,
			Action::Call(address),
			Action::PrivateToPrivate,
			Action::PublicToPrivate,
			Action::PrivateCall(address),
		];
		for action in actions.iter() {
			let encoded = ::rlp::encode(action);
			let decoded: Action = rlp::decode(&encoded).unwrap();
			assert_eq!(action, &decoded);
		}
	}

	//#[test]
	fn encode_decode_tx_action_type() {
		// Constructs a normal tx from bytes.
		let bytes = ::rustc_hex::FromHex::from_hex("f86b808501dcd6500082520894ad7a28390f3256fef876ea8cb7eea39e2af34a608722ee26e36e80008025a0b21a213fd39bfcd5c169be51c7bc4abe9a8db2089c7fbd63e6dcf6b817b6a35ea0031f13fe6df442e8618097858642ca642d670c20a4bd77e7bd191a4792bba9fc").unwrap();
		let mut t: UnverifiedTransaction =
			rlp::decode(&bytes).expect("decoding UnverifiedTransaction failed");
		let prev_hash = t.hash.clone();

		assert!(!t.is_unshield());
		t.unsigned.private = Some(PrivateTransaction {
			spends: vec![],
			outputs: vec![],
			balancing_value: -10,
			binding_sig: [1u8; 64],
		});
		t = t.compute_hash();
		// Adding private should change hash.
		assert!(t.hash != prev_hash);
		let encoded = ::rlp::encode(&t);
		let t2: UnverifiedTransaction = rlp::decode(&encoded).unwrap();
		assert!(t2.is_unshield());
		assert_eq!(t2.unsigned.private.unwrap().balancing_value, -10);
	}

	#[test]
	fn test_privacy_transaction() {
		let tx = Transaction::create_private(vec![0, 1], 42.into(), Action::PrivateToPrivate);
		let result = tx.get_nullifier_set();
		let commitment_note_list = tx.get_commitment_notes();
		let anchors = tx.get_commitment_anchors();
		assert_eq!(result.len(), 2);
		assert_eq!(commitment_note_list.len(), 2);
		assert_eq!(anchors.len(), 2);

		// check the first anchor in transaction
		assert_eq!(anchors[0], Fr::from_repr(FrRepr::from(0)).unwrap());

		// check the first commitment note in the transaction
		let note = Node::new(commitment_note_list[0].into_repr());
		assert_eq!(note.clone(), Node::new(FrRepr::default()));
		let mut tmp = [0u8; 32];
		note.write(&mut tmp[..]).expect("length is 32 bytes");
		assert_eq!(
			hex::encode(&tmp[..]),
			"0000000000000000000000000000000000000000000000000000000000000000"
		);

		let t = tx.sign_for_private(TEST_CHAIN_ID);
		assert!(t.is_private());
		assert_eq!(t.transaction.nonce, 42.into());
	}

	#[test]
	fn test_shield_transaction() {
		use ethkey::{Generator, Random};
		let key = Random.generate().unwrap();
		let t = Transaction::create_private(vec![0], 42.into(), Action::PublicToPrivate)
			.sign(&key.secret(), None);
		assert!(t.is_shield());
		assert_eq!(t.transaction.nonce, 42.into());

		assert_eq!(Address::from(keccak(key.public())), t.sender());
		assert_eq!(t.chain_id(), None);
	}

	#[test]
	fn test_unshield_transaction() {
		let t = Transaction::create_private(
			vec![0],
			42.into(),
			Action::PrivateCall(Address::from("0000000000000000000000000000000000000005")),
		)
		.sign_for_private(TEST_CHAIN_ID);
		assert!(t.is_unshield());
		assert_eq!(t.transaction.nonce, 42.into());
	}
	#[test]
	fn test_verify_private_to_private_transaction() {
		let tx = Transaction::create_private(vec![0, 1], U256::zero(), Action::PrivateToPrivate)
			.sign_for_private(TEST_CHAIN_ID);
		assert!(tx.transaction.verify_private_tx_basic().is_ok());
		assert!(tx
			.transaction
			.verify_basic(true, Some(TEST_CHAIN_ID), false)
			.is_ok());
		assert_eq!(tx
			.transaction
			.verify_basic(true, Some(TEST_CHAIN_ID + 1), false), Err(error::Error::InvalidChainId));

		// Change to an invalid action.
		let mut tx1 = tx.clone();
		tx1.transaction.unsigned.action = Action::Create;
		assert_eq!(
			tx1.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(
				PrivateTxError::InvalidAction
			))
		);

		// Change nonce to non zero.
		let mut tx2 = tx.clone();
		tx2.transaction.unsigned.nonce = U256::one();
		assert_eq!(
			tx2.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(PrivateTxError::InvalidNonce))
		);

		// Change value to non zero.
		let mut tx3 = tx.clone();
		tx3.transaction.unsigned.value = U256::one();
		assert_eq!(
			tx3.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(PrivateTxError::InvalidValue))
		);

		// Change balancing value to invalid.
		let mut tx4 = tx.clone();
		tx4.transaction.unsigned.private.as_mut().unwrap().balancing_value = 1;
		assert_eq!(
			tx4.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(
				PrivateTxError::InvalidBalancingValue
			))
		);

		// Create a private to private without spends.
		let tx5 = Transaction::create_private(vec![], U256::zero(), Action::PrivateToPrivate)
			.sign_for_private(TEST_CHAIN_ID);
		assert_eq!(
			tx5.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(
				PrivateTxError::InvalidNumberOfSpends
			))
		);

		// Create two spends with the same nullifier.
		let mut tx6 =
			Transaction::create_private(vec![0, 0], U256::zero(), Action::PrivateToPrivate)
				.sign_for_private(TEST_CHAIN_ID);
		assert_eq!(
			tx6.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(
				PrivateTxError::DuplicatedNullifier
			))
		);

		// Change the first spend to a different anchor.
		let mut tx7 =
			Transaction::create_private(vec![0, 1], U256::zero(), Action::PrivateToPrivate)
				.sign_for_private(TEST_CHAIN_ID);
		tx7.transaction.unsigned.private.as_mut().unwrap().spends[0].anchor = Fr::from_repr(FrRepr::from(1)).unwrap();
		assert_eq!(
			tx7.transaction.verify_private_tx_basic(),
			Ok(())
		);
	}

	#[test]
	fn test_private_input_sender_recover() {
		let mut tx = Transaction::create_private(
			vec![0],
			U256::zero(),
			Action::PrivateToPrivate,
		).sign_for_private(TEST_CHAIN_ID);
		let recovered_sign = SignedTransaction::new(tx.transaction.clone()).unwrap();
		assert_eq!(tx, recovered_sign);
		assert_eq!(tx.sender, recovered_sign.sender);
	}

	#[test]
	fn test_verify_private_to_public_transaction() {
		let mut tx = Transaction::create_private(
			vec![0],
			U256::zero(),
			Action::PrivateCall(Address::from("0000000000000000000000000000000000000005")),
		)
		.sign_for_private(TEST_CHAIN_ID);
		assert!(tx.transaction.verify_private_tx_basic().is_ok());
		assert!(tx
			.transaction
			.verify_basic(true, Some(TEST_CHAIN_ID), false)
			.is_ok());
	}

	#[test]
	fn test_verify_public_to_private_transaction() {
		let key = Random.generate().unwrap();
		let tx = Transaction::create_private(vec![], U256::zero(), Action::PublicToPrivate)
			.sign(&key.secret(), Some(TEST_CHAIN_ID));
		assert!(tx.transaction.verify_private_tx_basic().is_ok());
		assert!(tx
			.transaction
			.verify_basic(true, Some(TEST_CHAIN_ID), false)
			.is_ok());
		println!("outputs bytes:{:?}",hex::encode(tx.private.as_ref().unwrap().outputs[0].rlp_bytes()));

		// Change tx signature to empty signature.
		let tx2 = Transaction::create_private(vec![], U256::zero(), Action::PublicToPrivate)
			.sign_for_private(TEST_CHAIN_ID);
		assert_eq!(
			tx2.transaction
				.verify_basic(true, Some(TEST_CHAIN_ID), false),
			Err(ethkey::Error::InvalidSignature.into())
		);

		// Add a spend to transaction.
		let tx3 = Transaction::create_private(vec![1], U256::zero(), Action::PublicToPrivate)
			.sign(&key.secret(), Some(TEST_CHAIN_ID));
		assert_eq!(
			tx3.transaction.verify_private_tx_basic(),
			Err(error::Error::InvalidPrivateTx(
				PrivateTxError::InvalidNumberOfSpends
			))
		);
	}

	#[test]
	fn test_tx_hash_without_sig() {
		let mut tx = Transaction::create_private(vec![1,2,3], U256::zero(), Action::PublicToPrivate);
		let hash = tx.hash(Some(TEST_CHAIN_ID));
		tx.private.as_mut().unwrap().binding_sig = [2u8; 64];
		let hash1 = tx.hash(Some(TEST_CHAIN_ID));
		assert_eq!(hash, hash1);
		for spend in &mut tx.private.as_mut().unwrap().spends {
			spend.spend_auth_sig = Some(
					sapling_crypto::redjubjub::Signature::read(&[1u8; 64][..]).unwrap(),
				);
		}
		let hash2 = tx.hash(Some(TEST_CHAIN_ID));
		assert_eq!(hash, hash2);
		let mut tx1 = tx.clone();
		tx.nonce = U256::from("1");
		let hash3 = tx.hash(Some(TEST_CHAIN_ID));
		assert_ne!(hash, hash3);
		tx1.private.as_mut().unwrap().balancing_value = 1;
		let hash4 = tx1.hash(Some(TEST_CHAIN_ID));
		assert_ne!(hash, hash4);
	}
}
