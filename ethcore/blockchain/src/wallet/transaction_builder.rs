use ethereum_types::{Address, U256};
use pairing::bls12_381::{Bls12, Fr};
use rand::{OsRng, Rand};
use sapling_crypto::{jubjub::fs::Fs, primitives::Diversifier, redjubjub::PrivateKey};
use std::fmt;
use zcash_primitives::{
	merkle_tree::{CommitmentTreeWitness, IncrementalWitness},
	note_encryption::{Memo, SaplingNoteEncryption},
	sapling::{spend_sig, Node},
	transaction::components::GROTH_PROOF_SIZE,
	JUBJUB,
};
use zcash_proofs::sapling::SaplingProvingContext;

use crate::wallet::sendmany::{CAmount, OutputDescriptionInfo, SpendDescriptionInfo};
use crate::wallet::wallet_types::{
	SaplingCommitmentTreeWitness, SaplingExpandedSpendingKey, SaplingNote,
	SaplingOutgoingViewingKey, SaplingOutputDescription, SaplingPaymentAddress,
	SaplingSpendDescription,
};
use crate::wallet::zkp::{OUTPUT_PARAM, SPEND_PARAM, SPEND_VK};
use common_types::transaction::{
	Action, PrivateTransaction, Transaction, CONVERSION_FACTOR, MAX_VALUE_ALLOWED,
};

#[derive(Debug)]
pub struct Error(pub ErrorKind);

impl Error {
	pub fn kind(&self) -> &ErrorKind {
		&self.0
	}
}

#[derive(Debug, PartialEq)]
pub enum ErrorKind {
	BindingSig,
	InvalidChange(String),
	InvalidAddress,
	InvalidAmount(String),
	InsufficientBalance(String),
	ConversionFactorError,
	InvalidMemo,
	InvalidWitness,
	NoChangeAddress,
	NoPrivateKey,
	SpendProof,
	InvalidGasMulGasPrice(String),
}

impl fmt::Display for ErrorKind {
	fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
		match *self {
			ErrorKind::BindingSig => write!(f, "Binding Signature."),
			ErrorKind::InvalidChange(ref e) => write!(f, "Invalid change:{}.", e),
			ErrorKind::InvalidAddress => write!(f, "Invalid Address."),
			ErrorKind::InvalidAmount(ref e) => write!(f, "Invalid Amount:{}.", e),
			ErrorKind::InsufficientBalance(ref e) => write!(f, "Insufficient Balance:{}.", e),
			ErrorKind::ConversionFactorError =>
				write!(f, "The balance should be the multiple of 10^9."),
			ErrorKind::InvalidMemo => write!(f, "Invalid Memo."),
			ErrorKind::InvalidWitness => write!(f, "Invalid Witness."),
			ErrorKind::NoChangeAddress => write!(f, "No Change Address."),
			ErrorKind::NoPrivateKey => write!(f, "No Private Key."),
			ErrorKind::SpendProof => write!(f, "Spend Proof."),
			ErrorKind::InvalidGasMulGasPrice(ref e) =>
				write!(f, "Invalid Product of Gas and Gas_price:{}", e),
		}
	}
}

impl Into<String> for ErrorKind {
	fn into(self) -> String {
		format!("{}", self)
	}
}

/// It used to generated a shield transaction according the protocol
pub struct TransactionBuilder {
	rng: OsRng,
	// Describe spend transfers
	pub spends: Vec<SpendDescriptionInfo>,
	// Describe output transfers
	pub outputs: Vec<OutputDescriptionInfo>,
	tx: Transaction,
	// The amount of value transferred from public account.
	public_input_amount: U256,
	// The amount of value transferred to public account.
	public_output_amount: U256,
	// Chain ID
	pub chain_id: u64,
}

impl TransactionBuilder {
	pub fn new(gas_price: U256, nonce: U256, gas: U256, data: Vec<u8>, chain_id: u64) -> Self {
		TransactionBuilder {
			rng: OsRng::new().expect("should be able to construct RNG"),
			spends: Vec::new(),
			outputs: Vec::new(),
			tx: Transaction {
				action: Action::PrivateToPrivate,
				nonce,
				gas_price,
				gas,
				value: U256::from(0),
				data,
				private: Some(PrivateTransaction {
					spends: vec![],
					outputs: vec![],
					balancing_value: 0,
					binding_sig: [0u8; 64],
				}),
			},
			public_input_amount: U256::from(0),
			public_output_amount: U256::from(0),
			chain_id,
		}
	}

	pub fn add_sapling_spend(
		&mut self,
		expsk: SaplingExpandedSpendingKey,
		diversifier: Diversifier,
		note: SaplingNote,
		anchor: Fr,
		witness: SaplingCommitmentTreeWitness,
	) -> Result<(), Error> {
		let alpha = Fs::rand(&mut self.rng);
		// tx.private is initialized so calling unwrap should be safe.
		self.tx.private.as_mut().unwrap().balancing_value += note.value as i64;
		self.spends.push(SpendDescriptionInfo {
			expsk,
			diversifier,
			note,
			alpha,
			anchor,
			witness,
		});
		Ok(())
	}

	/// Adds a private output to the transaction.
	/// It constructs an OutputDescriptionInfo and stores it.
	/// The stored info will be used to create the private OutputDescription in the transaction.
	pub fn add_sapling_output(
		&mut self,
		ovk: SaplingOutgoingViewingKey,
		to: SaplingPaymentAddress,
		value: &U256,
		memo: &str,
	) -> Result<(), Error> {
		// For each output description, the sender select a value v and a
		// shielded payment address and performs the follow steps:
		// Step 1: check pk_d is right type and a valid ctEdwards point on the Jubjub curve.
		let g_d = match to.g_d(&JUBJUB) {
			Some(g_d) => g_d,
			None => return Err(Error(ErrorKind::InvalidAddress)),
		};

		// Step 2: Choose independent uniformly random commitment trapdoors.
		let rcm = Fs::rand(&mut self.rng);
		if *value > MAX_VALUE_ALLOWED {
			return Err(Error(ErrorKind::InvalidAmount(value.to_string())));
		}
		if (*value) % CONVERSION_FACTOR != U256::from(0) {
			return Err(Error(ErrorKind::ConversionFactorError));
		}
		let value = (*value / CONVERSION_FACTOR).low_u64();
		// The Sapling note does not have a ρ field. There is in fact a ρ value associated with
		// each Sapling note, but this only be computed once its position in the note commitment tree is known.
		let note = SaplingNote {
			g_d,
			pk_d: to.pk_d.clone(),
			value,
			r: rcm,
		};
		let value = value as i64;
		self.tx.private.as_mut().unwrap().balancing_value -= value;

		let memo = match Memo::from_str(memo) {
			Some(m) => m,
			None => return Err(Error(ErrorKind::InvalidMemo)),
		};

		let output_desc_info = OutputDescriptionInfo {
			ovk,
			to,
			note,
			memo,
		};
		self.outputs.push(output_desc_info);
		Ok(())
	}

	pub fn set_public_input(&mut self, value: U256) {
		self.tx.action = Action::PublicToPrivate;
		self.tx.value = value;
		self.public_input_amount = value;
	}

	pub fn set_public_output(&mut self, address: Address, value: &U256) {
		self.tx.action = Action::PrivateCall(address);
		self.tx.value = *value;
		self.public_output_amount += *value;
	}

	fn compute_change(&self) -> Result<U256, Error> {
		let balancing_value = self.tx.balancing_value();
		if balancing_value.is_negative() {
			if self.public_input_amount
				>= self.public_output_amount
					+ U256::from((-balancing_value) as u64) * CONVERSION_FACTOR
			{
				return Ok(self.public_input_amount
					- self.public_output_amount
					- U256::from((-balancing_value) as u64) * CONVERSION_FACTOR);
			} else {
				return Err(Error(ErrorKind::InvalidChange(
					String::from("-")
						+ &(self.public_output_amount
							+ U256::from((-balancing_value) as u64) * CONVERSION_FACTOR
							- self.public_input_amount)
							.to_string(),
				)));
			}
		} else {
			if self.public_input_amount + U256::from((balancing_value) as u64) * CONVERSION_FACTOR
				>= self.public_output_amount
			{
				return Ok(self.public_input_amount
					+ U256::from((balancing_value) as u64) * CONVERSION_FACTOR
					- self.public_output_amount);
			} else {
				return Err(Error(ErrorKind::InvalidChange(
					String::from("-")
						+ &(self.public_output_amount
							- self.public_input_amount - U256::from((balancing_value) as u64)
							* CONVERSION_FACTOR)
							.to_string(),
				)));
			}
		}
	}

	pub fn build(&mut self) -> Result<Transaction, Error> {
		if self.tx.value % CONVERSION_FACTOR != U256::from(0) {
			return Err(Error(ErrorKind::ConversionFactorError));
		}
		if self.tx.action != Action::PublicToPrivate
			&& (self.tx.gas * self.tx.gas_price) % CONVERSION_FACTOR != U256::from(0)
		{
			return Err(Error(ErrorKind::InvalidGasMulGasPrice(
				(self.tx.gas * self.tx.gas_price).to_string(),
			)));
		}
		// Deduct transaction fee.
		if self.tx.action.is_input_private() {
			self.public_output_amount += (self.tx.gas * self.tx.gas_price);
		}
		let change = self.compute_change()?;
		if !(change / CONVERSION_FACTOR).is_zero() {
			if !self.spends.is_empty() {
				// Send change to the address of the first shield spend.
				self.add_sapling_output(
					self.spends[0].expsk.ovk.clone(),
					SaplingPaymentAddress {
						diversifier: self.spends[0].diversifier,
						pk_d: self.spends[0].note.pk_d.clone(),
					},
					&change,
					"",
				)?;
			} else {
				// If the fund is from public account, no change should be left.
				return Err(Error(ErrorKind::NoChangeAddress));
			}
		} else if !change.is_zero() {
			return Err(Error(ErrorKind::InvalidChange(change.to_string())));
		}
		let mut ctx = SaplingProvingContext::new();

		for spend in self.spends.iter() {
			let proof_generation_key = spend.expsk.proof_generation_key(&JUBJUB);

			let mut nullifier = [0u8; 32];
			nullifier.copy_from_slice(&spend.note.nf(
				&proof_generation_key.into_viewing_key(&JUBJUB),
				spend.witness.position,
				&JUBJUB,
			));
			let (proof, cv, rk) = ctx
				.spend_proof(
					proof_generation_key,
					spend.diversifier,
					spend.note.r,
					spend.alpha,
					spend.note.value,
					spend.anchor,
					spend.witness.clone(),
					&SPEND_PARAM,
					&SPEND_VK,
					&JUBJUB,
				)
				.map_err(|()| Error(ErrorKind::SpendProof))?;

			let mut v = vec![];
			proof.write(&mut v).unwrap();
			let mut zkproof = [0u8; GROTH_PROOF_SIZE];
			zkproof.copy_from_slice(v.as_slice());
			self.tx
				.private
				.as_mut()
				.unwrap()
				.spends
				.push(SaplingSpendDescription {
					cv,
					anchor: spend.anchor,
					nullifier,
					rk,
					zkproof,
					spend_auth_sig: None,
				});
		}

		for output in self.outputs.iter() {
			// Encrypt note to the recipient diversified transmission key pk_d
			// with diversified transmission base g_d, and to the outgoing viewing key ovk,
			// giving the transmitted note ciphertext (epk, Cenc, Cout)
			let encryptor = SaplingNoteEncryption::new(
				output.ovk,
				output.note.clone(),
				output.to.clone(),
				output.memo.clone(),
			);
			let xxx = output.note.value;
			// println!("In build 2.1, {0}", xxx);
			// Generate a proof ZKOutput for the Output statement
			let (proof, cv) = ctx.output_proof(
				*encryptor.esk(),
				output.to,
				output.note.r,
				output.note.value,
				&OUTPUT_PARAM,
				&JUBJUB,
			);
			let mut v = vec![];
			proof.write(&mut v).unwrap();
			let mut zkproof = [0u8; GROTH_PROOF_SIZE];
			zkproof.copy_from_slice(v.as_slice());

			let cmu = output.note.cm(&JUBJUB);

			// Use cv and cmu to derive the outgoing cipher key .
			let enc_ciphertext = encryptor.encrypt_note_plaintext();
			let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu);

			let ephemeral_key = encryptor.epk().clone().into();
			let output_desc = SaplingOutputDescription {
				cv,
				cmu,
				ephemeral_key,
				enc_ciphertext,
				out_ciphertext,
				zkproof,
			};
			self.tx.private.as_mut().unwrap().outputs.push(output_desc);
		}
		// Signature
		// TODO(xin): Compute real sig_hash.
		let sighash = self.tx.hash(Some(self.chain_id)).into();
		for (i, spend) in self.spends.iter().enumerate() {
			self.tx.private.as_mut().unwrap().spends[i].spend_auth_sig = Some(spend_sig(
				PrivateKey(spend.expsk.ask),
				spend.alpha,
				&sighash,
				&JUBJUB,
			));
		}

		let binding_sig = match ctx.binding_sig(self.tx.balancing_value(), &sighash, &JUBJUB) {
			Ok(sig) => sig,
			Err(_) => return Err(Error(ErrorKind::BindingSig)),
		};

		binding_sig.write(&mut self.tx.private.as_mut().unwrap().binding_sig[..]);

		Ok(self.tx.clone())
	}
}

mod tests {
	use super::*;
	use crate::wallet::wallet_types::{
		SaplingExtendedFullViewingKey, SaplingExtendedSpendingKey, SaplingMerkleTree,
		SaplingWitness,
	};
	use crate::wallet::zkp::{OUTPUT_VK, SPEND_VK};

	use bellman::groth16::Proof;
	use ff::PrimeField;
	use sapling_crypto::redjubjub::Signature;
	use zcash_primitives::{
		merkle_tree::{CommitmentTree, IncrementalWitness},
		note_encryption::try_sapling_note_decryption,
		sapling::Node,
	};
	use zcash_proofs::sapling::SaplingVerificationContext;
	// TODO(xin): Add tests for failure cases.
	const TEST_CHAIN_ID: u64 = 2;
	#[test]
	fn build_transaction() {
		let mut rng = OsRng::new().expect("should be able to construct RNG");

		let extsk = SaplingExtendedSpendingKey::master(&[]);
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;

		let mut builder = TransactionBuilder::new(
			0.into(),
			U256::from(0),
			U256::from(21000),
			vec![],
			TEST_CHAIN_ID,
		);

		// Add input
		let note1 = to.create_note(300, Fs::rand(&mut rng), &JUBJUB).unwrap();
		let mut tree = CommitmentTree::new();
		let cm1 = Node::new(note1.cm(&JUBJUB).into_repr());

		tree.append(cm1).unwrap();
		let inc_tree = IncrementalWitness::from_tree(&tree);
		let witness1 = inc_tree.path().unwrap();
		assert!(builder
			.add_sapling_spend(
				extsk.expsk,
				to.diversifier,
				note1,
				inc_tree.root().into(),
				witness1
			)
			.is_ok());

		// Add output
		assert!(builder
			.add_sapling_output(ovk, to, &(U256::from(200) * CONVERSION_FACTOR), "haha")
			.is_ok());

		let result = builder.build();
		assert!(result.is_ok());
		let tx = result.unwrap();
		let sighash = tx.hash(Some(TEST_CHAIN_ID)).into();
		// Verify input.
		let mut ctx = SaplingVerificationContext::new();
		// tx.get_nullifier_set()
		// tx.v_shielded_spend();
		assert_eq!(tx.v_shielded_spend().len(), 1);
		let spend_desc = tx.v_shielded_spend()[0].clone();
		let spend_proof = Proof::<Bls12>::read(&spend_desc.zkproof[..]).unwrap();
		assert!(ctx.check_spend(
			spend_desc.cv,
			spend_desc.anchor,
			&spend_desc.nullifier,
			spend_desc.rk,
			// TODO(xin): Change to real sighash.
			&sighash,
			spend_desc.spend_auth_sig.unwrap(),
			spend_proof,
			&SPEND_VK,
			&JUBJUB
		));

		// Verify output.
		assert_eq!(tx.v_shielded_output().len(), 2);
		let mut output_desc = tx.v_shielded_output()[0].clone();
		let zkproof = Proof::<Bls12>::read(&output_desc.zkproof[..]).unwrap();
		assert!(ctx.check_output(
			output_desc.cv,
			output_desc.cmu,
			output_desc.ephemeral_key,
			zkproof,
			&OUTPUT_VK,
			&JUBJUB,
		));
		let epk = output_desc.ephemeral_key.as_prime_order(&JUBJUB).unwrap();
		let (note, address, memo) = try_sapling_note_decryption(
			&extfvk.fvk.vk.ivk(),
			&epk,
			&output_desc.cmu,
			&output_desc.enc_ciphertext,
		)
		.unwrap();
		assert_eq!(address, to);
		assert_eq!(memo.to_utf8().unwrap().unwrap(), "haha");
		assert_eq!(note.value, 200);
		assert_eq!(note.pk_d, address.pk_d);

		// Verifty change
		let mut output_desc = tx.v_shielded_output()[1].clone();
		let zkproof = Proof::<Bls12>::read(&output_desc.zkproof[..]).unwrap();
		assert!(ctx.check_output(
			output_desc.cv,
			output_desc.cmu,
			output_desc.ephemeral_key,
			zkproof,
			&OUTPUT_VK,
			&JUBJUB,
		));
		let epk = output_desc.ephemeral_key.as_prime_order(&JUBJUB).unwrap();
		let (note, address, memo) = try_sapling_note_decryption(
			&extfvk.fvk.vk.ivk(),
			&epk,
			&output_desc.cmu,
			&output_desc.enc_ciphertext,
		)
		.unwrap();
		assert_eq!(address, to);
		assert_eq!(note.value, 100);
		assert_eq!(note.pk_d, address.pk_d);

		// Check balance.
		assert_eq!(tx.balancing_value(), 0);
		assert!(ctx.final_check(
			tx.balancing_value(),
			&sighash,
			Signature::read(&tx.binding_sig()[..]).unwrap(),
			&JUBJUB,
		));
		assert!(tx
			.sign_for_private(TEST_CHAIN_ID)
			.verify_private_tx_basic()
			.is_ok());
	}

	#[test]
	fn build_private_to_public_transaction() {
		let mut rng = OsRng::new().expect("should be able to construct RNG");

		let extsk = SaplingExtendedSpendingKey::master(&[]);
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;

		let mut builder = TransactionBuilder::new(
			0.into(),
			U256::from(0),
			U256::from(21000),
			vec![],
			TEST_CHAIN_ID,
		);

		// Add input
		let note1 = to
			.create_note(300 + 21000, Fs::rand(&mut rng), &JUBJUB)
			.unwrap();
		let mut tree = CommitmentTree::new();
		let cm1 = Node::new(note1.cm(&JUBJUB).into_repr());

		tree.append(cm1).unwrap();
		let inc_tree = IncrementalWitness::from_tree(&tree);
		let witness1 = inc_tree.path().unwrap();
		assert!(builder
			.add_sapling_spend(
				extsk.expsk,
				to.diversifier,
				note1,
				inc_tree.root().into(),
				witness1
			)
			.is_ok());

		// Add output
		builder.set_public_output(
			Address::from("0000000000000000000000000000000000000005"),
			&(U256::from(200) * CONVERSION_FACTOR),
		);

		let result = builder.build();
		assert!(result.is_ok());
		let tx = result.unwrap();
		assert!(tx
			.sign_for_private(TEST_CHAIN_ID)
			.verify_private_tx_basic()
			.is_ok());
	}

	#[test]
	fn build_transaction_with_public_input() {
		let extsk = SaplingExtendedSpendingKey::master(&[]);
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;

		let mut builder = TransactionBuilder::new(
			0.into(),
			U256::from(0),
			U256::from(21000),
			vec![],
			TEST_CHAIN_ID,
		);
		// Add output
		assert!(builder
			.add_sapling_output(ovk, to, &(U256::from(200) * CONVERSION_FACTOR), "haha")
			.is_ok());

		// Build failed because change is negative.
		assert!(builder.build().is_err());

		// Build should succeed. The private output has value 200, it comes from the public input.
		builder.set_public_input(U256::from(200) * CONVERSION_FACTOR);
		assert!(builder.build().is_ok());

		builder.set_public_input(U256::from(250) * CONVERSION_FACTOR);
		// Build failed because change is positive but there's no private input.
		assert!(builder.build().is_err());
	}
}
