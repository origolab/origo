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

use dir::Directories;
use ethereum_types::{H160, H256, U256};
use ff::PrimeField;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use parking_lot::Mutex as parking_Mutex;
use rand::Rng;
use std::collections::HashMap;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::path::Path;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use ethcore_db as db;
use kvdb::DBTransaction;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use zcash_primitives::merkle_tree::CommitmentTree;
use zcash_primitives::sapling::Node;
use zcash_primitives::{note_encryption::try_sapling_note_decryption, JUBJUB};

use crate::wallet::key_store::{
	decode_destination, decode_payment_address, encode_payment_address, KeyStore,
};
use crate::wallet::sendmany::{SaplingNoteData, SaplingNoteEntry};
use crate::wallet::wallet_types::{
	SaplingExtendedFullViewingKey, SaplingExtendedSpendingKey, SaplingFullViewingKey,
	SaplingIncomingViewingKey, SaplingMerkleTree, SaplingOutputDescription, SaplingPaymentAddress,
	SaplingSpendDescription, SaplingWitness, TxHash,
};

use crate::blockchain::BlockChain;
use crate::wallet::origo_account::OrigoAccount;
use crate::wallet::origo_key_file::OrigoKeyFile;
use common_types::encoded;
use common_types::transaction::{LocalizedTransaction, SyncTransaction, UnverifiedTransaction};
use ethstore::ethkey::Password;
use ethstore::JsonCrypto;
use std::collections::hash_set::HashSet;
use std::fs;
use std::io::Cursor;

use backtrace::Backtrace;

type SaplingIncomingViewingKeyMap = HashMap<SaplingPaymentAddress, SaplingIncomingViewingKey>;

pub const WITNESS_CACHE_SIZE: usize = 100;
pub const DUMMY_WALLET_PASS: &'static str = "dummy_wallet_pass";

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalletTxHashes {
	// All the related transaction hashes in the wallet.
	pub hashes: Vec<TxHash>,
}

impl WalletTxAddresses {
	pub fn new() -> Self {
		WalletTxAddresses { addresses: vec![] }
	}
}

impl rlp::Encodable for WalletTxHashes {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(1);
		s.append_list(&self.hashes);
	}
}

impl rlp::Decodable for WalletTxHashes {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(WalletTxHashes {
			hashes: rlp.list_at(0)?,
		})
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalletTxAddresses {
	// All the related transaction hashes in the wallet.
	pub addresses: Vec<String>,
}

impl rlp::Encodable for WalletTxAddresses {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(self.addresses.len());
		for b in &self.addresses {
			s.append(b);
		}
	}
}

impl rlp::Decodable for WalletTxAddresses {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		let mut addresses = vec![];
		for i in 0..rlp.item_count()? {
			addresses.push(rlp.val_at(i)?);
		}
		Ok(WalletTxAddresses { addresses })
	}
}

#[derive(Debug, Clone)]
pub struct ReloadBlockInfo {
	pub block_hash: H256,
	pub block: encoded::Block,
	pub tx_hashes: HashSet<TxHash>,
}

pub struct Wallet {
	pub nullifier_notes: HashMap<U256, SaplingNoteData>,
	pub address_nullifiers: HashMap<SaplingPaymentAddress, Vec<U256>>,
	pub tx_nullifiers: HashMap<H256, Vec<U256>>,

	pub key_store: KeyStore,
	file_path: String,
	file_name_prefix: String,
}

impl Wallet {
	pub fn new_from_default_dir() -> Self {
		let file_path = format!("{}", &Directories::default().wallet);
		Wallet::new_from_file("wallet_", &file_path[..])
	}

	pub fn new_from_file(file_name_prefix: &str, file_path: &str) -> Self {
		let mut wallet = Wallet {
			nullifier_notes: HashMap::new(),
			address_nullifiers: HashMap::new(),
			tx_nullifiers: HashMap::new(),
			key_store: KeyStore::new_with_file_prefix(file_name_prefix, file_path),
			file_path: file_path.into(),
			file_name_prefix: file_name_prefix.into(),
		};
		wallet.load_from_encrypted_files();
		wallet
	}

	/// Save internal state to file.
	fn save_key_to_file(
		&mut self,
		espk: &SaplingExtendedSpendingKey,
		pass: String,
	) -> std::io::Result<()> {
		self.key_store
			.encrypt_key_file_and_add_viewing_key(espk, pass)?;
		Ok(())
	}

	pub fn load_from_encrypted_files(&mut self) -> std::io::Result<()> {
		let dir = format!("{}", self.file_path);

		let paths = fs::read_dir(dir)?;

		let mut key_store = KeyStore::new_with_file_prefix(&self.file_name_prefix[..], &self.file_path[..]);

		for path in paths {
			let mut file_name = format!("{}", path.unwrap().path().display());
			file_name = file_name.as_str()[0..].to_string();

			if file_name.contains(&self.file_name_prefix[..]) {
				//println!("{}", file_name);
				let mut file = File::open(file_name);
				let key_file = OrigoKeyFile::load(&file.unwrap()).unwrap();
				let origo_account = OrigoAccount::from_file(key_file, None);

				let origo_account = origo_account.unwrap();
				//Only decode full viewing keys using blank password
				let none_pass = Password::from("");
				let secret_efvk = origo_account.efvk.decrypt(&none_pass).unwrap();
				let mut rdr_efvk = Cursor::new(secret_efvk);
				let efvk = SaplingExtendedFullViewingKey::read(&mut rdr_efvk).unwrap();

				let (_, address) = efvk.default_address().unwrap();

				key_store.add_full_viewing_key(efvk.fvk, address);
			}
		}
		self.key_store = key_store;
		Ok(())
	}

	pub fn add_address_from_seed(&mut self, seed: [u8; 32], pass: String) -> (String, SaplingExtendedSpendingKey)  {
		let xsk = SaplingExtendedSpendingKey::master(&seed);

		// Store the keys into key_store and serialize.
		let xfvk = SaplingExtendedFullViewingKey::from(&xsk);
		let (_, address) = xfvk.default_address().unwrap();

		self.save_key_to_file(&xsk, pass);

		(encode_payment_address(&address), xsk)
	}

	pub fn list_addresses(&self) -> Vec<String> {
		self.key_store
			.get_sapling_payment_addresses()
			.iter()
			.map(|payment_address| encode_payment_address(payment_address))
			.collect()
	}

	/// Clear the notes data in wallet.
	pub fn clear_wallet_data(&mut self) {
		self.nullifier_notes.clear();
		self.tx_nullifiers.clear();
		self.address_nullifiers.clear();
	}

	/// Write the related transaction hash data into db.
	pub fn write_wallet_data(&self, batch: &mut DBTransaction) {
		let wallet_hashes = WalletTxHashes {
			hashes: self
				.tx_nullifiers
				.iter()
				.map(|(hash, _)| hash.clone())
				.collect(),
		};
		let encoded = ::rlp::encode(&wallet_hashes);
		batch.put(db::COL_EXTRA, b"wallet_txs", &encoded);

		let wallet_addresses = WalletTxAddresses {
			addresses: self.list_addresses(),
		};
		let encoded = ::rlp::encode(&wallet_addresses);
		batch.put(db::COL_EXTRA, b"wallet_addresses", &encoded);
	}

	/// Get all the addresses in wallet.
	pub fn get_wallet_addresses(&self) -> WalletTxAddresses {
		WalletTxAddresses {
			addresses: self.list_addresses(),
		}
	}

	/// Add the SaplingNote on the new block.
	pub fn sync_new_block(
		&mut self,
		mut parent_commitment_tree: &mut CommitmentTree<Node>,
		pblock: &encoded::Block,
	) {
		self.process_new_block(parent_commitment_tree, pblock, &None, &None);
	}

	/// Reload the SaplingNote on the block for filtered_txs.
	pub fn reload_new_block(
		&mut self,
		mut parent_commitment_tree: &mut CommitmentTree<Node>,
		pblock: &encoded::Block,
		filtered_tx_hashes: &Option<HashSet<TxHash>>,
	) {
		self.process_new_block(parent_commitment_tree, pblock, &None, filtered_tx_hashes);
	}

	/// Scan the blockchain for new imported users.
	pub fn scan_new_block(
		&mut self,
		mut parent_commitment_tree: &mut CommitmentTree<Node>,
		pblock: &encoded::Block,
		handled_addresses: &Option<HashSet<String>>,
	) {
		self.process_new_block(parent_commitment_tree, pblock, handled_addresses, &None);
	}

	/// This function process the transaction in block to receive the sapling note into wallet.
	fn process_new_block(
		&mut self,
		mut parent_commitment_tree: &mut CommitmentTree<Node>,
		pblock: &encoded::Block,
		handled_addresses: &Option<HashSet<String>>,
		filtered_tx_hashes: &Option<HashSet<TxHash>>,
	) {
		let block_height = pblock.view().header().number();
		let txs = pblock.view().localized_private_txs();
		let mut note_commitment_index: usize = 0;
		let mut note_commitment_list = vec![];
		let unhandled_viewing_keys = self.key_store.get_unhandled_viewing_keys(handled_addresses);

		for tx in txs.iter() {
			for (i, item) in tx.v_shielded_output().iter().enumerate() {
				let cm = item.cmu;
				note_commitment_list.push(Node::new(cm.into_repr()));
			}
		}
		for tx in txs.iter() {
			self.receive_spling_notes_into_wallet(
				&block_height,
				tx,
				&mut parent_commitment_tree,
				&unhandled_viewing_keys,
				filtered_tx_hashes,
				&note_commitment_list,
				&mut note_commitment_index,
			);
		}
	}

	/// Delete the SaplingNote on the retracted txs.
	pub fn remove_retracted_txs(&mut self, retracted_tx_hashes: &Vec<H256>) {
		for hash in retracted_tx_hashes.iter() {
			if let Some(nullifiers) = self.tx_nullifiers.get(hash) {
				for nullifier in nullifiers.iter() {
					self.nullifier_notes.remove(nullifier);
				}
			}
		}

		// Reconstruct the tx_nullifiers and address_nullifiers data.
		self.tx_nullifiers.clear();
		self.address_nullifiers.clear();
		for (nullifier, salingNote) in self.nullifier_notes.iter() {
			match self.tx_nullifiers.get_mut(&salingNote.hash) {
				None => {
					let mut nullifiers = Vec::new();
					nullifiers.push(nullifier.clone());
					self.tx_nullifiers
						.insert(salingNote.hash.clone(), nullifiers);
				}
				Some(mut v) => {
					v.push(nullifier.clone());
				}
			}
			match self.address_nullifiers.get_mut(&salingNote.address) {
				None => {
					let mut nullifiers = Vec::new();
					nullifiers.push(nullifier.clone());
					self.address_nullifiers
						.insert(salingNote.address.clone(), nullifiers);
				}
				Some(mut v) => {
					v.push(nullifier.clone());
				}
			}
		}
	}

	/// This function process the private transaction,
	/// which uses the viewing keys to decrypt the shielded outputs
	/// and receives the sapling notes into the wallet.
	fn receive_spling_notes_into_wallet(
		&mut self,
		block_height: &u64,
		tx: &LocalizedTransaction,
		mut commitment_tree: &mut CommitmentTree<Node>,
		handled_viewing_keys: &HashMap<SaplingIncomingViewingKey, SaplingFullViewingKey>,
		filtered_tx_hashes_option: &Option<HashSet<TxHash>>,
		note_commitment_list: &Vec<Node>,
		commitment_index: &mut usize,
	) {
		let hash = tx.hash();
		for (i, output) in tx.v_shielded_output().iter().enumerate() {
			let current_commitment_index = *commitment_index;
			commitment_tree.append(note_commitment_list[current_commitment_index].clone());
			*commitment_index += 1;
			if let Some(filtered_tx_hashes) = filtered_tx_hashes_option {
				if !filtered_tx_hashes.contains(&hash) {
					return;
				}
			}
			for (ivk, fvk) in handled_viewing_keys.iter() {
				match output.ephemeral_key.as_prime_order(&JUBJUB) {
					None => continue,
					Some(epk) => {
						match try_sapling_note_decryption(
							&ivk,
							&epk,
							&output.cmu,
							&output.enc_ciphertext,
						) {
							None => continue,
							Some((note, address, memo)) => {
								let mut front_op = SaplingWitness::from_tree(&commitment_tree);
								let current_commitment_index = *commitment_index;
								for successor_index in
									current_commitment_index..note_commitment_list.len()
								{
									front_op.append(note_commitment_list[successor_index].clone());
								}
								let position = front_op.position();
								let vk = fvk.vk;
								let nullifier_vec = note.clone().nf(&vk, position as u64, &JUBJUB);
								let mut nullifier_arr = [0u8; 32];
								nullifier_arr.copy_from_slice(&nullifier_vec);
								let nullifier = U256::from(nullifier_arr);

								let mut note_data = SaplingNoteData::new(
									address.clone(),
									note,
									memo,
									block_height.clone(),
									ivk.clone(),
									nullifier.clone(),
									hash.clone(),
									i,
								);
								note_data.push_front(front_op);

								match self.tx_nullifiers.get_mut(&hash) {
									None => {
										let mut nullifiers = Vec::new();
										nullifiers.push(nullifier.clone());
										self.tx_nullifiers.insert(hash.clone(), nullifiers);
									}
									Some(mut v) => {
										v.push(nullifier);
									}
								}

								match self.address_nullifiers.get_mut(&address) {
									None => {
										let mut nullifiers = Vec::new();
										nullifiers.push(nullifier.clone());
										self.address_nullifiers.insert(address.clone(), nullifiers);
									}
									Some(mut v) => {
										v.push(nullifier.clone());
									}
								}

								assert!(!self.nullifier_notes.contains_key(&nullifier));
								self.nullifier_notes.insert(nullifier.clone(), note_data);
								break;
							}
						};
					}
				};
			}
		}

		// Mark the spend notes as confirmed.
		for spend in tx.v_shielded_spend().iter() {
			let nullifier = U256::from(spend.nullifier);
			match self.nullifier_notes.get_mut(&nullifier) {
				Some(mut note) => {
					note.confirmHeight = Some(block_height.clone());
				}
				None => {}
			}
		}
	}

	pub fn create_new_private_address(&mut self, password: Option<String>) -> String {
		// TODO(xin): Change to generate new address from the same seed,
		// instead of generating a new seed every time.
		let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
		//TODO
		let mut pass = match password {
			Some(pass) => pass,
			None => String::from(DUMMY_WALLET_PASS),
		};

		self.add_address_from_seed(random_bytes, pass).0
	}

	// Get the SaplingNoteEntry for the specific filtered address.
	pub fn get_filtered_address_notes(&self, address: &String) -> Vec<SaplingNoteEntry> {
		let mut filtered_addresses = HashSet::new();
		if address.len() > 0 {
			let payment_address = decode_payment_address(&address);
			if payment_address.is_some() {
				filtered_addresses.insert(payment_address.unwrap());
			}
		}
		//TODO, min_depth and max_depth now is not used, ignore_locked is unused
		self.get_filtered_notes(&filtered_addresses, 0, 0, true, true)
	}

	fn get_filtered_notes(
		&self,
		filtered_addresses: &HashSet<SaplingPaymentAddress>,
		min_depth: i64,
		max_depth: i64,
		ignore_spent: bool,
		ignore_locked: bool,
	) -> Vec<SaplingNoteEntry> {
		let mut filter_notes: Vec<SaplingNoteEntry> = Vec::new();
		for address in filtered_addresses.iter() {

			if let Some(nullifiers) = self.address_nullifiers.get(address) {
				for nullifier in nullifiers.iter() {
					if let Some(saplingNote) = self.nullifier_notes.get(nullifier) {
						if ignore_spent && saplingNote.confirmHeight.is_some() {
							continue;
						}

						let note = SaplingNoteEntry {
							hash: saplingNote.hash.clone(),
							index: saplingNote.index.clone(),
							address: address.clone(),
							witness: saplingNote.front().unwrap(),
							note: saplingNote.note.clone(),
							memo: saplingNote.memo.clone(),
							confirmation: 0,
						};
						filter_notes.push(note)
					}
				}
			}
		}
		filter_notes
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs;
	use std::str::FromStr;

	use crate::generator::{BlockBuilder, BlockGenerator, BlockOptions};
	use crate::wallet::transaction_builder::TransactionBuilder;
	use crate::wallet::wallet_types::{SaplingExtendedFullViewingKey, SaplingExtendedSpendingKey};
	use common_types::ids::BlockId::Hash;
	use common_types::transaction::{Action, Transaction, CONVERSION_FACTOR};
	use ff::PrimeField;
	use rand::{OsRng, Rand};
	use sapling_crypto::{jubjub::fs::Fs, redjubjub::Signature};
	use std::collections::btree_map::BTreeMap;
	use zcash_primitives::{
		merkle_tree::{CommitmentTree, IncrementalWitness},
		sapling::Node,
		JUBJUB,
	};

	const TEST_CHAIN_ID: u64 = 0;

	fn create_private_transaction(mut wallet: &mut Wallet) -> Transaction {
		let mut rng = OsRng::new().expect("should be able to construct RNG");

		let (_, extsk) = wallet.add_address_from_seed([0u8;32], "".to_string());
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;

		let mut builder =
			TransactionBuilder::new(0.into(), U256::from(0), U256::from(21000), vec![], 2);

		// Add input
		let note1 = to.create_note(400, Fs::rand(&mut rng), &JUBJUB).unwrap();
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
		let mut tx = result.unwrap();
		tx
	}

	fn remove_old_key_files(file_name_prefix_op: &str, file_path: &str) {
		//Remove old key files
		let mut dir = format!("{}", file_path);
		if file_path == "" {
			dir = "./".to_string();
		}

		let paths = fs::read_dir(dir).unwrap();

		let mut file_name_prefix = "wallet";
		if file_name_prefix_op != "" {
			file_name_prefix = file_name_prefix_op;
		}

		for path in paths {
			let mut file_name = format!("{}", path.unwrap().path().display());
			file_name = file_name.as_str()[2..].to_string();
			if file_name.starts_with(file_name_prefix) {
				fs::remove_file(file_name);
			}
		}
	}

	#[test]
	fn test_save_load_wallet() {
		let file_name_prefix = "test_wallet_save";

		let mut wallet = Wallet::new_from_file(file_name_prefix, "./");
		let add1 = wallet.create_new_private_address(None);
		let add2 = wallet.create_new_private_address(None);

		let addresses1 = wallet.list_addresses();
		assert_eq!(addresses1.len(), 2);

		let mut wallet2 = Wallet::new_from_file(file_name_prefix, "./");

		// Test addresses are the same from loaded wallet.
		let addresses2 = wallet2.list_addresses();
		assert_eq!(addresses2.len(), 2);
		assert!(addresses2.contains(&add1));
		assert!(addresses2.contains(&add2));
		// Remove temp file.
		remove_old_key_files(file_name_prefix, "./");
	}

	#[test]
	fn test_sync_and_retract_block() {
		let file_name_path = "test_wallet_sync";
		let mut wallet = Wallet::new_from_file(file_name_path, "./");

		let genesis = BlockBuilder::genesis();
		let t1 = create_private_transaction(&mut wallet).sign_for_private(0);
		let b1a = genesis.add_block_with_transactions(vec![t1.clone()]);
		let generator = BlockGenerator::new(vec![b1a]);
		let mut parent_commitment_tree = CommitmentTree::<Node>::new();

		let mut retract_tx_hashes = vec![];
		for block in generator {
			wallet.sync_new_block(&mut parent_commitment_tree, &block.encoded());
			for tx in block.encoded().view().localized_private_txs().iter() {
				retract_tx_hashes.push(tx.hash().clone());
			}
		}

		assert_eq!(wallet.tx_nullifiers.len(), 1);
		assert_eq!(wallet.address_nullifiers.len(), 1);
		assert_eq!(wallet.nullifier_notes.len(), 2);
		for (nullifier, note) in wallet.nullifier_notes.iter() {
			assert_eq!(note.createHeight, 1);
			assert_eq!(note.confirmHeight, None);
			assert_eq!(note.spendHeight, None);
		}

		let addresses = wallet.list_addresses();
		assert_eq!(addresses.len(), 1);
		let saplingNotes = wallet.get_filtered_address_notes(&addresses[0]);
		let mut sum = 0;
		for entry in saplingNotes.iter() {
			sum = sum + entry.note.value;
		}
		assert_eq!(sum, 400);

		wallet.remove_retracted_txs(&retract_tx_hashes);
		assert_eq!(wallet.tx_nullifiers.len(), 0);
		assert_eq!(wallet.address_nullifiers.len(), 0);
		assert_eq!(wallet.nullifier_notes.len(), 0);
		remove_old_key_files(file_name_path, "./");
	}

	#[test]
	fn test_write_reload_scan_wallet_data() {
		let file_name_prefix = "test_wallet_reload";
		let mut wallet = Wallet::new_from_file(file_name_prefix, "./");

		let genesis = BlockBuilder::genesis();
		let t1 = create_private_transaction(&mut wallet).sign_for_private(TEST_CHAIN_ID);
		let t1_hash = t1.hash();
		let mut t2 = create_private_transaction(&mut wallet);
		t2.value = 100.into();
		t2.nonce = 2.into();
		let signed_t2 = t2.sign_for_private(TEST_CHAIN_ID);
		assert_ne!(t1.hash(), signed_t2.hash());
		let b1a = genesis.add_block_with_transactions(vec![t1.clone(), signed_t2]);
		let block = b1a.last().encoded();

		let mut parent_commitment_tree = CommitmentTree::<Node>::new();
		wallet.sync_new_block(&mut parent_commitment_tree, &block);
		let wallet_hashes = WalletTxHashes {
			hashes: wallet
				.tx_nullifiers
				.iter()
				.map(|(hash, _)| hash.clone())
				.collect::<Vec<TxHash>>(),
		};
		let encoded = ::rlp::encode(&wallet_hashes);
		let decode_hashes: WalletTxHashes = rlp::decode(&encoded).unwrap();
		assert_eq!(wallet_hashes, decode_hashes);
		assert_eq!(wallet_hashes.hashes.len(), 2);
		let wallet_addresses = WalletTxAddresses {
			addresses: wallet
				.address_nullifiers
				.iter()
				.map(|(address, _)| encode_payment_address(address))
				.collect(),
		};
		let encoded = ::rlp::encode(&wallet_addresses);
		let decoded_addresses: WalletTxAddresses = rlp::decode(&encoded).unwrap();
		assert_eq!(wallet_addresses, decoded_addresses);
		assert_eq!(wallet_addresses.addresses.len(), 1);

		let mut wallet = Wallet::new_from_file(file_name_prefix, "./");

		let handled_addresses = wallet_addresses
			.addresses
			.iter()
			.cloned()
			.collect::<HashSet<_>>();
		wallet.scan_new_block(
			&mut parent_commitment_tree,
			&block,
			&Some(handled_addresses),
		);
		assert_eq!(wallet.tx_nullifiers.len(), 0);

		let mut tx_hashes: HashSet<TxHash> = HashSet::new();
		tx_hashes.insert(t1_hash);
		let block_height = block.number();
		wallet.reload_new_block(&mut parent_commitment_tree, &block, &Some(tx_hashes));
		assert_eq!(wallet.tx_nullifiers.len(), 1);
		assert_eq!(wallet.address_nullifiers.len(), 1);
		assert_eq!(wallet.nullifier_notes.len(), 2);

		let addresses = wallet.list_addresses();
		let saplingNotes = wallet.get_filtered_address_notes(&addresses[0]);
		let mut sum = 0;
		for entry in saplingNotes.iter() {
			sum = sum + entry.note.value;
		}
		assert_eq!(sum, 400);
		remove_old_key_files(file_name_prefix, "./");
	}

	#[test]
	fn test_reload_block_ordered() {
		let file_name_prefix = "test_wallet_ordered";
		let mut wallet = Wallet::new_from_file(file_name_prefix, "./");

		let genesis = BlockBuilder::genesis();
		let t1 = create_private_transaction(&mut wallet).sign_for_private(TEST_CHAIN_ID);
		let b1a = genesis.add_block_with_transactions(vec![t1.clone()]);
		let block = b1a.last().encoded();
		let mut reload_blocks: BTreeMap<u64, ReloadBlockInfo> = BTreeMap::new();
		let reload_block = ReloadBlockInfo {
			block_hash: block.hash(),
			block,
			tx_hashes: HashSet::new(),
		};
		reload_blocks.insert(10, reload_block.clone());
		reload_blocks.insert(2, reload_block.clone());
		reload_blocks.insert(5, reload_block.clone());

		// The reload blocks must in ordered by block_height.
		assert_eq!(
			vec![2, 5, 10],
			reload_blocks
				.iter()
				.map(|(key, value)| { (*key).clone() })
				.collect::<Vec<u64>>()
		);
		remove_old_key_files(file_name_prefix, "./");
	}

	#[test]
	fn test_save_load_file() {
		let wallet_file_prefix = "test_wallet_new";
		let mut wallet = Wallet::new_from_file(wallet_file_prefix, "./");

		let seed = [0u8; 32];
		let address_str = wallet.add_address_from_seed(seed, String::from("pass_for_test"));
		let wallet_new = Wallet::new_from_file(wallet_file_prefix, "./");

		let addresses = wallet.key_store.get_sapling_payment_addresses();
		let reload_addresses = wallet_new.key_store.get_sapling_payment_addresses();

		assert_eq!(addresses.len(), 1);
		for index in 0..addresses.len() {
			let address = addresses[index];
			let reload_address = reload_addresses[index];
			assert_eq!(address.clone(), reload_address.clone());

			let fs = wallet.key_store.get_incoming_viewing_key(&address).expect("");
			let reload_fs = wallet_new.key_store.get_incoming_viewing_key(&reload_address).expect("");

			let fvks = wallet.key_store.get_full_viewing_key(&fs).expect("");
			let reload_fvks = wallet_new.key_store.get_full_viewing_key(&reload_fs).expect("");
			assert_eq!(fvks.vk.ak, reload_fvks.vk.ak);
			assert_eq!(fvks.vk.nk, reload_fvks.vk.nk);
			assert_eq!(fvks.ovk, reload_fvks.ovk);
		}
		remove_old_key_files(wallet_file_prefix, "");
	}

	#[test]
	fn test_encrypt_key_file() {
		let wallet_file_prefix = "test_wallet_new";
		let mut wallet = Wallet::new_from_file(wallet_file_prefix, "./");

		let seed = [0u8; 32];
		wallet.add_address_from_seed(seed, String::from("pass_for_test"));

		let x = "ogo180m058urhazk8j98zvz9fsq5zd0vd9dpsc8c6ednwd2xkc3l8z9thmxsezepzx4aascp6nrlkd6";
		let path = format!("{}{}", wallet_file_prefix, x);

		//Just for showing example of encryted file
		let expected_simuler_result = r#"
			{
				"address":"ogo180m058urhazk8j98zvz9fsq5zd0vd9dpsc8c6ednwd2xkc3l8z9thmxsezepzx4aascp6nrlkd6",
				"crypto":
					{
						"cipher":"aes-128-ctr",
						"cipherparams":{"iv":"734243b9ecf79c2f3d30ea9b6099dee0"},
						"ciphertext":"15c8fba8f02476a47f890a7bd71adbd99dd74219859f144af574c0516b13b69ca24d9d6da162c25e60e506d4f563d61c2a967cd2023fa08e4c6c19e3dd5d555aeb5ff7faae52bb45e14e594d57ea6c256af2c347e2a28ee11583384da6211a53eebcb8edea0464fc26013df9767499f6da75abe7d5f5e96b04bfd1ec0dad7f1defeffdfaea8edf49e2f248fbe29f4f952d03b3761e9f5fd9ecfbbd786589dc9f320f0ac53b0b5114e2",
						"kdf":"pbkdf2",
						"kdfparams":{"c":10240,"dklen":32,"prf":"hmac-sha256","salt":"d93cd65787d722f51a37023d1c65387bed382b6d909bee2bc4558bd26bde491a"},
						"mac":"cbf9a0770c3a7f8d8d39251b24084d716e123138f72576976d22f0a49e0d12a0"},
						"efvk":{"cipher":"aes-128-ctr","cipherparams":{"iv":"8ad6a7b91e2fd0c64449ebc978f61280"},"ciphertext":"d77b706e12e81d345d57b113a94de7bc7c1cbe9f054b6440c0ce9cefea1b607ddb6d85c542343e45c0837f1d46d3a28d6b9618dd851b855d4b97d18d54e81988d393e6162d1829901157597b54467573bff8f76a8073566693fd0479fe250b1c8bd46b7ac85e5d9af044d572538e7a6b146e52da87f34750829b2827a9e5a2bc5b16c06c01cc3bec3aacb7c7571a5e922c950d4b6fef668162bb08328d8c61eecbe926a5a2ff40faa2","kdf":"pbkdf2","kdfparams":{"c":10240,"dklen":32,"prf":"hmac-sha256","salt":"3a8cc7393a6cd567cb915616c7ee620045f4150cc6dfe4ca0b667a6ba76d582a"},"mac":"dc3c4e331ab109b30cdcf80bdc045ea97299366fecb524f79142a5c0ba22dbd9"}
					}"#;
		let contents = fs::read_to_string(path);
	}
}
