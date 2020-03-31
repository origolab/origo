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

//! Blockchain database.

use std::collections::{HashMap, HashSet, btree_map::BTreeMap};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::{io, mem};

use ansi_term::Colour;
use blooms_db;
use common_types::blockchain_info::BlockChainInfo;
use common_types::encoded;
use common_types::engines::epoch::{
	PendingTransition as PendingEpochTransition, Transition as EpochTransition,
};
use common_types::engines::ForkChoice;
use common_types::header::{ExtendedHeader, Header};
use common_types::log_entry::{LocalizedLogEntry, LogEntry};
use common_types::receipt::Receipt;
use common_types::reward_config::RewardConfig;
use common_types::rewards::{EraRewardInfo, Rewards};
use common_types::transaction::{LocalizedTransaction, SyncTransaction};
use common_types::tree_route::TreeRoute;
use common_types::view;
use common_types::views::{BlockView, HeaderView};
use common_types::BlockNumber;
use ethcore_db::cache_manager::CacheManager;
use ethcore_db::keys::{
	BlockDetails, BlockReceipts, CommitmentTreeSerialization, EpochTransitions, TransactionAddress,
	EPOCH_KEY_PREFIX,
};
use ethcore_db::{self as db, CacheUpdatePolicy, Readable, Writable};
use ethereum_types::{Bloom, BloomRef, H256, U256};
use heapsize::HeapSizeOf;
use itertools::Itertools;
use kvdb::{DBTransaction, KeyValueDB};
use log::{info, trace, warn};
use parity_bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rayon::prelude::*;
use rlp::RlpStream;
use rlp_compress::{blocks_swapper, compress, decompress};

use std::ops::DerefMut;
use std::sync::mpsc;
use std::sync::Mutex as STD_Mutex;
use std::sync::RwLock as STD_RwLock;

use crate::ff::PrimeField;
use crate::wallet::wallet::{Wallet, WalletTxHashes, ReloadBlockInfo, WalletTxAddresses};
use crate::zcash_primitives::merkle_tree::CommitmentTree;
use crate::zcash_primitives::sapling::Node;

use crate::best_block::{BestAncientBlock, BestBlock};
use crate::block_info::{BlockInfo, BlockLocation, BranchBecomingCanonChainData};
use crate::update::{ExtrasInsert, ExtrasUpdate};
use crate::{CacheSize, Config, ImportRoute};
use crate::wallet::wallet_types::TxHash;

/// Database backing `BlockChain`.
pub trait BlockChainDB: Send + Sync {
	/// Generic key value store.
	fn key_value(&self) -> &Arc<KeyValueDB>;

	/// Header blooms database.
	fn blooms(&self) -> &blooms_db::Database;

	/// Trace blooms database.
	fn trace_blooms(&self) -> &blooms_db::Database;

	/// Restore the DB from the given path
	fn restore(&self, new_db: &str) -> Result<(), io::Error> {
		// First, close the Blooms databases
		self.blooms().close()?;
		self.trace_blooms().close()?;

		// Restore the key_value DB
		self.key_value().restore(new_db)?;

		// Re-open the Blooms databases
		self.blooms().reopen()?;
		self.trace_blooms().reopen()?;
		Ok(())
	}
}

/// Generic database handler. This trait contains one function `open`. When called, it opens database with a
/// predefined config.
pub trait BlockChainDBHandler: Send + Sync {
	/// Open the predefined key-value database.
	fn open(&self, path: &Path) -> io::Result<Arc<BlockChainDB>>;
}

/// Interface for querying blocks by hash and by number.
pub trait BlockProvider {
	/// Returns true if the given block is known
	/// (though not necessarily a part of the canon chain).
	fn is_known(&self, hash: &H256) -> bool;

	/// Returns true if the given block is known and in the canon chain.
	fn is_canon(&self, hash: &H256) -> bool {
		let is_canon = || Some(hash == &self.block_hash(self.block_number(hash)?)?);
		is_canon().unwrap_or(false)
	}

	/// Get the first block of the best part of the chain.
	/// Return `None` if there is no gap and the first block is the genesis.
	/// Any queries of blocks which precede this one are not guaranteed to
	/// succeed.
	fn first_block(&self) -> Option<H256>;

	/// Get the number of the first block.
	fn first_block_number(&self) -> Option<BlockNumber> {
		self.first_block().map(|b| self.block_number(&b).expect("First block is always set to an existing block or `None`. Existing block always has a number; qed"))
	}

	/// Get the best block of an first block sequence if there is a gap.
	fn best_ancient_block(&self) -> Option<H256>;

	/// Get the number of the first block.
	fn best_ancient_number(&self) -> Option<BlockNumber> {
		self.best_ancient_block().map(|h| self.block_number(&h).expect("Ancient block is always set to an existing block or `None`. Existing block always has a number; qed"))
	}
	/// Get raw block data
	fn block(&self, hash: &H256) -> Option<encoded::Block>;

	/// Get the familial details concerning a block.
	fn block_details(&self, hash: &H256) -> Option<BlockDetails>;

	/// Get the block hash for the given commitment tree root
	/// Return None if the given commitment tree not exist
	fn commitment_root_block(&self, root: &Node) -> Option<H256>;

	/// Get the commitment tree serialization for the given block
	/// Return None if the given block not exist
	fn block_commitment_ser(&self, hash: &H256) -> Option<CommitmentTreeSerialization>;

	/// Get the hash of given block's number.
	fn block_hash(&self, index: BlockNumber) -> Option<H256>;

	/// Get the address of transaction with given hash.
	fn transaction_address(&self, hash: &H256) -> Option<TransactionAddress>;

	/// Get the hash of transaction for given nullifier.
	/// Returns None if the nullifier does not exist.
	fn nullifier_transaction(&self, nullifier: &U256) -> Option<H256>;

	/// Get receipts of block with given hash.
	fn block_receipts(&self, hash: &H256) -> Option<BlockReceipts>;

	/// Get the header RLP of a block.
	fn block_header_data(&self, hash: &H256) -> Option<encoded::Header>;

	/// Get the block body (uncles and transactions).
	fn block_body(&self, hash: &H256) -> Option<encoded::Body>;

	/// Get a list of uncles for a given block.
	/// Returns None if block does not exist.
	fn uncles(&self, hash: &H256) -> Option<Vec<Header>> {
		self.block_body(hash).map(|body| body.uncles())
	}

	/// Get a list of uncle hashes for a given block.
	/// Returns None if block does not exist.
	fn uncle_hashes(&self, hash: &H256) -> Option<Vec<H256>> {
		self.block_body(hash).map(|body| body.uncle_hashes())
	}

	/// Get the number of given block's hash.
	fn block_number(&self, hash: &H256) -> Option<BlockNumber> {
		self.block_header_data(hash).map(|header| header.number())
	}

	/// Get transaction with given transaction hash.
	fn transaction(&self, address: &TransactionAddress) -> Option<LocalizedTransaction> {
		self.block_body(&address.block_hash).and_then(|body| {
			self.block_number(&address.block_hash).and_then(|n| {
				body.view()
					.localized_transaction_at(&address.block_hash, n, address.index)
			})
		})
	}

	/// Get a list of transactions for a given block.
	/// Returns None if block does not exist.
	fn transactions(&self, hash: &H256) -> Option<Vec<LocalizedTransaction>> {
		self.block_body(hash).and_then(|body| {
			self.block_number(hash)
				.map(|n| body.view().localized_transactions(hash, n))
		})
	}

	/// Returns reference to genesis hash.
	fn genesis_hash(&self) -> H256 {
		self.block_hash(0)
			.expect("Genesis hash should always exist")
	}

	/// Returns the header of the genesis block.
	fn genesis_header(&self) -> encoded::Header {
		self.block_header_data(&self.genesis_hash())
			.expect("Genesis header always stored; qed")
	}

	/// Returns numbers of blocks containing given bloom.
	fn blocks_with_bloom<'a, B, I, II>(
		&self,
		blooms: II,
		from_block: BlockNumber,
		to_block: BlockNumber,
	) -> Vec<BlockNumber>
	where
		BloomRef<'a>: From<B>,
		II: IntoIterator<Item = B, IntoIter = I> + Copy,
		I: Iterator<Item = B>,
		Self: Sized;

	/// Returns logs matching given filter.
	fn logs<F>(
		&self,
		blocks: Vec<H256>,
		matches: F,
		limit: Option<usize>,
	) -> Vec<LocalizedLogEntry>
	where
		F: Fn(&LogEntry) -> bool + Send + Sync,
		Self: Sized;
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
enum CacheId {
	BlockHeader(H256),
	BlockBody(H256),
	BlockDetails(H256),
	BlockCommitmentRoot(Node),
	BlockCommitmentSer(H256),
	BlockHashes(BlockNumber),
	TransactionAddresses(H256),
	TransactionNullifier(U256),
	BlockReceipts(H256),
}

/// Structure providing fast access to blockchain data.
///
/// **Does not do input data verification.**
pub struct BlockChain {
	// save chain reward config.
	reward_config: RewardConfig,

	// All locks must be captured in the order declared here.
	best_block: RwLock<BestBlock>,
	// Stores best block of the first uninterrupted sequence of blocks. `None` if there are no gaps.
	// Only updated with `insert_unordered_block`.
	best_ancient_block: RwLock<Option<BestAncientBlock>>,
	// Stores the last block of the last sequence of blocks. `None` if there are no gaps.
	// This is calculated on start and does not get updated.
	first_block: Option<H256>,
	// Store the last processed private user addresses in wallet.
	// only updated with 'insert_block'.
	pt_wallet_addresses: RwLock<WalletTxAddresses>,

	// block cache
	block_headers: RwLock<HashMap<H256, encoded::Header>>,
	block_bodies: RwLock<HashMap<H256, encoded::Body>>,

	// extra caches
	block_details: RwLock<HashMap<H256, BlockDetails>>,
	block_hashes: RwLock<HashMap<BlockNumber, H256>>,
	// store the map for commitment tree root to block hash.
	commitment_root_blocks: RwLock<HashMap<Node, H256>>,
	// store the map for block hash to commitment tree serialization
	block_commitment_sers: RwLock<HashMap<H256, CommitmentTreeSerialization>>,
	transaction_addresses: RwLock<HashMap<H256, TransactionAddress>>,
	transaction_nullifiers: RwLock<HashMap<U256, H256>>,
	block_receipts: RwLock<HashMap<H256, BlockReceipts>>,

	// store reward of each era.
	rewards: RwLock<Rewards>,

	pt_wallet: Arc<STD_RwLock<Wallet>>,

	db: Arc<BlockChainDB>,

	cache_man: Mutex<CacheManager<CacheId>>,

	pending_best_ancient_block: RwLock<Option<Option<BestAncientBlock>>>,
	pending_best_block: RwLock<Option<BestBlock>>,
	pending_pt_wallet_addresses: RwLock<Option<WalletTxAddresses>>,
	pending_block_hashes: RwLock<HashMap<BlockNumber, H256>>,
	pending_block_details: RwLock<HashMap<H256, BlockDetails>>,
	pending_commitment_root_blocks: RwLock<HashMap<Node, Option<H256>>>,
	pending_block_commitment_sers: RwLock<HashMap<H256, CommitmentTreeSerialization>>,
	pending_transaction_addresses: RwLock<HashMap<H256, Option<TransactionAddress>>>,
	pending_transaction_nullifiers: RwLock<HashMap<U256, Option<H256>>>,
	pending_rewards: RwLock<Option<Rewards>>,

	pending_routes: RwLock<ImportRoute>,
}

impl BlockProvider for BlockChain {
	/// Returns true if the given block is known
	/// (though not necessarily a part of the canon chain).
	fn is_known(&self, hash: &H256) -> bool {
		self.db
			.key_value()
			.exists_with_cache(db::COL_EXTRA, &self.block_details, hash)
	}

	fn first_block(&self) -> Option<H256> {
		self.first_block.clone()
	}

	fn best_ancient_block(&self) -> Option<H256> {
		self.best_ancient_block.read().as_ref().map(|b| b.hash)
	}

	fn best_ancient_number(&self) -> Option<BlockNumber> {
		self.best_ancient_block.read().as_ref().map(|b| b.number)
	}

	/// Get raw block data
	fn block(&self, hash: &H256) -> Option<encoded::Block> {
		let header = self.block_header_data(hash)?;
		let body = self.block_body(hash)?;
		Some(encoded::Block::new_from_header_and_body(
			&header.view(),
			&body.view(),
		))
	}

	/// Get block header data
	fn block_header_data(&self, hash: &H256) -> Option<encoded::Header> {
		// Check cache first
		{
			let read = self.block_headers.read();
			if let Some(v) = read.get(hash) {
				return Some(v.clone());
			}
		}

		// Check if it's the best block
		{
			let best_block = self.best_block.read();
			if &best_block.header.hash() == hash {
				return Some(best_block.header.encoded());
			}
		}

		// Read from DB and populate cache
		let b = self.db.key_value().get(db::COL_HEADERS, hash).expect(
			"Low level database error when fetching block header data. Some issue with disk?",
		)?;

		let header = encoded::Header::new(decompress(&b, blocks_swapper()).into_vec());
		let mut write = self.block_headers.write();
		write.insert(*hash, header.clone());

		self.cache_man.lock().note_used(CacheId::BlockHeader(*hash));
		Some(header)
	}

	/// Get block body data
	fn block_body(&self, hash: &H256) -> Option<encoded::Body> {
		// Check cache first
		{
			let read = self.block_bodies.read();
			if let Some(v) = read.get(hash) {
				return Some(v.clone());
			}
		}
		// Check if it's the best block
		{
			let best_block = self.best_block.read();
			if &best_block.header.hash() == hash {
				return Some(encoded::Body::new(Self::block_to_body(
					best_block.block.rlp().as_raw(),
				)));
			}
		}

		// Read from DB and populate cache
		let b = self.db.key_value().get(db::COL_BODIES, hash).expect(
			"Low level database error when fetching block body data. Some issue with disk?",
		)?;

		let body = encoded::Body::new(decompress(&b, blocks_swapper()).into_vec());
		let mut write = self.block_bodies.write();
		write.insert(*hash, body.clone());

		self.cache_man.lock().note_used(CacheId::BlockBody(*hash));
		Some(body)
	}

	/// Get the familial details concerning a block.
	fn block_details(&self, hash: &H256) -> Option<BlockDetails> {
		let result =
			self.db
				.key_value()
				.read_with_cache(db::COL_EXTRA, &self.block_details, hash)?;
		self.cache_man
			.lock()
			.note_used(CacheId::BlockDetails(*hash));
		Some(result)
	}

	/// Get the hash of given block's number.
	fn block_hash(&self, index: BlockNumber) -> Option<H256> {
		let result =
			self.db
				.key_value()
				.read_with_cache(db::COL_EXTRA, &self.block_hashes, &index)?;
		self.cache_man.lock().note_used(CacheId::BlockHashes(index));
		Some(result)
	}

	/// Get the block hash for the given commitment tree root
	/// Return None if the given commitment tree not exist
	fn commitment_root_block(&self, root: &Node) -> Option<H256> {
		let result = self.db.key_value().read_with_cache(
			db::COL_EXTRA,
			&self.commitment_root_blocks,
			root,
		)?;
		self.cache_man
			.lock()
			.note_used(CacheId::BlockCommitmentRoot(*root));
		Some(result)
	}

	/// Get the commitment tree serialization for the given block
	/// Return None if the given block not exist
	fn block_commitment_ser(&self, hash: &H256) -> Option<CommitmentTreeSerialization> {
		let result = self.db.key_value().read_with_cache(
			db::COL_EXTRA,
			&self.block_commitment_sers,
			hash,
		)?;
		self.cache_man
			.lock()
			.note_used(CacheId::BlockCommitmentSer(*hash));
		Some(result)
	}

	/// Get the address of transaction with given hash.
	fn transaction_address(&self, hash: &H256) -> Option<TransactionAddress> {
		let result = self.db.key_value().read_with_cache(
			db::COL_EXTRA,
			&self.transaction_addresses,
			hash,
		)?;
		self.cache_man
			.lock()
			.note_used(CacheId::TransactionAddresses(*hash));
		Some(result)
	}

	/// Get the hash of transaction for given nullifier.
	/// Returns None if the nullifier does not exist.
	fn nullifier_transaction(&self, nullifier: &U256) -> Option<H256> {
		let result = self.db.key_value().read_with_cache(
			db::COL_EXTRA,
			&self.transaction_nullifiers,
			nullifier,
		)?;
		self.cache_man
			.lock()
			.note_used(CacheId::TransactionNullifier(*nullifier));
		Some(result)
	}

	/// Get receipts of block with given hash.
	fn block_receipts(&self, hash: &H256) -> Option<BlockReceipts> {
		let result =
			self.db
				.key_value()
				.read_with_cache(db::COL_EXTRA, &self.block_receipts, hash)?;
		self.cache_man
			.lock()
			.note_used(CacheId::BlockReceipts(*hash));
		Some(result)
	}

	/// Returns numbers of blocks containing given bloom.
	fn blocks_with_bloom<'a, B, I, II>(
		&self,
		blooms: II,
		from_block: BlockNumber,
		to_block: BlockNumber,
	) -> Vec<BlockNumber>
	where
		BloomRef<'a>: From<B>,
		II: IntoIterator<Item = B, IntoIter = I> + Copy,
		I: Iterator<Item = B>,
	{
		self.db
			.blooms()
			.filter(from_block, to_block, blooms)
			.expect("Low level database error when searching blooms. Some issue with disk?")
	}

	/// Returns logs matching given filter. The order of logs returned will be the same as the order of the blocks
	/// provided. And it's the callers responsibility to sort blocks provided in advance.
	fn logs<F>(
		&self,
		mut blocks: Vec<H256>,
		matches: F,
		limit: Option<usize>,
	) -> Vec<LocalizedLogEntry>
	where
		F: Fn(&LogEntry) -> bool + Send + Sync,
		Self: Sized,
	{
		// sort in reverse order
		blocks.reverse();

		let mut logs = blocks
			.chunks(128)
			.flat_map(move |blocks_chunk| {
				blocks_chunk.into_par_iter()
					.filter_map(|hash| self.block_number(&hash).map(|r| (r, hash)))
					.filter_map(|(number, hash)| self.block_receipts(&hash).map(|r| (number, hash, r.receipts)))
					.filter_map(|(number, hash, receipts)| self.block_body(&hash).map(|ref b| (number, hash, receipts, b.transaction_hashes())))
					.flat_map(|(number, hash, mut receipts, mut hashes)| {
						if receipts.len() != hashes.len() {
							warn!("Block {} ({}) has different number of receipts ({}) to transactions ({}). Database corrupt?", number, hash, receipts.len(), hashes.len());
							assert!(false);
						}
						let mut log_index = receipts.iter().fold(0, |sum, receipt| sum + receipt.logs.len());

						let receipts_len = receipts.len();
						hashes.reverse();
						receipts.reverse();
						receipts.into_iter()
							.map(|receipt| receipt.logs)
							.zip(hashes)
							.enumerate()
							.flat_map(move |(index, (mut logs, tx_hash))| {
								let current_log_index = log_index;
								let no_of_logs = logs.len();
								log_index -= no_of_logs;

								logs.reverse();
								logs.into_iter()
									.enumerate()
									.map(move |(i, log)| LocalizedLogEntry {
										entry: log,
										block_hash: *hash,
										block_number: number,
										transaction_hash: tx_hash,
										// iterating in reverse order
										transaction_index: receipts_len - index - 1,
										transaction_log_index: no_of_logs - i - 1,
										log_index: current_log_index - i - 1,
									})
							})
							.filter(|log_entry| matches(&log_entry.entry))
							.take(limit.unwrap_or(::std::usize::MAX))
							.collect::<Vec<_>>()
					})
					.collect::<Vec<_>>()
			})
			.take(limit.unwrap_or(::std::usize::MAX))
			.collect::<Vec<LocalizedLogEntry>>();
		logs.reverse();
		logs
	}
}

/// An iterator which walks the blockchain towards the genesis.
#[derive(Clone)]
pub struct AncestryIter<'a> {
	current: H256,
	chain: &'a BlockChain,
}

impl<'a> Iterator for AncestryIter<'a> {
	type Item = H256;
	fn next(&mut self) -> Option<H256> {
		if self.current.is_zero() {
			None
		} else {
			self.chain
				.block_details(&self.current)
				.map(|details| mem::replace(&mut self.current, details.parent))
		}
	}
}

/// An iterator which walks the blockchain towards the genesis, with metadata information.
pub struct AncestryWithMetadataIter<'a> {
	current: H256,
	chain: &'a BlockChain,
}

impl<'a> Iterator for AncestryWithMetadataIter<'a> {
	type Item = ExtendedHeader;
	fn next(&mut self) -> Option<ExtendedHeader> {
		if self.current.is_zero() {
			None
		} else {
			let details = self.chain.block_details(&self.current);
			let header = self.chain.block_header_data(&self.current).map(|h| {
				h.decode()
					.expect("Stored block header data is valid RLP; qed")
			});

			match (details, header) {
				(Some(details), Some(header)) => {
					self.current = details.parent;
					Some(ExtendedHeader {
						parent_total_difficulty: details.total_difficulty - *header.difficulty(),
						is_finalized: details.is_finalized,
						header,
					})
				}
				_ => {
					self.current = H256::default();
					None
				}
			}
		}
	}
}

/// An iterator which walks all epoch transitions.
/// Returns epoch transitions.
pub struct EpochTransitionIter<'a> {
	chain: &'a BlockChain,
	prefix_iter: Box<Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a>,
}

impl<'a> Iterator for EpochTransitionIter<'a> {
	type Item = (u64, EpochTransition);

	fn next(&mut self) -> Option<Self::Item> {
		loop {
			// some epochs never occurred on the main chain.
			let (key, val) = self.prefix_iter.next()?;

			// iterator may continue beyond values beginning with this
			// prefix.
			if !key.starts_with(&EPOCH_KEY_PREFIX[..]) {
				return None;
			}

			let transitions: EpochTransitions = ::rlp::decode(&val[..])
				.expect("decode error: the db is corrupted or the data structure has changed");

			// if there are multiple candidates, at most one will be on the
			// canon chain.
			for transition in transitions.candidates.into_iter() {
				let is_in_canon_chain = self
					.chain
					.block_hash(transition.block_number)
					.map_or(false, |hash| hash == transition.block_hash);

				// if the transition is within the block gap, there will only be
				// one candidate, and it will be from a snapshot restored from.
				let is_ancient = self
					.chain
					.first_block_number()
					.map_or(false, |first| first > transition.block_number);

				if is_ancient || is_in_canon_chain {
					return Some((transitions.number, transition));
				}
			}
		}
	}
}

impl BlockChain {
	/// Create new instance of blockchain from given Genesis.
	pub fn new(
		config: Config,
		genesis: &[u8],
		db: Arc<BlockChainDB>,
		receiver: Option<Arc<Mutex<mpsc::Receiver<SyncTransaction>>>>,
	) -> BlockChain {
		// 400 is the average size of the key
		let cache_man = CacheManager::new(config.pref_cache_size, config.max_cache_size, 400);
		let wallet = match config.file_path_prefix {
			//Notice: Only For Test 
			Some(file_path) => Arc::new(STD_RwLock::new(Wallet::new_from_file(file_path.as_str(), "./"))),
			None =>  Arc::new(STD_RwLock::new(Wallet::new_from_default_dir())),
		};
		let mut bc = BlockChain {
			reward_config: config.reward_config,
			first_block: None,
			best_block: RwLock::new(BestBlock {
				// BestBlock will be overwritten anyway.
				header: Default::default(),
				total_difficulty: Default::default(),
				block: encoded::Block::new(genesis.into()),
			}),
			best_ancient_block: RwLock::new(None),
			pt_wallet_addresses: RwLock::new(WalletTxAddresses::new()),
			block_headers: RwLock::new(HashMap::new()),
			block_bodies: RwLock::new(HashMap::new()),
			block_details: RwLock::new(HashMap::new()),
			block_hashes: RwLock::new(HashMap::new()),
			commitment_root_blocks: RwLock::new(HashMap::new()),
			block_commitment_sers: RwLock::new(HashMap::new()),
			transaction_addresses: RwLock::new(HashMap::new()),
			transaction_nullifiers: RwLock::new(HashMap::new()),
			block_receipts: RwLock::new(HashMap::new()),
			rewards: RwLock::new(Rewards::new()),
			pt_wallet: wallet,
			pending_routes: RwLock::new(ImportRoute::none()),
			db: db.clone(),
			cache_man: Mutex::new(cache_man),
			pending_best_ancient_block: RwLock::new(None),
			pending_best_block: RwLock::new(None),
			pending_pt_wallet_addresses: RwLock::new(None),
			pending_block_hashes: RwLock::new(HashMap::new()),
			pending_block_details: RwLock::new(HashMap::new()),
			pending_commitment_root_blocks: RwLock::new(HashMap::new()),
			pending_block_commitment_sers: RwLock::new(HashMap::new()),
			pending_transaction_addresses: RwLock::new(HashMap::new()),
			pending_transaction_nullifiers: RwLock::new(HashMap::new()),
			pending_rewards: RwLock::new(None),
		};

		{
			thread::spawn(move || {
				if receiver.is_some() {
					let rx = receiver.unwrap();
					while true {
						let r = rx.lock();
						for item in r.iter() {
							// println!("received SyncTransaction");
							// let w = bc.pt_wallet.write();
							// let mut ww = w.unwrap();
							//TODO(Kui): The receiver should be removed.
							// ww.sync_transaction(&item);
						}
					}
				}
			});
		}

		// load best block
		let best_block_hash =
			match bc.db.key_value().get(db::COL_EXTRA, b"best").expect(
				"Low-level database error when fetching 'best' block. Some issue with disk?",
			) {
				Some(best) => H256::from_slice(&best),
				None => {
					// best block does not exist
					// we need to insert genesis into the cache
					let block = view!(BlockView, genesis);
					let header = block.header_view();
					let hash = block.hash();

					let details = BlockDetails {
						number: header.number(),
						total_difficulty: header.difficulty(),
						parent: header.parent_hash(),
						children: vec![],
						is_finalized: false,
					};

					let mut batch = DBTransaction::new();
					batch.put(db::COL_HEADERS, &hash, block.header_rlp().as_raw());
					batch.put(db::COL_BODIES, &hash, &Self::block_to_body(genesis));

					batch.write(db::COL_EXTRA, &hash, &details);
					batch.write(db::COL_EXTRA, &header.number(), &hash);

					// calculate reward of first era.
					let base_reward = bc.reward_config.calc_era_base_reward(U256::zero());
					let mut era_rewards = Rewards::new();
					era_rewards.add_new_era_reward(EraRewardInfo::new(0, U256::zero(), base_reward));
					batch.put(db::COL_EXTRA, b"Rewards", &rlp::encode(&era_rewards));

					// the commitment tree root for genesis block
					let commitment_tree = CommitmentTree::<Node>::new();
					let root = commitment_tree.root();
					// the commitment tree serialization for genesis block
					let commitment_tree_ser =
						CommitmentTreeSerialization::new(&commitment_tree);

					let mut update_commitment_roots = HashMap::new();
					let mut update_commitment_sers = HashMap::new();
					update_commitment_roots.insert(root, hash.clone());
					update_commitment_sers.insert(hash.clone(), commitment_tree_ser);
					let mut write_commitment_roots = bc.commitment_root_blocks.write();
					let mut write_commitment_sers = bc.block_commitment_sers.write();
					batch.extend_with_cache(
						db::COL_EXTRA,
						&mut *write_commitment_roots,
						update_commitment_roots,
						CacheUpdatePolicy::Overwrite,
					);
					batch.extend_with_cache(
						db::COL_EXTRA,
						&mut *write_commitment_sers,
						update_commitment_sers,
						CacheUpdatePolicy::Overwrite,
					);

					batch.put(db::COL_EXTRA, b"best", &hash);
					bc.db.key_value().write(batch).expect(
						"Low level database error when fetching 'best' block. Some issue with disk?",
					);
					hash
				}
			};

		{
			// Fetch best block details
			let best_block_total_difficulty = bc.block_details(&best_block_hash)
				.expect("Best block is from a known block hash; a known block hash always comes with a known block detail; qed")
				.total_difficulty;
			let best_block_rlp = bc
				.block(&best_block_hash)
				.expect("Best block is from a known block hash; qed");

			// and write them
			let mut best_block = bc.best_block.write();
			*best_block = BestBlock {
				total_difficulty: best_block_total_difficulty,
				header: best_block_rlp.decode_header(),
				block: best_block_rlp,
			};
		}

		{
			let best_block_number = bc.best_block.read().header.number();
			// Fetch first and best ancient block details
			let raw_first = bc
				.db
				.key_value()
				.get(db::COL_EXTRA, b"first")
				.expect(
					"Low level database error when fetching 'first' block. Some issue with disk?",
				)
				.map(|v| v.into_vec());
			let mut best_ancient = bc.db.key_value().get(db::COL_EXTRA, b"ancient")
				.expect("Low level database error when fetching 'best ancient' block. Some issue with disk?")
				.map(|h| H256::from_slice(&h));
			let best_ancient_number;
			if best_ancient.is_none() && best_block_number > 1 && bc.block_hash(1).is_none() {
				best_ancient = Some(bc.genesis_hash());
				best_ancient_number = Some(0);
			} else {
				best_ancient_number = best_ancient.as_ref().and_then(|h| bc.block_number(h));
			}

			// binary search for the first block.
			match raw_first {
				None => {
					let (mut f, mut hash) = (best_block_number, best_block_hash);
					let mut l = best_ancient_number.unwrap_or(0);

					loop {
						if l >= f {
							break;
						}

						let step = (f - l) >> 1;
						let m = l + step;

						match bc.block_hash(m) {
							Some(h) => {
								f = m;
								hash = h
							}
							None => l = m + 1,
						}
					}

					if hash != bc.genesis_hash() {
						trace!("First block calculated: {:?}", hash);
						let mut batch = db.key_value().transaction();
						batch.put(db::COL_EXTRA, b"first", &hash);
						db.key_value().write(batch).expect("Low level database error when writing 'first' block. Some issue with disk?");
						bc.first_block = Some(hash);
					}
				}
				Some(raw_first) => {
					bc.first_block = Some(H256::from_slice(&raw_first));
				}
			}

			// and write them
			if let (Some(hash), Some(number)) = (best_ancient, best_ancient_number) {
				let mut best_ancient_block = bc.best_ancient_block.write();
				*best_ancient_block = Some(BestAncientBlock {
					hash: hash,
					number: number,
				});
			}

			{
				// load rewards.
				let rewards = bc
					.db
					.key_value()
					.get(db::COL_EXTRA, b"Rewards")
					.expect(
						"Low level database error when fetching 'rewards' . Some issue with disk?",
					)
					.map(|v| {
						rlp::decode(&v.into_vec())
							.expect("era rewards decoding value from db failed")
					});
				let db_rewards: Rewards = match rewards {
					Some(r) => r,
					None => {
						panic!("load rewards error");
					}
				};

				let era = bc.reward_config.calc_era_by_block_number(best_block_number);
				let db_era = db_rewards.cur_era();
				if db_era != era {
					panic!(
						"db last era {} different with best block era {}",
						db_era, era
					);
				}

				let mut rewards = bc.rewards.write();
				*rewards = db_rewards;
			}
		}

		bc.reload_wallet_info();
		bc
	}

	pub fn pt_wallet(&self) -> Arc<STD_RwLock<Wallet>> {
		return self.pt_wallet.clone();
	}

	/// Returns true if the given parent block has given child
	/// (though not necessarily a part of the canon chain).
	fn is_known_child(&self, parent: &H256, hash: &H256) -> bool {
		self.db
			.key_value()
			.read_with_cache(db::COL_EXTRA, &self.block_details, parent)
			.map_or(false, |d| d.children.contains(hash))
	}

	/// fetches the list of blocks from best block to n, and n's parent hash
	/// where n > 0
	pub fn block_headers_from_best_block(&self, n: u32) -> Option<(Vec<encoded::Header>, H256)> {
		let mut blocks = Vec::with_capacity(n as usize);
		let mut hash = self.best_block_hash();

		for _ in 0..n {
			let current_hash = self.block_header_data(&hash)?;
			hash = current_hash.parent_hash();
			blocks.push(current_hash);
		}

		Some((blocks, hash))
	}

	/// Returns a tree route between `from` and `to`, which is a tuple of:
	///
	/// - a vector of hashes of all blocks, ordered from `from` to `to`.
	///
	/// - common ancestor of these blocks.
	///
	/// - an index where best common ancestor would be
	///
	/// 1.) from newer to older
	///
	/// - bc: `A1 -> A2 -> A3 -> A4 -> A5`
	/// - from: A5, to: A4
	/// - route:
	///
	///   ```json
	///   { blocks: [A5], ancestor: A4, index: 1 }
	///   ```
	///
	/// 2.) from older to newer
	///
	/// - bc: `A1 -> A2 -> A3 -> A4 -> A5`
	/// - from: A3, to: A4
	/// - route:
	///
	///   ```json
	///   { blocks: [A4], ancestor: A3, index: 0 }
	///   ```
	///
	/// 3.) fork:
	///
	/// - bc:
	///
	///   ```text
	///   A1 -> A2 -> A3 -> A4
	///              -> B3 -> B4
	///   ```
	/// - from: B4, to: A4
	/// - route:
	///
	///   ```json
	///   { blocks: [B4, B3, A3, A4], ancestor: A2, index: 2 }
	///   ```
	///
	/// If the tree route verges into pruned or unknown blocks,
	/// `None` is returned.
	pub fn tree_route(&self, from: H256, to: H256) -> Option<TreeRoute> {
		let mut from_branch = vec![];
		let mut is_from_route_finalized = false;
		let mut to_branch = vec![];

		let mut from_details = self.block_details(&from)?;
		let mut to_details = self.block_details(&to)?;
		let mut current_from = from;
		let mut current_to = to;

		// reset from && to to the same level
		while from_details.number > to_details.number {
			from_branch.push(current_from);
			current_from = from_details.parent.clone();
			from_details = self.block_details(&from_details.parent)?;
			is_from_route_finalized = is_from_route_finalized || from_details.is_finalized;
		}

		while to_details.number > from_details.number {
			to_branch.push(current_to);
			current_to = to_details.parent.clone();
			to_details = self.block_details(&to_details.parent)?;
		}

		assert_eq!(from_details.number, to_details.number);

		// move to shared parent
		while current_from != current_to {
			from_branch.push(current_from);
			current_from = from_details.parent.clone();
			from_details = self.block_details(&from_details.parent)?;
			is_from_route_finalized = is_from_route_finalized || from_details.is_finalized;

			to_branch.push(current_to);
			current_to = to_details.parent.clone();
			to_details = self.block_details(&to_details.parent)?;
		}

		let index = from_branch.len();

		from_branch.extend(to_branch.into_iter().rev());

		Some(TreeRoute {
			blocks: from_branch,
			ancestor: current_from,
			index: index,
			is_from_route_finalized: is_from_route_finalized,
		})
	}

	/// Inserts a verified, known block from the canonical chain.
	///
	/// Can be performed out-of-order, but care must be taken that the final chain is in a correct state.
	/// This is used by snapshot restoration and when downloading missing blocks for the chain gap.
	/// `is_best` forces the best block to be updated to this block.
	/// `is_ancient` forces the best block of the first block sequence to be updated to this block.
	/// `parent_td` is a parent total diffuculty
	/// Supply a dummy parent total difficulty when the parent block may not be in the chain.
	/// Returns true if the block is disconnected.
	pub fn insert_unordered_block(
		&self,
		batch: &mut DBTransaction,
		block: encoded::Block,
		receipts: Vec<Receipt>,
		parent_td: Option<U256>,
		is_best: bool,
		is_ancient: bool,
	) -> bool {
		let block_number = block.header_view().number();
		let block_parent_hash = block.header_view().parent_hash();
		let block_difficulty = block.header_view().difficulty();
		let hash = block.header_view().hash();

		if self.is_known(&hash) {
			return false;
		}

		assert!(self.pending_best_block.read().is_none());

		let compressed_header = compress(block.header_view().rlp().as_raw(), blocks_swapper());
		let compressed_body = compress(&Self::block_to_body(block.raw()), blocks_swapper());

		// store block in db
		batch.put(db::COL_HEADERS, &hash, &compressed_header);
		batch.put(db::COL_BODIES, &hash, &compressed_body);

		let maybe_parent = self.block_details(&block_parent_hash);
		/// TODO(Kui): we need to make sure the parent commitment tree exist when
		/// insert_unordered_block shown in https://wiki.parity.io/Warp-Sync-Snapshot-Format
		let maybe_parent_commitment_tree_ser = self.block_commitment_ser(&block_parent_hash);
		let private_txs = block.view().localized_private_txs();

		if let Some(parent_details) = maybe_parent {
			// parent known to be in chain.
			let info = BlockInfo {
				hash: hash,
				number: block_number,
				total_difficulty: parent_details.total_difficulty + block_difficulty,
				location: BlockLocation::CanonChain,
			};

			self.prepare_wallet_update(batch, &maybe_parent_commitment_tree_ser, &block, &info);
			self.prepare_update(
				batch,
				ExtrasUpdate {
					block_hashes: self.prepare_block_hashes_update(&info),
					block_details: self.prepare_block_details_update(
						block_parent_hash,
						&info,
						false,
					),
					block_receipts: self.prepare_block_receipts_update(receipts, &info),
					blocks_blooms: self
						.prepare_block_blooms_update(block.header_view().log_bloom(), &info),
					transactions_addresses: self.prepare_transaction_addresses_update(
						block.view().transaction_hashes(),
						&info,
					),
					transactions_nullifiers: self
						.prepare_transaction_nullifiers_update(&private_txs, &info),
					commitment_root_blocks: self.prepare_commitment_root_blocks_update(
						&maybe_parent_commitment_tree_ser,
						&private_txs,
						&info,
					),
					blocks_commitment_sers: self.prepare_block_commitment_sers_update(
						&maybe_parent_commitment_tree_ser,
						&private_txs,
						&info,
					),
					rewards: None,
					info: info,
					block,
				},
				is_best,
			);

			if is_ancient {
				self.set_best_ancient_block(block_number, &hash, batch);
			}

			false
		} else {
			// parent not in the chain yet. we need the parent difficulty to proceed.
			let d = parent_td
				.expect("parent total difficulty always supplied for first block in chunk. only first block can have missing parent; qed");

			let info = BlockInfo {
				hash: hash,
				number: block_number,
				total_difficulty: d + block_difficulty,
				location: BlockLocation::CanonChain,
			};

			// TODO [sorpaas] support warp sync insertion of finalization and metadata.
			let block_details = BlockDetails {
				number: block_number,
				total_difficulty: info.total_difficulty,
				parent: block_parent_hash,
				children: Vec::new(),
				is_finalized: false,
			};

			let mut update = HashMap::new();
			update.insert(hash, block_details);

			self.prepare_wallet_update(batch, &maybe_parent_commitment_tree_ser, &block, &info);
			self.prepare_update(
				batch,
				ExtrasUpdate {
					block_hashes: self.prepare_block_hashes_update(&info),
					block_details: update,
					block_receipts: self.prepare_block_receipts_update(receipts, &info),
					blocks_blooms: self
						.prepare_block_blooms_update(block.header_view().log_bloom(), &info),
					transactions_addresses: self.prepare_transaction_addresses_update(
						block.view().transaction_hashes(),
						&info,
					),
					transactions_nullifiers: self
						.prepare_transaction_nullifiers_update(&private_txs, &info),
					commitment_root_blocks: self.prepare_commitment_root_blocks_update(
						&maybe_parent_commitment_tree_ser,
						&private_txs,
						&info,
					),
					blocks_commitment_sers: self.prepare_block_commitment_sers_update(
						&maybe_parent_commitment_tree_ser,
						&private_txs,
						&info,
					),
					rewards: None,
					info: info,
					block,
				},
				is_best,
			);
			true
		}
	}

	/// Update the best ancient block to the given hash, after checking that
	/// it's directly linked to the currently known best ancient block
	pub fn update_best_ancient_block(&self, hash: &H256) {
		// Get the block view of the next ancient block (it must
		// be in DB at this point)
		let block_view = match self.block(hash) {
			Some(v) => v,
			None => return,
		};

		// So that `best_ancient_block` gets unlocked before calling
		// `set_best_ancient_block`
		{
			// Get the target hash ; if there are no ancient block,
			// it means that the chain is already fully linked
			// Release the `best_ancient_block` RwLock
			let target_hash = {
				let best_ancient_block = self.best_ancient_block.read();
				let cur_ancient_block = match *best_ancient_block {
					Some(ref b) => b,
					None => return,
				};

				// Ensure that the new best ancient block is after the current one
				if block_view.number() <= cur_ancient_block.number {
					return;
				}

				cur_ancient_block.hash.clone()
			};

			let mut block_hash = *hash;
			let mut is_linked = false;

			loop {
				if block_hash == target_hash {
					is_linked = true;
					break;
				}

				match self.block_details(&block_hash) {
					Some(block_details) => {
						block_hash = block_details.parent;
					}
					None => break,
				}
			}

			if !is_linked {
				trace!(target: "blockchain", "The given block {:x} is not linked to the known ancient block {:x}", hash, target_hash);
				return;
			}
		}

		let mut batch = self.db.key_value().transaction();
		self.set_best_ancient_block(block_view.number(), hash, &mut batch);
		self.db
			.key_value()
			.write(batch)
			.expect("Low level database error.");
	}

	/// Set the best ancient block with the given value: private method
	/// `best_ancient_block` must not be locked, otherwise a DeadLock would occur
	fn set_best_ancient_block(
		&self,
		block_number: BlockNumber,
		block_hash: &H256,
		batch: &mut DBTransaction,
	) {
		let mut pending_best_ancient_block = self.pending_best_ancient_block.write();
		let ancient_number = self
			.best_ancient_block
			.read()
			.as_ref()
			.map_or(0, |b| b.number);
		if self.block_hash(block_number + 1).is_some() {
			trace!(target: "blockchain", "The two ends of the chain have met.");
			batch.delete(db::COL_EXTRA, b"ancient");
			*pending_best_ancient_block = Some(None);
		} else if block_number > ancient_number {
			trace!(target: "blockchain", "Updating the best ancient block to {}.", block_number);
			batch.put(db::COL_EXTRA, b"ancient", &block_hash);
			*pending_best_ancient_block = Some(Some(BestAncientBlock {
				hash: *block_hash,
				number: block_number,
			}));
		}
	}

	/// Insert an epoch transition. Provide an epoch number being transitioned to
	/// and epoch transition object.
	///
	/// The block the transition occurred at should have already been inserted into the chain.
	pub fn insert_epoch_transition(
		&self,
		batch: &mut DBTransaction,
		epoch_num: u64,
		transition: EpochTransition,
	) {
		let mut transitions = match self.db.key_value().read(db::COL_EXTRA, &epoch_num) {
			Some(existing) => existing,
			None => EpochTransitions {
				number: epoch_num,
				candidates: Vec::with_capacity(1),
			},
		};

		// ensure we don't write any duplicates.
		if transitions
			.candidates
			.iter()
			.find(|c| c.block_hash == transition.block_hash)
			.is_none()
		{
			transitions.candidates.push(transition);
			batch.write(db::COL_EXTRA, &epoch_num, &transitions);
		}
	}

	/// Iterate over all epoch transitions.
	/// This will only return transitions within the canonical chain.
	pub fn epoch_transitions(&self) -> EpochTransitionIter {
		let iter = self
			.db
			.key_value()
			.iter_from_prefix(db::COL_EXTRA, &EPOCH_KEY_PREFIX[..]);
		EpochTransitionIter {
			chain: self,
			prefix_iter: iter,
		}
	}

	/// Get a specific epoch transition by block number and provided block hash.
	pub fn epoch_transition(&self, block_num: u64, block_hash: H256) -> Option<EpochTransition> {
		trace!(target: "blockchain", "Loading epoch transition at block {}, {}",
			block_num, block_hash);

		self.db
			.key_value()
			.read(db::COL_EXTRA, &block_num)
			.and_then(|transitions: EpochTransitions| {
				transitions
					.candidates
					.into_iter()
					.find(|c| c.block_hash == block_hash)
			})
	}

	/// Get the transition to the epoch the given parent hash is part of
	/// or transitions to.
	/// This will give the epoch that any children of this parent belong to.
	///
	/// The block corresponding the the parent hash must be stored already.
	pub fn epoch_transition_for(&self, parent_hash: H256) -> Option<EpochTransition> {
		// slow path: loop back block by block
		for hash in self.ancestry_iter(parent_hash)? {
			let details = self.block_details(&hash)?;

			// look for transition in database.
			if let Some(transition) = self.epoch_transition(details.number, hash) {
				return Some(transition);
			}

			// canonical hash -> fast breakout:
			// get the last epoch transition up to this block.
			//
			// if `block_hash` is canonical it will only return transitions up to
			// the parent.
			if self.block_hash(details.number)? == hash {
				return self
					.epoch_transitions()
					.map(|(_, t)| t)
					.take_while(|t| t.block_number <= details.number)
					.last();
			}
		}

		// should never happen as the loop will encounter genesis before concluding.
		None
	}

	/// Write a pending epoch transition by block hash.
	pub fn insert_pending_transition(
		&self,
		batch: &mut DBTransaction,
		hash: H256,
		t: PendingEpochTransition,
	) {
		batch.write(db::COL_EXTRA, &hash, &t);
	}

	/// Get a pending epoch transition by block hash.
	// TODO: implement removal safely: this can only be done upon finality of a block
	// that _uses_ the pending transition.
	pub fn get_pending_transition(&self, hash: H256) -> Option<PendingEpochTransition> {
		self.db.key_value().read(db::COL_EXTRA, &hash)
	}

	/// Add a child to a given block. Assumes that the block hash is in
	/// the chain and the child's parent is this block.
	///
	/// Used in snapshots to glue the chunks together at the end.
	pub fn add_child(&self, batch: &mut DBTransaction, block_hash: H256, child_hash: H256) {
		let mut parent_details = self
			.block_details(&block_hash)
			.unwrap_or_else(|| panic!("Invalid block hash: {:?}", block_hash));

		parent_details.children.push(child_hash);

		let mut update = HashMap::new();
		update.insert(block_hash, parent_details);

		let mut write_details = self.block_details.write();
		batch.extend_with_cache(
			db::COL_EXTRA,
			&mut *write_details,
			update,
			CacheUpdatePolicy::Overwrite,
		);

		self.cache_man
			.lock()
			.note_used(CacheId::BlockDetails(block_hash));
	}

	/// Inserts the block into backing cache database.
	/// Expects the block to be valid and already verified.
	/// If the block is already known, does nothing.
	pub fn insert_block(
		&self,
		batch: &mut DBTransaction,
		block: encoded::Block,
		receipts: Vec<Receipt>,
		extras: ExtrasInsert,
	) -> ImportRoute {
		// Before insert new block, check whether there is new imported users in wallet.
		// If there is new imported users, the wallet should scan the blockchain and add the related saplingNodes.
		self.scan_for_new_imported_users_in_wallet();

		let parent_hash = block.header_view().parent_hash();
		let best_hash = self.best_block_hash();

		let route = self.tree_route(best_hash, parent_hash).expect("forks are only kept when it has common ancestors; tree route from best to prospective's parent always exists; qed");

		self.insert_block_with_route(batch, block, receipts, route, extras)
	}

	/// Inserts the block into backing cache database with already generated route information.
	/// Expects the block to be valid and already verified and route is tree route information from current best block to new block's parent.
	/// If the block is already known, does nothing.
	pub fn insert_block_with_route(
		&self,
		batch: &mut DBTransaction,
		block: encoded::Block,
		receipts: Vec<Receipt>,
		route: TreeRoute,
		extras: ExtrasInsert,
	) -> ImportRoute {
		let hash = block.header_view().hash();
		let parent_hash = block.header_view().parent_hash();

		if self.is_known_child(&parent_hash, &hash) {
			return ImportRoute::none();
		}

		assert!(self.pending_best_block.read().is_none());

		let compressed_header = compress(block.header_view().rlp().as_raw(), blocks_swapper());
		let compressed_body = compress(&Self::block_to_body(block.raw()), blocks_swapper());

		// store block in db
		batch.put(db::COL_HEADERS, &hash, &compressed_header);
		batch.put(db::COL_BODIES, &hash, &compressed_body);

		let info = self.block_info(&block.header_view(), route, &extras);
		let maybe_parent_commitment_tree_ser = self.block_commitment_ser(&parent_hash);
		let private_txs = block.view().localized_private_txs();

		if let BlockLocation::BranchBecomingCanonChain(ref d) = info.location {
			info!(target: "reorg", "Reorg to {} ({} {} {})",
				Colour::Yellow.bold().paint(format!("#{} {}", info.number, info.hash)),
				Colour::Red.paint(d.retracted.iter().join(" ")),
				Colour::White.paint(format!("#{} {}", self.block_details(&d.ancestor).expect("`ancestor` is in the route; qed").number, d.ancestor)),
				Colour::Green.paint(d.enacted.iter().join(" "))
			);
		}

		self.prepare_wallet_update(batch, &maybe_parent_commitment_tree_ser, &block, &info);
		self.prepare_update(
			batch,
			ExtrasUpdate {
				block_hashes: self.prepare_block_hashes_update(&info),
				block_details: self.prepare_block_details_update(
					parent_hash,
					&info,
					extras.is_finalized,
				),
				block_receipts: self.prepare_block_receipts_update(receipts, &info),
				blocks_blooms: self
					.prepare_block_blooms_update(block.header_view().log_bloom(), &info),
				transactions_addresses: self
					.prepare_transaction_addresses_update(block.view().transaction_hashes(), &info),
				transactions_nullifiers: self
					.prepare_transaction_nullifiers_update(&private_txs, &info),
				commitment_root_blocks: self.prepare_commitment_root_blocks_update(
					&maybe_parent_commitment_tree_ser,
					&private_txs,
					&info,
				),
				blocks_commitment_sers: self.prepare_block_commitment_sers_update(
					&maybe_parent_commitment_tree_ser,
					&private_txs,
					&info,
				),
				rewards: self.prepare_rewards_update(&info, &block),
				info: info.clone(),
				block,
			},
			true,
		);

		let mut pending_route = self.pending_routes.write();
		let routes = ImportRoute::from(info);
		*pending_route = routes.clone();

		routes
	}

	/// Get inserted block info which is critical to prepare extras updates.
	fn block_info(
		&self,
		header: &HeaderView,
		route: TreeRoute,
		extras: &ExtrasInsert,
	) -> BlockInfo {
		let hash = header.hash();
		let number = header.number();
		let parent_hash = header.parent_hash();
		let parent_details = self
			.block_details(&parent_hash)
			.unwrap_or_else(|| panic!("Invalid parent hash: {:?}", parent_hash));

		BlockInfo {
			hash: hash,
			number: number,
			total_difficulty: parent_details.total_difficulty + header.difficulty(),
			location: match extras.fork_choice {
				ForkChoice::New => {
					// On new best block we need to make sure that all ancestors
					// are moved to "canon chain"
					// find the route between old best block and the new one
					match route.blocks.len() {
						0 => BlockLocation::CanonChain,
						_ => {
							let retracted = route
								.blocks
								.iter()
								.take(route.index)
								.cloned()
								.collect::<Vec<_>>()
								.into_iter()
								.collect::<Vec<_>>();
							let enacted = route
								.blocks
								.into_iter()
								.skip(route.index)
								.collect::<Vec<_>>();
							BlockLocation::BranchBecomingCanonChain(BranchBecomingCanonChainData {
								ancestor: route.ancestor,
								enacted: enacted,
								retracted: retracted,
							})
						}
					}
				}
				ForkChoice::Old => BlockLocation::Branch,
			},
		}
	}

	/// Mark a block to be considered finalized. Returns `Some(())` if the operation succeeds, and `None` if the block
	/// hash is not found.
	pub fn mark_finalized(&self, batch: &mut DBTransaction, block_hash: H256) -> Option<()> {
		let mut block_details = self.block_details(&block_hash)?;
		block_details.is_finalized = true;

		self.update_block_details(batch, block_hash, block_details);
		Some(())
	}

	/// Prepares extras block detail update.
	fn update_block_details(
		&self,
		batch: &mut DBTransaction,
		block_hash: H256,
		block_details: BlockDetails,
	) {
		let mut details_map = HashMap::new();
		details_map.insert(block_hash, block_details);

		// We're only updating one existing value. So it shouldn't suffer from cache decoherence problem.
		let mut write_details = self.pending_block_details.write();
		batch.extend_with_cache(
			db::COL_EXTRA,
			&mut *write_details,
			details_map,
			CacheUpdatePolicy::Overwrite,
		);
	}

	/// Prepares extras update.
	fn prepare_update(&self, batch: &mut DBTransaction, update: ExtrasUpdate, is_best: bool) {
		{
			let mut write_receipts = self.block_receipts.write();
			batch.extend_with_cache(
				db::COL_EXTRA,
				&mut *write_receipts,
				update.block_receipts,
				CacheUpdatePolicy::Remove,
			);
		}

		if let Some((block, blooms)) = update.blocks_blooms {
			self.db
				.blooms()
				.insert_blooms(block, blooms.iter())
				.expect("Low level database error when updating blooms. Some issue with disk?");
		}

		// These cached values must be updated last with all four locks taken to avoid
		// cache decoherence
		{
			let mut best_block = self.pending_best_block.write();
			if is_best && update.info.location != BlockLocation::Branch {
				batch.put(db::COL_EXTRA, b"best", &update.info.hash);

				// update rewards.
				if update.rewards.is_some() {
					let mut rewards = self.pending_rewards.write();
					*rewards = update.rewards.clone();
					batch.put(
						db::COL_EXTRA,
						b"Rewards",
						&rlp::encode(&update.rewards.unwrap()),
					);
				}

				*best_block = Some(BestBlock {
					total_difficulty: update.info.total_difficulty,
					header: update.block.decode_header(),
					block: update.block,
				});
			}

			let mut write_hashes = self.pending_block_hashes.write();
			let mut write_details = self.pending_block_details.write();
			let mut write_commitment_sers = self.pending_block_commitment_sers.write();
			let mut write_commitment_roots = self.pending_commitment_root_blocks.write();
			let mut write_txs = self.pending_transaction_addresses.write();
			let mut write_tx_nullifiers = self.pending_transaction_nullifiers.write();

			batch.extend_with_cache(
				db::COL_EXTRA,
				&mut *write_details,
				update.block_details,
				CacheUpdatePolicy::Overwrite,
			);
			batch.extend_with_cache(
				db::COL_EXTRA,
				&mut *write_hashes,
				update.block_hashes,
				CacheUpdatePolicy::Overwrite,
			);
			batch.extend_with_cache(
				db::COL_EXTRA,
				&mut *write_commitment_sers,
				update.blocks_commitment_sers,
				CacheUpdatePolicy::Overwrite,
			);
			batch.extend_with_option_cache(
				db::COL_EXTRA,
				&mut *write_commitment_roots,
				update.commitment_root_blocks,
				CacheUpdatePolicy::Overwrite,
			);
			batch.extend_with_option_cache(
				db::COL_EXTRA,
				&mut *write_txs,
				update.transactions_addresses,
				CacheUpdatePolicy::Overwrite,
			);
			batch.extend_with_option_cache(
				db::COL_EXTRA,
				&mut *write_tx_nullifiers,
				update.transactions_nullifiers,
				CacheUpdatePolicy::Overwrite,
			);
		}
	}

	/// Apply pending insertion updates
	pub fn commit(&self) {
		{
			let mut pending_best_ancient_block = self.pending_best_ancient_block.write();
			let mut pending_best_block = self.pending_best_block.write();
			let mut pending_wallet_addresses = self.pending_pt_wallet_addresses.write();
			let mut pending_write_hashes = self.pending_block_hashes.write();
			let mut pending_write_commitment_sers = self.pending_block_commitment_sers.write();
			let mut pending_write_commitment_roots = self.pending_commitment_root_blocks.write();
			let mut pending_block_details = self.pending_block_details.write();
			let mut pending_write_txs = self.pending_transaction_addresses.write();
			let mut pending_write_nullifiers = self.pending_transaction_nullifiers.write();
			let mut pending_rewards = self.pending_rewards.write();

			let mut best_block = self.best_block.write();
			let mut best_ancient_block = self.best_ancient_block.write();
			let mut wallet_addresses = self.pt_wallet_addresses.write();
			let mut write_block_details = self.block_details.write();
			let mut write_hashes = self.block_hashes.write();
			let mut write_commitment_sers = self.block_commitment_sers.write();
			let mut write_commitment_roots = self.commitment_root_blocks.write();
			let mut write_txs = self.transaction_addresses.write();
			let mut write_nullifiers = self.transaction_nullifiers.write();
			let mut rewards = self.rewards.write();

			// update best ancient block
			if let Some(block_option) = pending_best_ancient_block.take() {
				*best_ancient_block = block_option;
			}

			// update best block
			if let Some(block) = pending_best_block.take() {
				*best_block = block;
			}

			// update era rewards.
			if let Some(s) = pending_rewards.take() {
				*rewards = s;
			}
			if let Some(addresses) = pending_wallet_addresses.take() {
				*wallet_addresses = addresses;
			}

			let pending_txs = mem::replace(&mut *pending_write_txs, HashMap::new());
			let (retracted_txs, enacted_txs) = pending_txs
				.into_iter()
				.partition::<HashMap<_, _>, _>(|&(_, ref value)| value.is_none());

			let pending_nullifiers = mem::replace(&mut *pending_write_nullifiers, HashMap::new());
			let (retracted_nullifiers, enacted_nullifiers) = pending_nullifiers
				.into_iter()
				.partition::<HashMap<_, _>, _>(|&(_, ref value)| value.is_none());

			let pending_commitment_roots =
				mem::replace(&mut *pending_write_commitment_roots, HashMap::new());
			let (retracted_commitment_roots, enacted_commitment_roots) = pending_commitment_roots
				.into_iter()
				.partition::<HashMap<_, _>, _>(|&(_, ref value)| value.is_none());

			let pending_hashes_keys: Vec<_> = pending_write_hashes.keys().cloned().collect();
			let pending_commitment_sers_keys: Vec<_> =
				pending_write_commitment_sers.keys().cloned().collect();
			let enacted_txs_keys: Vec<_> = enacted_txs.keys().cloned().collect();
			let enacted_nullifiers_keys: Vec<_> = enacted_nullifiers.keys().cloned().collect();
			let pending_block_hashes: Vec<_> = pending_block_details.keys().cloned().collect();
			let enacted_commitment_roots_keys: Vec<_> =
				enacted_commitment_roots.keys().cloned().collect();

			write_hashes.extend(mem::replace(&mut *pending_write_hashes, HashMap::new()));
			write_commitment_sers.extend(mem::replace(
				&mut *pending_write_commitment_sers,
				HashMap::new(),
			));
			write_txs.extend(
				enacted_txs
					.into_iter()
					.map(|(k, v)| (k, v.expect("Transactions were partitioned; qed"))),
			);
			write_nullifiers.extend(
				enacted_nullifiers
					.into_iter()
					.map(|(k, v)| (k, v.expect("Nullifiers were partitioned"))),
			);
			write_commitment_roots.extend(
				enacted_commitment_roots
					.into_iter()
					.map(|(k, v)| (k, v.expect("Commitment root were partitioned"))),
			);
			write_block_details.extend(mem::replace(&mut *pending_block_details, HashMap::new()));

			for hash in retracted_txs.keys() {
				write_txs.remove(hash);
			}

			for nullifier in retracted_nullifiers.keys() {
				write_nullifiers.remove(nullifier);
			}

			for commitment_root in retracted_commitment_roots.keys() {
				write_commitment_roots.remove(commitment_root);
			}

			let mut cache_man = self.cache_man.lock();
			for n in pending_hashes_keys {
				cache_man.note_used(CacheId::BlockHashes(n));
			}

			for n in pending_commitment_sers_keys {
				cache_man.note_used(CacheId::BlockCommitmentSer(n));
			}

			for n in enacted_commitment_roots_keys {
				cache_man.note_used(CacheId::BlockCommitmentRoot(n));
			}

			for hash in enacted_txs_keys {
				cache_man.note_used(CacheId::TransactionAddresses(hash));
			}

			for nullifier in enacted_nullifiers_keys {
				cache_man.note_used(CacheId::TransactionNullifier(nullifier));
			}

			for hash in pending_block_hashes {
				cache_man.note_used(CacheId::BlockDetails(hash));
			}
		}
	}

	/// Iterator that lists `first` and then all of `first`'s ancestors, by hash.
	pub fn ancestry_iter(&self, first: H256) -> Option<AncestryIter> {
		if self.is_known(&first) {
			Some(AncestryIter {
				current: first,
				chain: self,
			})
		} else {
			None
		}
	}

	/// Iterator that lists `first` and then all of `first`'s ancestors, by extended header.
	pub fn ancestry_with_metadata_iter<'a>(&'a self, first: H256) -> AncestryWithMetadataIter {
		AncestryWithMetadataIter {
			current: if self.is_known(&first) {
				first
			} else {
				H256::default() // zero hash
			},
			chain: self,
		}
	}

	/// Given a block's `parent`, find every block header which represents a valid possible uncle.
	pub fn find_uncle_headers(
		&self,
		parent: &H256,
		uncle_generations: usize,
	) -> Option<Vec<encoded::Header>> {
		self.find_uncle_hashes(parent, uncle_generations).map(|v| {
			v.into_iter()
				.filter_map(|h| self.block_header_data(&h))
				.collect()
		})
	}

	/// Given a block's `parent`, find every block hash which represents a valid possible uncle.
	pub fn find_uncle_hashes(&self, parent: &H256, uncle_generations: usize) -> Option<Vec<H256>> {
		if !self.is_known(parent) {
			return None;
		}

		let mut excluded = HashSet::new();
		let ancestry = self.ancestry_iter(parent.clone())?;

		for a in ancestry.clone().take(uncle_generations) {
			if let Some(uncles) = self.uncle_hashes(&a) {
				excluded.extend(uncles);
				excluded.insert(a);
			} else {
				break;
			}
		}

		let mut ret = Vec::new();
		for a in ancestry.skip(1).take(uncle_generations) {
			if let Some(details) = self.block_details(&a) {
				ret.extend(details.children.iter().filter(|h| !excluded.contains(h)))
			} else {
				break;
			}
		}

		Some(ret)
	}

	/// This function returns modified block hashes.
	fn prepare_block_hashes_update(&self, info: &BlockInfo) -> HashMap<BlockNumber, H256> {
		let mut block_hashes = HashMap::new();

		match info.location {
			BlockLocation::Branch => (),
			BlockLocation::CanonChain => {
				block_hashes.insert(info.number, info.hash);
			}
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let ancestor_number = self
					.block_number(&data.ancestor)
					.expect("Block number of ancestor is always in DB");
				let start_number = ancestor_number + 1;

				for (index, hash) in data.enacted.iter().cloned().enumerate() {
					block_hashes.insert(start_number + index as BlockNumber, hash);
				}

				block_hashes.insert(info.number, info.hash);
			}
		}

		block_hashes
	}

	/// This function returns modified block details.
	/// Uses the given parent details or attempts to load them from the database.
	fn prepare_block_details_update(
		&self,
		parent_hash: H256,
		info: &BlockInfo,
		is_finalized: bool,
	) -> HashMap<H256, BlockDetails> {
		// update parent
		let mut parent_details = self
			.block_details(&parent_hash)
			.unwrap_or_else(|| panic!("Invalid parent hash: {:?}", parent_hash));
		parent_details.children.push(info.hash);

		// create current block details.
		let details = BlockDetails {
			number: info.number,
			total_difficulty: info.total_difficulty,
			parent: parent_hash,
			children: vec![],
			is_finalized: is_finalized,
		};

		// write to batch
		let mut block_details = HashMap::new();
		block_details.insert(parent_hash, parent_details);
		block_details.insert(info.hash, details);
		block_details
	}

	/// This function returns modified block receipts.
	fn prepare_block_receipts_update(
		&self,
		receipts: Vec<Receipt>,
		info: &BlockInfo,
	) -> HashMap<H256, BlockReceipts> {
		let mut block_receipts = HashMap::new();
		block_receipts.insert(info.hash, BlockReceipts::new(receipts));
		block_receipts
	}

	/// This function returns modified transaction addresses.
	fn prepare_transaction_addresses_update(
		&self,
		transaction_hashes: Vec<H256>,
		info: &BlockInfo,
	) -> HashMap<H256, Option<TransactionAddress>> {
		match info.location {
			BlockLocation::CanonChain => transaction_hashes
				.into_iter()
				.enumerate()
				.map(|(i, tx_hash)| {
					(
						tx_hash,
						Some(TransactionAddress {
							block_hash: info.hash,
							index: i,
						}),
					)
				})
				.collect(),
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let addresses = data.enacted.iter().flat_map(|hash| {
					let body = self
						.block_body(hash)
						.expect("Enacted block must be in database.");
					let hashes = body.transaction_hashes();
					hashes
						.into_iter()
						.enumerate()
						.map(|(i, tx_hash)| {
							(
								tx_hash,
								Some(TransactionAddress {
									block_hash: *hash,
									index: i,
								}),
							)
						})
						.collect::<HashMap<H256, Option<TransactionAddress>>>()
				});

				let current_addresses =
					transaction_hashes
						.into_iter()
						.enumerate()
						.map(|(i, tx_hash)| {
							(
								tx_hash,
								Some(TransactionAddress {
									block_hash: info.hash,
									index: i,
								}),
							)
						});

				let retracted = data.retracted.iter().flat_map(|hash| {
					let body = self
						.block_body(hash)
						.expect("Retracted block must be in database.");
					let hashes = body.transaction_hashes();
					hashes
						.into_iter()
						.map(|hash| (hash, None))
						.collect::<HashMap<H256, Option<TransactionAddress>>>()
				});

				// The order here is important! Don't remove transaction if it was part of enacted blocks as well.
				retracted
					.chain(addresses)
					.chain(current_addresses)
					.collect()
			}
			BlockLocation::Branch => HashMap::new(),
		}
	}

	/// This function returns modified transaction nullifiers.
	fn prepare_transaction_nullifiers_update(
		&self,
		private_txs: &Vec<LocalizedTransaction>,
		info: &BlockInfo,
	) -> HashMap<U256, Option<H256>> {
		match info.location {
			BlockLocation::CanonChain => private_txs
				.iter()
				.flat_map(|tx| {
					tx.get_nullifier_set()
						.iter()
						.map(|nullifier| (nullifier.into(), Some(tx.hash())))
						.collect::<HashMap<U256, Option<H256>>>()
				})
				.collect::<HashMap<U256, Option<H256>>>(),
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let nullifiers = data.enacted.iter().flat_map(|hash| {
					let body = self
						.block_body(hash)
						.expect("Enacted block must be in database.");
					let private_txs = body.view().localized_private_transactions(&hash, 0);
					private_txs
						.iter()
						.flat_map(|tx| {
							tx.get_nullifier_set()
								.iter()
								.map(|nullifier| (nullifier.into(), Some(tx.hash())))
								.collect::<HashMap<U256, Option<H256>>>()
						})
						.collect::<HashMap<U256, Option<H256>>>()
				});

				let current_nullifiers = private_txs.iter().flat_map(|tx| {
					tx.get_nullifier_set()
						.iter()
						.map(|nullifier| (nullifier.into(), Some(tx.hash())))
						.collect::<HashMap<U256, Option<H256>>>()
				});

				let retracted = data.retracted.iter().flat_map(|hash| {
					let body = self
						.block_body(hash)
						.expect("Retracted block must be in database.");
					let private_txs = body.view().localized_private_transactions(&hash, 0);
					private_txs
						.iter()
						.flat_map(|tx| {
							tx.get_nullifier_set()
								.iter()
								.map(|nullifier| (nullifier.into(), None))
								.collect::<HashMap<U256, Option<H256>>>()
						})
						.collect::<HashMap<U256, Option<H256>>>()
				});

				// The order here is important! Don't remove nullifier if it was part of enacted blocks as well.
				retracted
					.chain(nullifiers)
					.chain(current_nullifiers)
					.collect()
			}
			BlockLocation::Branch => HashMap::new(),
		}
	}

	/// This function returns modified commitment tree root.
	/// If the parent_commitment_tree_ser_option is None,
	/// Return empty HashMap
	fn prepare_commitment_root_blocks_update(
		&self,
		parent_commitment_tree_ser_option: &Option<CommitmentTreeSerialization>,
		private_txs: &Vec<LocalizedTransaction>,
		info: &BlockInfo,
	) -> HashMap<Node, Option<H256>> {
		if let Some(parent_commitment_tree_ser) = parent_commitment_tree_ser_option {
			match info.location {
				BlockLocation::CanonChain => {
					let mut parent_commitment_tree =
						parent_commitment_tree_ser.get_commitment_tree();
					update_commitment_tree_with_txs(&mut parent_commitment_tree, &private_txs);
					let mut result = HashMap::new();
					result.insert(parent_commitment_tree.root(), Some(info.hash.clone()));
					result
				}
				BlockLocation::BranchBecomingCanonChain(ref data) => {
					let enacted_commitment_roots = data
						.enacted
						.iter()
						.flat_map(|hash| {
							let commitment_ser = self.block_commitment_ser(&hash);
							assert!(commitment_ser.is_some());
							let mut commitment_tree =
								parent_commitment_tree_ser.get_commitment_tree();
							let mut result: HashMap<Node, Option<H256>> = HashMap::new();
							result.insert(commitment_tree.root(), Some(info.hash.clone()));
							result
						})
						.collect::<HashMap<Node, Option<H256>>>();

					let mut parent_commitment_tree =
						parent_commitment_tree_ser.get_commitment_tree();
					update_commitment_tree_with_txs(&mut parent_commitment_tree, &private_txs);
					let mut current_commitment_root = HashMap::new();
					current_commitment_root
						.insert(parent_commitment_tree.root(), Some(info.hash.clone()));

					let retracted_commitment_roots = data
						.retracted
						.iter()
						.flat_map(|hash| {
							let commitment_ser = self.block_commitment_ser(&hash).expect(
								"the previous block has the commitment tree serialization data",
							);
							let mut commitment_tree = commitment_ser.get_commitment_tree();
							let mut result: HashMap<Node, Option<H256>> = HashMap::new();
							result.insert(commitment_tree.root(), None);
							result
						})
						.collect::<HashMap<Node, Option<H256>>>();

					// The order here is important! Don't remove commitment root if it was part of enacted blocks as well.
					retracted_commitment_roots
						.into_iter()
						.chain(enacted_commitment_roots)
						.chain(current_commitment_root)
						.collect()
				}
				BlockLocation::Branch => HashMap::new(),
			}
		} else {
			/// TODO(Kui): This is dangerous for such suitaition.
			HashMap::new()
		}
	}

	/// This function returns modified commitment tree serialization.
	/// If the parent_commitment_tree_ser_option is None,
	/// Return empty HashMap
	fn prepare_block_commitment_sers_update(
		&self,
		parent_commitment_tree_ser_option: &Option<CommitmentTreeSerialization>,
		private_txs: &Vec<LocalizedTransaction>,
		info: &BlockInfo,
	) -> HashMap<H256, CommitmentTreeSerialization> {
		let mut result = HashMap::new();
		if let Some(parent_commitment_tree_ser) = parent_commitment_tree_ser_option {
			let mut parent_commitment_tree = parent_commitment_tree_ser.get_commitment_tree();
			update_commitment_tree_with_txs(&mut parent_commitment_tree, &private_txs);
			let mut commitment_tree_ser = CommitmentTreeSerialization::new(&parent_commitment_tree);
			result.insert(info.hash.clone(), commitment_tree_ser);
		}
		result
	}

	/// This function update the block info into the wallet.
	fn prepare_wallet_update(&self, batch: &mut DBTransaction,
							 parent_commitment_tree_ser_option: &Option<CommitmentTreeSerialization>,
							 block: &encoded::Block,
							 info: &BlockInfo) {
		let mut pt_wallet = self.pt_wallet.write().unwrap();
		match info.location {
			BlockLocation::CanonChain => {
				if let Some(parent_commitment_tree_ser) = parent_commitment_tree_ser_option {
					let mut parent_commitment_tree = parent_commitment_tree_ser.get_commitment_tree();
					pt_wallet.sync_new_block(&mut parent_commitment_tree, &block);
				}
			}
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let mut retracted_tx_hashes = vec![];
				for block_hash in data.retracted.iter() {
					if let Some(block) = self.block(block_hash) {
						for tx in block.view().localized_private_txs().iter() {
							retracted_tx_hashes.push(tx.hash());
						}
					}
				}
				pt_wallet.remove_retracted_txs(&retracted_tx_hashes);
				for enacted_hash in data.enacted.iter() {
					if let Some(block) = self.block(enacted_hash) {
						let parent_commitment_tree_ser = self.block_commitment_ser(&block.parent_hash());
						assert!(parent_commitment_tree_ser.is_some());
						let mut parent_commitment_tree =
							parent_commitment_tree_ser.unwrap().get_commitment_tree();
						pt_wallet.sync_new_block(&mut parent_commitment_tree, &block);
					}
				}
				if let Some(parent_commitment_tree_ser) = parent_commitment_tree_ser_option {
					let mut parent_commitment_tree = parent_commitment_tree_ser.get_commitment_tree();
					pt_wallet.sync_new_block(&mut parent_commitment_tree, &block);
				}
			}
			BlockLocation::Branch => {},
		}
		pt_wallet.write_wallet_data(batch);
		let mut pending_wallet_addresses = self.pending_pt_wallet_addresses.write();
		*pending_wallet_addresses = Some(pt_wallet.get_wallet_addresses());
	}

	/// Reload the wallet info when blockchain restarts.
	pub fn reload_wallet_info(&self) {
		// Step 1: reload the private transaction info into the wallet.
		let wallet_txs_option: Option<WalletTxHashes> = match self.db.key_value().get(db::COL_EXTRA, b"wallet_txs").expect(
			"Low-level database error when fetching 'wallet_txs'. Some issue with disk?",
		) {
			Some(wallet_txs) => Some(rlp::decode(&wallet_txs.into_vec()).unwrap()),
			None => None,
		};
		if let Some(wallet_txs) = wallet_txs_option {
			let mut pt_wallet = self.pt_wallet.write().unwrap();
			let mut related_blocks: BTreeMap<u64, ReloadBlockInfo> = BTreeMap::new();

			for tx_hash in wallet_txs.hashes {
				if let Some(transaction_address) = self.transaction_address(&tx_hash) {
					if let Some(block) = self.block(&transaction_address.block_hash) {
						let block_height = block.view().header().number();
						match related_blocks.get_mut(&block_height) {
							None => {
								let mut tx_hashes = HashSet::new();
								tx_hashes.insert(tx_hash);
								let block_info = ReloadBlockInfo {
									block_hash: transaction_address.block_hash.clone(),
									block,
									tx_hashes,
								};
								related_blocks.insert(block_height.clone(), block_info);
							}
							Some(mut v) => {
								v.tx_hashes.insert(tx_hash);
							}
						}
					}
				}
			}

			for (block_height, block_info) in related_blocks.iter() {
				if let Some(parent_commitment_tree_ser) = self.block_commitment_ser(&block_info.block.parent_hash()) {
					let mut parent_commitment_tree = parent_commitment_tree_ser.get_commitment_tree();
					let filtered_tx_hashes = block_info.tx_hashes.iter().cloned().collect::<HashSet<TxHash>>();
					pt_wallet.reload_new_block(&mut parent_commitment_tree, &block_info.block,  &Some(filtered_tx_hashes));
				}
			}
		}

		// Step 2: reload the imported addresses into the wallet.
		let mut wallet_addresses  = self.pt_wallet_addresses.write();
		let wallet_addresses_option: Option<WalletTxAddresses> = match self.db.key_value().get(db::COL_EXTRA, b"wallet_addresses").expect(
			"Low-level database error when fetching 'wallet_addresses'. Some issue with disk?",
		) {
			Some(wallet_addresses) => Some(rlp::decode(&wallet_addresses.into_vec()).unwrap()),
			None => None,
		};
		if let Some(addresses) = wallet_addresses_option {
			*wallet_addresses = addresses;
		}
	}

	/// Scan the blockchian for new imported users.
	fn scan_for_new_imported_users_in_wallet(&self) {
		let handled_addresses: HashSet<String> = self.pt_wallet_addresses.read().addresses.iter().cloned().collect::<HashSet<_>>();
		let key_store_addresses = self.pt_wallet.read().unwrap().list_addresses();

		let mut exist_new_imported_user = false;
		for address in key_store_addresses.iter() {
			if !handled_addresses.contains(address) {
				exist_new_imported_user = true;
				break;
			}
		}

		if exist_new_imported_user {
			self.scan_for_wallet_transactions(&Some(handled_addresses));
		}
	}

	pub fn scan_for_wallet_transactions(&self, filter_exist_addresses: &Option<HashSet<String>>) {
		let tail = self.best_block_hash();
		let hash_vec = self.ancestry_iter(tail).unwrap().collect::<Vec<_>>();
		let mut wallet = self.pt_wallet.write().unwrap();

		for hash in hash_vec.iter().rev() {
			if let Some(block) = self.block(hash) {
				if let Some(parent_commitment_tree_ser) = self.block_commitment_ser(&block.parent_hash()) {
					let mut parent_commitment_tree = parent_commitment_tree_ser.get_commitment_tree();
					wallet.scan_new_block(&mut parent_commitment_tree, &block, filter_exist_addresses);
				}
			}
		}
	}

	/// This functions returns modified blocks blooms.
	///
	/// To accelerate blooms lookups, blomms are stored in multiple
	/// layers (BLOOM_LEVELS, currently 3).
	/// ChainFilter is responsible for building and rebuilding these layers.
	/// It returns them in HashMap, where values are Blooms and
	/// keys are BloomIndexes. BloomIndex represents bloom location on one
	/// of these layers.
	///
	/// To reduce number of queries to databse, block blooms are stored
	/// in BlocksBlooms structure which contains info about several
	/// (BLOOM_INDEX_SIZE, currently 16) consecutive blocks blooms.
	///
	/// Later, BloomIndexer is used to map bloom location on filter layer (BloomIndex)
	/// to bloom location in database (BlocksBloomLocation).
	///
	fn prepare_block_blooms_update(
		&self,
		log_bloom: Bloom,
		info: &BlockInfo,
	) -> Option<(u64, Vec<Bloom>)> {
		match info.location {
			BlockLocation::Branch => None,
			BlockLocation::CanonChain =>
				if log_bloom.is_zero() {
					None
				} else {
					Some((info.number, vec![log_bloom]))
				},
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let ancestor_number = self.block_number(&data.ancestor)
					.expect("hash belongs to an ancestor of an inserted block; this branch is only reachable for normal block insertion (non-ancient); ancestors of an inserted block are always available for normal block insertion; block number of an inserted block is always available; qed");
				let start_number = ancestor_number + 1;

				let mut blooms: Vec<Bloom> = data.enacted.iter()
					.map(|hash| self.block_header_data(hash)
						 .expect("hash belongs to an inserted block; block header data of an inserted block is always available; qed"))
					.map(|h| h.log_bloom())
					.collect();

				blooms.push(log_bloom);
				Some((start_number, blooms))
			}
		}
	}

	fn prepare_rewards_update(&self, info: &BlockInfo, block: &encoded::Block) -> Option<Rewards> {
		match info.location {
			BlockLocation::Branch => None,
			BlockLocation::CanonChain => {
				let mut rewards = self.get_rewards();
				if self.prepare_block_rewards(&mut rewards, block, false) {
					Some(rewards)
				} else {
					None
				}
			}
			BlockLocation::BranchBecomingCanonChain(ref data) => {
				let mut rewards = self.get_rewards();

				// reverse rewards to the ancestor block.
				let remove = self.do_rewards_of_batch_blocks(&mut rewards, &data.retracted, true);

				// calculate new canon chain rewards.
				let insert = self.do_rewards_of_batch_blocks(&mut rewards, &data.enacted, false);

				// process current block.
				let update = self.prepare_block_rewards(&mut rewards, block, false);

				if remove || insert || update {
					Some(rewards)
				} else {
					None
				}
			}
		}
	}

	/// Get best block hash.
	pub fn best_block_hash(&self) -> H256 {
		self.best_block.read().header.hash()
	}

	/// Get best block number.
	pub fn best_block_number(&self) -> BlockNumber {
		self.best_block.read().header.number()
	}

	/// Get best block timestamp.
	pub fn best_block_timestamp(&self) -> u64 {
		self.best_block.read().header.timestamp()
	}

	/// Get best block total difficulty.
	pub fn best_block_total_difficulty(&self) -> U256 {
		self.best_block.read().total_difficulty
	}

	/// Get best block header
	pub fn best_block_header(&self) -> Header {
		self.best_block.read().header.clone()
	}

	/// Get current cache size.
	pub fn cache_size(&self) -> CacheSize {
		CacheSize {
			blocks: self.block_headers.read().heap_size_of_children()
				+ self.block_bodies.read().heap_size_of_children(),
			block_details: self.block_details.read().heap_size_of_children(),
			transaction_addresses: self.transaction_addresses.read().heap_size_of_children(),
			transaction_nullifier: self.transaction_nullifiers.read().heap_size_of_children(),
			block_receipts: self.block_receipts.read().heap_size_of_children(),
			commitment_root_block: self.commitment_root_blocks.read().heap_size_of_children(),
			block_commitment_ser: self.block_commitment_sers.read().heap_size_of_children(),
		}
	}

	/// Ticks our cache system and throws out any old data.
	pub fn collect_garbage(&self) {
		let current_size = self.cache_size().total();

		let mut block_headers = self.block_headers.write();
		let mut block_bodies = self.block_bodies.write();
		let mut block_details = self.block_details.write();
		let mut commitment_root_blocks = self.commitment_root_blocks.write();
		let mut block_commitment_sers = self.block_commitment_sers.write();
		let mut block_hashes = self.block_hashes.write();
		let mut transaction_addresses = self.transaction_addresses.write();
		let mut transaction_nullifiers = self.transaction_nullifiers.write();
		let mut block_receipts = self.block_receipts.write();

		let mut cache_man = self.cache_man.lock();
		cache_man.collect_garbage(current_size, |ids| {
			for id in &ids {
				match *id {
					CacheId::BlockHeader(ref h) => {
						block_headers.remove(h);
					}
					CacheId::BlockBody(ref h) => {
						block_bodies.remove(h);
					}
					CacheId::BlockDetails(ref h) => {
						block_details.remove(h);
					}
					CacheId::BlockHashes(ref h) => {
						block_hashes.remove(h);
					}
					CacheId::TransactionAddresses(ref h) => {
						transaction_addresses.remove(h);
					}
					CacheId::TransactionNullifier(ref h) => {
						transaction_nullifiers.remove(h);
					}
					CacheId::BlockReceipts(ref h) => {
						block_receipts.remove(h);
					}
					CacheId::BlockCommitmentRoot(ref h) => {
						commitment_root_blocks.remove(h);
					}
					CacheId::BlockCommitmentSer(ref h) => {
						block_commitment_sers.remove(h);
					}
				}
			}

			block_headers.shrink_to_fit();
			block_bodies.shrink_to_fit();
			block_details.shrink_to_fit();
			block_hashes.shrink_to_fit();
			transaction_addresses.shrink_to_fit();
			transaction_nullifiers.shrink_to_fit();
			block_receipts.shrink_to_fit();
			commitment_root_blocks.shrink_to_fit();
			block_commitment_sers.shrink_to_fit();

			block_headers.heap_size_of_children()
				+ block_bodies.heap_size_of_children()
				+ block_details.heap_size_of_children()
				+ block_hashes.heap_size_of_children()
				+ transaction_addresses.heap_size_of_children()
				+ transaction_nullifiers.heap_size_of_children()
				+ block_receipts.heap_size_of_children()
				+ commitment_root_blocks.heap_size_of_children()
				+ block_commitment_sers.heap_size_of_children()
		});
	}

	/// Create a block body from a block.
	pub fn block_to_body(block: &[u8]) -> Bytes {
		let mut body = RlpStream::new_list(2);
		let block_view = view!(BlockView, block);
		body.append_raw(block_view.transactions_rlp().as_raw(), 1);
		body.append_raw(block_view.uncles_rlp().as_raw(), 1);
		body.out()
	}

	/// Returns general blockchain information
	pub fn chain_info(&self) -> BlockChainInfo {
		// Make sure to call internal methods first to avoid
		// recursive locking of `best_block`.
		let first_block_hash = self.first_block();
		let first_block_number = self.first_block_number().into();
		let genesis_hash = self.genesis_hash();

		// ensure data consistencly by locking everything first
		let best_block = self.best_block.read();
		let best_ancient_block = self.best_ancient_block.read();
		BlockChainInfo {
			total_difficulty: best_block.total_difficulty,
			pending_total_difficulty: best_block.total_difficulty,
			genesis_hash,
			best_block_hash: best_block.header.hash(),
			best_block_number: best_block.header.number(),
			best_block_timestamp: best_block.header.timestamp(),
			first_block_hash,
			first_block_number,
			ancient_block_hash: best_ancient_block.as_ref().map(|b| b.hash),
			ancient_block_number: best_ancient_block.as_ref().map(|b| b.number),
		}
	}

	pub fn get_total_reward(&self) -> (BlockNumber, U256) {
		(
			self.best_block.read().header.number(),
			self.rewards.read().total(),
		)
	}

	pub fn get_rewards(&self) -> Rewards {
		self.rewards.read().clone()
	}

	pub fn update_rewards(&self, update: Rewards) {
		let mut rewards = self.rewards.write();
		*rewards = update;
	}

	pub fn calculate_block_total_reward(&self, base_reward: U256, block: &encoded::Block) -> U256 {
		let uncles = block.uncles();
		trace!(target: "blockchain", "block total reward  block number {} base: {} ", block.number(), base_reward);

		let mut blcok_reward = self
			.reward_config
			.calc_author_miner_reward(base_reward, uncles.len());
		for uncle in uncles {
			trace!(target: "blockchain", "uncle number: {} ", uncle.number());
			blcok_reward += self.reward_config.calc_uncle_miner_reward(
				base_reward,
				block.number(),
				uncle.number(),
			);
		}

		blcok_reward
	}

	fn prepare_block_rewards(
		&self,
		rewards: &mut Rewards,
		block: &encoded::Block,
		is_remove: bool,
	) -> bool {
		trace!(target: "blockchain", "update_block_rewards total reward {:?} block number {:?} remove: {}", rewards.total(), block.number(), is_remove);
		let mut total = rewards.total();

		let era = self.reward_config.calc_era_by_block_number(block.number());
		let base_reward = match rewards.get_era_base_reward(era) {
			Some(r) => r,
			None => {
				// all reward had been mined, no rewards update.
				return false;
			}
		};

		let block_reward = self.calculate_block_total_reward(base_reward, block);
		if is_remove {
			total -= block_reward;
			rewards.update_total_reward(total);

			if self.reward_config.is_era_last_block(block.number()) {
				trace!(target: "blockchain", "delete last era {} ", era + 1);
				rewards.delete_last_era(era + 1);
			}
		} else {
			total += block_reward;
			rewards.update_total_reward(total);

			// if block is last block of one era, we should do new era rewards update.
			if self.reward_config.is_era_last_block(block.number()) {
				let new_base_reward = self.reward_config.calc_era_base_reward(total);
				if self
					.reward_config
					.is_big_than_min_base_reward(new_base_reward)
				{
					let info = EraRewardInfo::new(era + 1, total, new_base_reward);
					trace!(target: "blockchain", "add new era {:?} total {:?} reward {:?}", info.era(), info.total(), info.base());
					rewards.add_new_era_reward(info);
				}
			}
		}
		true
	}

	pub fn do_rewards_of_batch_blocks(
		&self,
		rewards: &mut Rewards,
		blocks: &Vec<H256>,
		is_remove: bool,
	) -> bool {
		trace!(target: "blockchain", "do_rewards_of_batch_blocks");

		let mut update = false;

		for hash in blocks.iter() {
			let block = self
				.block(hash)
				.expect("Retracted block must be in database.");
			if self.prepare_block_rewards(rewards, &block, is_remove) {
				update = true
			}
		}
		update
	}
}

/// Update the commitment tree with the notes in the transactions.
fn update_commitment_tree_with_txs(
	commitment_tree: &mut CommitmentTree<Node>,
	private_txs: &Vec<LocalizedTransaction>,
) {
	private_txs.iter().for_each(|tx| {
		tx.get_commitment_notes().iter().for_each(|fr| {
			commitment_tree
				.append(Node::new(fr.into_repr()))
				.expect("failed to append note")
		})
	});
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::iter;
	use std::fs;

	use rand::{OsRng, Rand};
	use crate::wallet::wallet_types::{
		SaplingExtendedFullViewingKey, SaplingExtendedSpendingKey,
	};
	use crate::wallet::transaction_builder::TransactionBuilder;
	use sapling_crypto::{
		jubjub::fs::Fs,
		redjubjub::Signature,
	};
	use zcash_primitives::{
		merkle_tree::{CommitmentTree,IncrementalWitness},
		sapling::Node,
		JUBJUB,
	};
	use ff::PrimeField;

	use crate::generator::{BlockBuilder, BlockGenerator, BlockOptions};
	use common_types::receipt::{Receipt, TransactionOutcome};
	use common_types::transaction::{Action, Transaction, CONVERSION_FACTOR};
	use ethkey::Secret;
	use keccak_hash::keccak;
	use rustc_hex::FromHex;
	use tempdir::TempDir;
	use crate::wallet::wallet::WalletTxHashes;

	const TEST_CHAIN_ID: u64 = 0;

	struct TestBlockChainDB {
		_blooms_dir: TempDir,
		_trace_blooms_dir: TempDir,
		blooms: blooms_db::Database,
		trace_blooms: blooms_db::Database,
		key_value: Arc<KeyValueDB>,
	}

	impl BlockChainDB for TestBlockChainDB {
		fn key_value(&self) -> &Arc<KeyValueDB> {
			&self.key_value
		}

		fn blooms(&self) -> &blooms_db::Database {
			&self.blooms
		}

		fn trace_blooms(&self) -> &blooms_db::Database {
			&self.trace_blooms
		}
	}

	/// Creates new test instance of `BlockChainDB`
	pub fn new_db() -> Arc<BlockChainDB> {
		let blooms_dir = TempDir::new("").unwrap();
		let trace_blooms_dir = TempDir::new("").unwrap();

		let db = TestBlockChainDB {
			blooms: blooms_db::Database::open(blooms_dir.path()).unwrap(),
			trace_blooms: blooms_db::Database::open(trace_blooms_dir.path()).unwrap(),
			_blooms_dir: blooms_dir,
			_trace_blooms_dir: trace_blooms_dir,
			key_value: Arc::new(kvdb_memorydb::create(ethcore_db::NUM_COLUMNS.unwrap())),
		};

		Arc::new(db)
	}

	fn new_chain(genesis: encoded::Block, db: Arc<BlockChainDB>) -> BlockChain {
		BlockChain::new(Config::default(), genesis.raw(), db, None)
	}

	fn insert_block(
		db: &Arc<BlockChainDB>,
		bc: &BlockChain,
		block: encoded::Block,
		receipts: Vec<Receipt>,
	) -> ImportRoute {
		insert_block_commit(db, bc, block, receipts, true)
	}

	fn insert_block_commit(
		db: &Arc<BlockChainDB>,
		bc: &BlockChain,
		block: encoded::Block,
		receipts: Vec<Receipt>,
		commit: bool,
	) -> ImportRoute {
		let mut batch = db.key_value().transaction();
		let res = insert_block_batch(&mut batch, bc, block, receipts);
		db.key_value().write(batch).unwrap();
		if commit {
			bc.commit();
		}
		res
	}

	fn insert_block_batch(
		batch: &mut DBTransaction,
		bc: &BlockChain,
		block: encoded::Block,
		receipts: Vec<Receipt>,
	) -> ImportRoute {
		use crate::ExtrasInsert;

		let fork_choice = {
			let header = block.header_view();
			let parent_hash = header.parent_hash();
			let parent_details = bc
				.block_details(&parent_hash)
				.unwrap_or_else(|| panic!("Invalid parent hash: {:?}", parent_hash));
			let block_total_difficulty = parent_details.total_difficulty + header.difficulty();
			if block_total_difficulty > bc.best_block_total_difficulty() {
				common_types::engines::ForkChoice::New
			} else {
				common_types::engines::ForkChoice::Old
			}
		};

		bc.insert_block(
			batch,
			block,
			receipts,
			ExtrasInsert {
				fork_choice: fork_choice,
				is_finalized: false,
			},
		)
	}

	fn create_private_transaction(mut wallet: &mut Wallet) -> Transaction {
		let mut rng = OsRng::new().expect("should be able to construct RNG");

		let (_, extsk) = wallet.add_address_from_seed([0u8;32], "".to_string());
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;

		let mut builder = TransactionBuilder::new(0.into(), U256::from(0), U256::from(21000), vec![], TEST_CHAIN_ID);


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
		assert!(builder.add_sapling_output(ovk, to, &(U256::from(200) * CONVERSION_FACTOR), "haha").is_ok());

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
	fn should_cache_best_block() {
		// given
		let genesis = BlockBuilder::genesis();
		let first = genesis.add_block();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());
		assert_eq!(bc.best_block_number(), 0);

		// when
		insert_block_commit(&db, &bc, first.last().encoded(), vec![], false);
		assert_eq!(bc.best_block_number(), 0);
		bc.commit();
		// NOTE no db.write here (we want to check if best block is cached)

		// then
		assert_eq!(bc.best_block_number(), 1);
		assert!(
			bc.block(&bc.best_block_hash()).is_some(),
			"Best block should be queryable even without DB write."
		);
	}

	#[test]
	fn basic_blockchain_insert() {
		let genesis = BlockBuilder::genesis();
		let first = genesis.add_block();

		let genesis = genesis.last();
		let first = first.last();
		let genesis_hash = genesis.hash();
		let first_hash = first.hash();

		println!("genesis_hash:{}, first_hash:{}", genesis_hash, first_hash);

		let db = new_db();
		let bc = new_chain(genesis.encoded(), db.clone());

		assert_eq!(bc.genesis_hash(), genesis_hash);
		assert_eq!(bc.best_block_hash(), genesis_hash);
		assert_eq!(bc.block_hash(0), Some(genesis_hash));
		assert_eq!(bc.block_hash(1), None);
		assert_eq!(bc.block_details(&genesis_hash).unwrap().children, vec![]);

		println!(
			"best_block_hash:{}, best_block_number:{}",
			bc.best_block_hash(),
			bc.best_block_number()
		);

		let mut batch = db.key_value().transaction();
		insert_block_batch(&mut batch, &bc, first.encoded(), vec![]);
		db.key_value().write(batch).unwrap();
		bc.commit();

		assert_eq!(bc.block_hash(0), Some(genesis_hash));
		assert_eq!(bc.best_block_number(), 1);
		assert_eq!(bc.best_block_hash(), first_hash);
		assert_eq!(bc.block_hash(1), Some(first_hash));
		assert_eq!(bc.block_details(&first_hash).unwrap().parent, genesis_hash);
		assert_eq!(
			bc.block_details(&genesis_hash).unwrap().children,
			vec![first_hash]
		);
		assert_eq!(bc.block_hash(2), None);
	}

	#[test]
	fn check_ancestry_iter() {
		let genesis = BlockBuilder::genesis();
		let first_10 = genesis.add_blocks(10);
		let generator = BlockGenerator::new(vec![first_10]);

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut block_hashes = vec![genesis.last().hash()];
		let mut batch = db.key_value().transaction();
		for block in generator {
			block_hashes.push(block.hash());
			insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
			bc.commit();
		}
		db.key_value().write(batch).unwrap();

		block_hashes.reverse();

		for hash in bc
			.ancestry_iter(block_hashes[0].clone())
			.unwrap()
			.collect::<Vec<_>>()
		{
			println!("block iter hash:{}", hash);
		}
		assert_eq!(
			bc.ancestry_iter(block_hashes[0].clone())
				.unwrap()
				.collect::<Vec<_>>(),
			block_hashes
		);
		assert_eq!(block_hashes.len(), 11);
	}

	#[test]
	fn scan_for_wallet_transactions() {
		let genesis = BlockBuilder::genesis();
		let db = new_db();
		let config = Config::new("wallet_for_scan".to_string());
		let mut bc = BlockChain::new(config, genesis.last().encoded().raw(), db.clone(), None);
		let t1 = {
			let mut wallet = bc.pt_wallet.write().unwrap();
			create_private_transaction(&mut wallet)
		};
		assert_eq!(bc.pt_wallet.read().unwrap().key_store.get_sapling_payment_addresses().len(), 1);
		let b1a = genesis.add_block_with_transactions(vec![t1.sign_for_private(TEST_CHAIN_ID)]);
		let generator = BlockGenerator::new(vec![b1a]);
		let mut batch = db.key_value().transaction();
		for block in generator {
			insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
			bc.commit();
		}
		db.key_value().write(batch).unwrap();
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);
		{
			let mut wallet = bc.pt_wallet.write().unwrap();
			wallet.clear_wallet_data();
		}
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 0);
		let handled_addresses: HashSet<String> = HashSet::new();
		bc.scan_for_wallet_transactions(&Some(handled_addresses));
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);
	}

	#[test]
	fn test_blockchain_wallet_import_new_users() {
		let wallet_file_prefix = "wallet_for_scan";
		let genesis = BlockBuilder::genesis();
		let db = new_db();
		let config = Config::new(wallet_file_prefix.to_string());
		let mut bc = BlockChain::new(config, genesis.last().encoded().raw(), db.clone(), None);
		let t1 = {
			let mut wallet = bc.pt_wallet.write().unwrap();
			create_private_transaction(&mut wallet)
		};
		let b1a = genesis.add_block_with_transactions(vec![t1.sign_for_private(TEST_CHAIN_ID)]);
		let b2a = b1a.add_block_with_transactions(vec![]);
		let b3a = b2a.add_block_with_transactions(vec![]);
		let generator = BlockGenerator::new(vec![b1a]);
		let mut batch = db.key_value().transaction();
		for block in generator {
			insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
			bc.commit();
		}
		db.key_value().write(batch).unwrap();
		{
			let mut wallet = bc.pt_wallet.write().unwrap();
			wallet.clear_wallet_data();
		}
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 0);

		let empty_wallet_addresses = WalletTxAddresses {
			addresses: vec![],
		};

		let previous_wallet_addresses= bc.pt_wallet_addresses.read().addresses.iter().cloned().collect::<Vec<String>>();
		assert_eq!(previous_wallet_addresses.len(), 1);
		// Clear the pt_wallet_addresses.
		{
			let mut wallet_addresses = bc.pt_wallet_addresses.write();
			*wallet_addresses = empty_wallet_addresses;
		}
		// The insert_block trigger scan_for_wallet_imported_users.
		let mut batch = db.key_value().transaction();
		insert_block_batch(&mut batch, &bc, b2a.last().encoded(), vec![]);
		bc.commit();
		assert_eq!(bc.pt_wallet_addresses.read().addresses.iter().cloned().collect::<Vec<String>>(), previous_wallet_addresses);
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);

		// Import new private address.
		{
			let mut pt_wallet = bc.pt_wallet.write().unwrap();
			pt_wallet.create_new_private_address(None);
		}
		let mut batch = db.key_value().transaction();
		insert_block_batch(&mut batch, &bc, b3a.last().encoded(), vec![]);
		bc.commit();
		let updated_wallet_addresses = bc.pt_wallet_addresses.read().addresses.iter().cloned().collect::<Vec<String>>();
		assert_eq!(updated_wallet_addresses.len(), 2);

		remove_old_key_files(wallet_file_prefix, "./");
	}

	#[test]
	fn test_db_transaction_batch_insert_and_get() {
		let db = new_db();
		let mut batch = db.key_value().transaction();
		let value = "test".as_bytes();
		batch.put(db::COL_EXTRA, b"best", &value);
		// The batch has not been commit, therefore the get function can not read the record.
		let result = match db.key_value().get(db::COL_EXTRA, b"best").expect("should read the value") {
			Some(best) => String::from_utf8(best.into_vec()).unwrap(),
			None => String::from(""),
		};
		assert_eq!(result, String::from(""));
		db.key_value().write(batch).unwrap();
		let result = match db.key_value().get(db::COL_EXTRA, b"best").expect("should read the value") {
			Some(best) => String::from_utf8(best.into_vec()).unwrap(),
			None => String::from(""),
		};
		assert_eq!(result, String::from("test"));
	}

	#[test]
	fn test_blockchain_wallet_write_and_reload() {
		let genesis = BlockBuilder::genesis();
		let db = new_db();
		let config = Config::new("wallet_for_scan".to_string());
		let mut bc = BlockChain::new(config, genesis.last().encoded().raw(), db.clone(), None);
		let t1 = {
			let mut wallet = bc.pt_wallet.write().unwrap();
			create_private_transaction(&mut wallet)
		}.sign_for_private(TEST_CHAIN_ID);
		let t2 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}.sign(&secret(), None);
		let tx_hash = t1.hash();
		assert_eq!(bc.pt_wallet.read().unwrap().key_store.get_sapling_payment_addresses().len(), 1);
		let b1a = genesis.add_block_with_transactions(vec![t1, t2]);
		let generator = BlockGenerator::new(vec![b1a]);
		let mut batch = db.key_value().transaction();
		for block in generator {
			insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
			bc.commit();
		}
		db.key_value().write(batch).unwrap();
		// Clear the wallet data.
		{
			let mut wallet = bc.pt_wallet.write().unwrap();
			wallet.clear_wallet_data();
		}
		bc.reload_wallet_info();
		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert!(bc.pt_wallet.read().unwrap().tx_nullifiers.contains_key(&tx_hash));
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);
	}

	#[test]
	fn test_find_uncles() {
		let genesis = BlockBuilder::genesis();
		let b1a = genesis.add_block();
		let b2a = b1a.add_block();
		let b3a = b2a.add_block();
		let b4a = b3a.add_block();
		let b5a = b4a.add_block();

		let b1b = genesis.add_block_with_difficulty(9);
		let b2b = b1a.add_block_with_difficulty(9);
		let b3b = b2a.add_block_with_difficulty(9);
		let b4b = b3a.add_block_with_difficulty(9);
		let b5b = b4a.add_block_with_difficulty(9);

		let uncle_headers = vec![
			b4b.last().header().encoded(),
			b3b.last().header().encoded(),
			b2b.last().header().encoded(),
		];
		let b4a_hash = b4a.last().hash();

		let generator = BlockGenerator::new(vec![b1a, b1b, b2a, b2b, b3a, b3b, b4a, b4b, b5a, b5b]);

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		for b in generator {
			insert_block(&db, &bc, b.encoded(), vec![]);
		}

		assert_eq!(uncle_headers, bc.find_uncle_headers(&b4a_hash, 3).unwrap());
		// TODO: insert block that already includes one of them as an uncle to check it's not allowed.
	}

	fn secret() -> Secret {
		keccak("").into()
	}

	#[test]
	fn test_fork_transaction_addresses() {
		let t1 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let t1_hash = t1.hash();

		let genesis = BlockBuilder::genesis();
		let b1a = genesis.add_block_with_transactions(iter::once(t1));
		let b1b = genesis.add_block_with_difficulty(9);
		let b2 = b1b.add_block();

		let b1a_hash = b1a.last().hash();
		let b1b_hash = b1b.last().hash();
		let b2_hash = b2.last().hash();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b1a.last().encoded(), vec![]);
		bc.commit();
		let _ = insert_block_batch(&mut batch, &bc, b1b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b1a_hash);
		assert_eq!(
			bc.transaction_address(&t1_hash),
			Some(TransactionAddress {
				block_hash: b1a_hash,
				index: 0,
			})
		);
		assert!(bc.block_details(&b1b_hash).is_some());

		// now let's make forked chain the canon chain
		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		// Transaction should be retracted
		assert_eq!(bc.best_block_hash(), b2_hash);
		assert_eq!(bc.transaction_address(&t1_hash), None);
		assert!(bc.block_details(&b1a_hash).is_some());
	}

	#[test]
	fn test_fork_transaction_nullifier() {
		let t1 =
			Transaction::create_private(vec![0, 1], 42.into(), Action::PrivateToPrivate).sign_for_private(TEST_CHAIN_ID);
		let t2 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let t1_hash = t1.hash();
		let nullifiers = t1.get_nullifier_set();

		let genesis = BlockBuilder::genesis();
		let b1a = genesis.add_block_with_transactions(vec![t1.clone(), t2.clone()]);
		let b1b = genesis.add_block_with_difficulty(9);
		let b2 = b1b.add_block();

		let b1a_hash = b1a.last().hash();
		let b2_hash = b2.last().hash();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b1a.last().encoded(), vec![]);
		bc.commit();
		let _ = insert_block_batch(&mut batch, &bc, b1b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b1a_hash);
		for nullifier in nullifiers.clone() {
			assert_eq!(bc.nullifier_transaction(&nullifier), Some(t1_hash));
		}

		// now let's make forked chain the canon chain
		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		// Transaction should be retracted
		assert_eq!(bc.best_block_hash(), b2_hash);
		for nullifier in nullifiers {
			assert_eq!(bc.nullifier_transaction(&nullifier), None);
		}
	}

	#[test]
	fn test_commitment_serialization_block() {
		let t1 =
			Transaction::create_private(vec![0, 1], 42.into(), Action::PrivateToPrivate).sign_for_private(TEST_CHAIN_ID);

		let genesis = BlockBuilder::genesis();
		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let mut block_list = Vec::new();
		let mut iter = &genesis;
		for i in 0..10 {
			let block = iter.add_block_with_transactions(vec![t1.clone()]);
			block_list.push(block);
			iter = &block_list[block_list.len() - 1];
		}
		for ref block in block_list {
			let _ = insert_block_batch(&mut batch, &bc, block.last().encoded(), vec![]);
			bc.commit();
		}
		db.key_value().write(batch).unwrap();
	}

	#[test]
	fn test_fork_commitment_root_block() {
		let t1 =
			Transaction::create_private(vec![0, 1], 42.into(), Action::PrivateToPrivate).sign_for_private(TEST_CHAIN_ID);
		let t2 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let genesis = BlockBuilder::genesis();
		let b1a = genesis.add_block_with_transactions(vec![t1.clone(), t2.clone()]);
		let b1b = genesis.add_block_with_difficulty(9);
		let b2 = b1b.add_block();

		let b1a_hash = b1a.last().hash();
		let b2_hash = b2.last().hash();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b1a.last().encoded(), vec![]);
		bc.commit();
		let _ = insert_block_batch(&mut batch, &bc, b1b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b1a_hash);

		assert!(bc.block_commitment_ser(&b1a_hash).is_some());
		let commitment_tree_ser = bc.block_commitment_ser(&b1a_hash).unwrap();
		let mut current_commitment_tree = commitment_tree_ser.get_commitment_tree();
		let b1a_commitment_root = current_commitment_tree.root();
		assert_eq!(
			bc.commitment_root_block(&b1a_commitment_root),
			Some(b1a_hash)
		);

		// now let's make forked chain the canon chain
		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		// Transaction should be retracted
		assert_eq!(bc.best_block_hash(), b2_hash);
		assert!(bc.commitment_root_block(&b1a_commitment_root).is_none());
		assert!(bc.block_commitment_ser(&b1a_hash).is_some());
	}

	/// TODO(Kui): We should also test the tree root and serialization value are computed correctly.
	/// We could create some transactions using the commitments in merkle_tree tests,
	/// and then check the root and serialization we get matches those in the tests as well.

	#[test]
	fn test_fork_blockchain_wallet() {
		let genesis = BlockBuilder::genesis();
		let db = new_db();
		let config = Config::new("wallet_for_scan".to_string());
		let mut bc = BlockChain::new(config, genesis.last().encoded().raw(), db.clone(), None);
		let t1 = {
			let mut wallet = bc.pt_wallet.write().unwrap();
			create_private_transaction(&mut wallet)
		};
		let t2 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}.sign(&secret(), None);
		assert_eq!(bc.pt_wallet.read().unwrap().key_store.get_sapling_payment_addresses().len(), 1);

		let b1a = genesis.add_block_with_transactions(vec![t1.sign_for_private(TEST_CHAIN_ID), t2]);
		let b2a = b1a.add_block();
		let b1b = genesis.add_block_with_difficulty(9);
		let b2 = b1b.add_block();

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b1a.last().encoded(), vec![]);
		bc.commit();
		let _ = insert_block_batch(&mut batch, &bc, b1b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 0);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 0);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 0);

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2a.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.pt_wallet.read().unwrap().tx_nullifiers.len(), 1);
		assert_eq!(bc.pt_wallet.read().unwrap().nullifier_notes.len(), 2);
		assert_eq!(bc.pt_wallet.read().unwrap().address_nullifiers.len(), 1);
	}

	#[test]
	fn test_overwriting_transaction_addresses() {
		let t1 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let t2 = Transaction {
			nonce: 1.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let t3 = Transaction {
			nonce: 2.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 100.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);

		let genesis = BlockBuilder::genesis();
		let b1a = genesis.add_block_with_transactions(vec![t1.clone(), t2.clone()]);
		// insert transactions in different order,
		// the block has lower difficulty, so the hash is also different
		let b1b = genesis.add_block_with(|| BlockOptions {
			difficulty: 9.into(),
			transactions: vec![t2.clone(), t1.clone()],
			..Default::default()
		});
		let b2 = b1b.add_block_with_transactions(iter::once(t3.clone()));

		let b1a_hash = b1a.last().hash();
		let b1b_hash = b1b.last().hash();
		let b2_hash = b2.last().hash();

		let t1_hash = t1.hash();
		let t2_hash = t2.hash();
		let t3_hash = t3.hash();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b1a.last().encoded(), vec![]);
		bc.commit();
		let _ = insert_block_batch(&mut batch, &bc, b1b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b1a_hash);
		assert_eq!(
			bc.transaction_address(&t1_hash),
			Some(TransactionAddress {
				block_hash: b1a_hash,
				index: 0,
			})
		);
		assert_eq!(
			bc.transaction_address(&t2_hash),
			Some(TransactionAddress {
				block_hash: b1a_hash,
				index: 1,
			})
		);

		// now let's make forked chain the canon chain
		let mut batch = db.key_value().transaction();
		let _ = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b2_hash);
		assert_eq!(
			bc.transaction_address(&t1_hash),
			Some(TransactionAddress {
				block_hash: b1b_hash,
				index: 1,
			})
		);
		assert_eq!(
			bc.transaction_address(&t2_hash),
			Some(TransactionAddress {
				block_hash: b1b_hash,
				index: 0,
			})
		);
		assert_eq!(
			bc.transaction_address(&t3_hash),
			Some(TransactionAddress {
				block_hash: b2_hash,
				index: 0,
			})
		);
	}

	#[test]
	fn test_small_fork() {
		let genesis = BlockBuilder::genesis();
		let b1 = genesis.add_block();
		let b2 = b1.add_block();
		let b3a = b2.add_block();
		let b3b = b2.add_block_with_difficulty(9);

		let genesis_hash = genesis.last().hash();
		let b1_hash = b1.last().hash();
		let b2_hash = b2.last().hash();
		let b3a_hash = b3a.last().hash();
		let b3b_hash = b3b.last().hash();

		// b3a is a part of canon chain, whereas b3b is part of sidechain
		let best_block_hash = b3a_hash;

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		let ir1 = insert_block_batch(&mut batch, &bc, b1.last().encoded(), vec![]);
		bc.commit();
		let ir2 = insert_block_batch(&mut batch, &bc, b2.last().encoded(), vec![]);
		bc.commit();
		let ir3b = insert_block_batch(&mut batch, &bc, b3b.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();
		assert_eq!(bc.block_hash(3).unwrap(), b3b_hash);
		let mut batch = db.key_value().transaction();
		let ir3a = insert_block_batch(&mut batch, &bc, b3a.last().encoded(), vec![]);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(
			ir1,
			ImportRoute {
				enacted: vec![b1_hash],
				retracted: vec![],
				omitted: vec![],
			}
		);

		assert_eq!(
			ir2,
			ImportRoute {
				enacted: vec![b2_hash],
				retracted: vec![],
				omitted: vec![],
			}
		);

		assert_eq!(
			ir3b,
			ImportRoute {
				enacted: vec![b3b_hash],
				retracted: vec![],
				omitted: vec![],
			}
		);

		assert_eq!(
			ir3a,
			ImportRoute {
				enacted: vec![b3a_hash],
				retracted: vec![b3b_hash],
				omitted: vec![],
			}
		);

		assert_eq!(bc.best_block_hash(), best_block_hash);
		assert_eq!(bc.block_number(&genesis_hash).unwrap(), 0);
		assert_eq!(bc.block_number(&b1_hash).unwrap(), 1);
		assert_eq!(bc.block_number(&b2_hash).unwrap(), 2);
		assert_eq!(bc.block_number(&b3a_hash).unwrap(), 3);
		assert_eq!(bc.block_number(&b3b_hash).unwrap(), 3);

		assert_eq!(bc.block_hash(0).unwrap(), genesis_hash);
		assert_eq!(bc.block_hash(1).unwrap(), b1_hash);
		assert_eq!(bc.block_hash(2).unwrap(), b2_hash);
		assert_eq!(bc.block_hash(3).unwrap(), b3a_hash);

		// test trie route
		let r0_1 = bc.tree_route(genesis_hash, b1_hash).unwrap();
		assert_eq!(r0_1.ancestor, genesis_hash);
		assert_eq!(r0_1.blocks, [b1_hash]);
		assert_eq!(r0_1.index, 0);

		let r0_2 = bc.tree_route(genesis_hash, b2_hash).unwrap();
		assert_eq!(r0_2.ancestor, genesis_hash);
		assert_eq!(r0_2.blocks, [b1_hash, b2_hash]);
		assert_eq!(r0_2.index, 0);

		let r1_3a = bc.tree_route(b1_hash, b3a_hash).unwrap();
		assert_eq!(r1_3a.ancestor, b1_hash);
		assert_eq!(r1_3a.blocks, [b2_hash, b3a_hash]);
		assert_eq!(r1_3a.index, 0);

		let r1_3b = bc.tree_route(b1_hash, b3b_hash).unwrap();
		assert_eq!(r1_3b.ancestor, b1_hash);
		assert_eq!(r1_3b.blocks, [b2_hash, b3b_hash]);
		assert_eq!(r1_3b.index, 0);

		let r3a_3b = bc.tree_route(b3a_hash, b3b_hash).unwrap();
		assert_eq!(r3a_3b.ancestor, b2_hash);
		assert_eq!(r3a_3b.blocks, [b3a_hash, b3b_hash]);
		assert_eq!(r3a_3b.index, 1);

		let r1_0 = bc.tree_route(b1_hash, genesis_hash).unwrap();
		assert_eq!(r1_0.ancestor, genesis_hash);
		assert_eq!(r1_0.blocks, [b1_hash]);
		assert_eq!(r1_0.index, 1);

		let r2_0 = bc.tree_route(b2_hash, genesis_hash).unwrap();
		assert_eq!(r2_0.ancestor, genesis_hash);
		assert_eq!(r2_0.blocks, [b2_hash, b1_hash]);
		assert_eq!(r2_0.index, 2);

		let r3a_1 = bc.tree_route(b3a_hash, b1_hash).unwrap();
		assert_eq!(r3a_1.ancestor, b1_hash);
		assert_eq!(r3a_1.blocks, [b3a_hash, b2_hash]);
		assert_eq!(r3a_1.index, 2);

		let r3b_1 = bc.tree_route(b3b_hash, b1_hash).unwrap();
		assert_eq!(r3b_1.ancestor, b1_hash);
		assert_eq!(r3b_1.blocks, [b3b_hash, b2_hash]);
		assert_eq!(r3b_1.index, 2);

		let r3b_3a = bc.tree_route(b3b_hash, b3a_hash).unwrap();
		assert_eq!(r3b_3a.ancestor, b2_hash);
		assert_eq!(r3b_3a.blocks, [b3b_hash, b3a_hash]);
		assert_eq!(r3b_3a.index, 1);
	}

	#[test]
	fn test_reopen_blockchain_db() {
		let genesis = BlockBuilder::genesis();
		let first = genesis.add_block();
		let genesis_hash = genesis.last().hash();
		let first_hash = first.last().hash();

		let db = new_db();

		{
			let bc = new_chain(genesis.last().encoded(), db.clone());
			assert_eq!(bc.best_block_hash(), genesis_hash);
			let mut batch = db.key_value().transaction();
			insert_block_batch(&mut batch, &bc, first.last().encoded(), vec![]);
			db.key_value().write(batch).unwrap();
			bc.commit();
			assert_eq!(bc.best_block_hash(), first_hash);
		}

		{
			let bc = new_chain(genesis.last().encoded(), db.clone());

			assert_eq!(bc.best_block_hash(), first_hash);
		}
	}

	#[test]
	fn find_transaction_by_hash() {
		let genesis = "f901fcf901f7a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0af81e09f8c46ca322193edfda764fa7e88e81923f802f1d325ec0b0308ac2cd0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000830200008083023e38808454c98c8142a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421880102030405060708c0c0".from_hex().unwrap();
		let b1 = "f904a8f901faa0ce1f26f798dd03c8782d63b3e42e79a64eaea5694ea686ac5d7ce3df5171d1aea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948888f1f195afa192cfee860698584c030f4c9db1a0a65c2364cd0f1542d761823dc0109c6b072f14c20459598c5455c274601438f4a070616ebd7ad2ed6fb7860cf7e9df00163842351c38a87cac2c1cb193895035a2a05c5b4fc43c2d45787f54e1ae7d27afdb4ad16dfc567c5692070d5c4556e0b1d7b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000830200000183023ec683021536845685109780a029f07836e4e59229b3a065913afc27702642c683bba689910b2b2fd45db310d3888957e6d004a31802f902a7f85f800a8255f094aaaf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ca0575da4e21b66fa764be5f74da9389e67693d066fb0d1312e19e17e501da00ecda06baf5a5327595f6619dfc2fcb3f2e6fb410b5810af3cb52d0e7508038e91a188f85f010a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ba04fa966bf34b93abc1bcd665554b7f316b50f928477b50be0f3285ead29d18c5ba017bba0eeec1625ab433746955e125d46d80b7fdc97386c51266f842d8e02192ef85f020a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ca004377418ae981cc32b1312b4a427a1d69a821b28db8584f5f2bd8c6d42458adaa053a1dba1af177fac92f3b6af0a9fa46a22adf56e686c93794b6a012bf254abf5f85f030a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ca04fe13febd28a05f4fcb2f451d7ddc2dda56486d9f8c79a62b0ba4da775122615a0651b2382dd402df9ebc27f8cb4b2e0f3cea68dda2dca0ee9603608f0b6f51668f85f040a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ba078e6a0ba086a08f8450e208a399bb2f2d2a0d984acd2517c7c7df66ccfab567da013254002cd45a97fac049ae00afbc43ed0d9961d0c56a3b2382c80ce41c198ddf85f050a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ba0a7174d8f43ea71c8e3ca9477691add8d80ac8e0ed89d8d8b572041eef81f4a54a0534ea2e28ec4da3b5b944b18c51ec84a5cf35f5b3343c5fb86521fd2d388f506f85f060a82520894bbbf5374fce5edbc8e2a8697c15331677e6ebf0b0a801ba034bd04065833536a10c77ee2a43a5371bc6d34837088b861dd9d4b7f44074b59a078807715786a13876d3455716a6b9cb2186b7a4887a5c31160fc877454958616c0".from_hex().unwrap();
		let b1_hash: H256 =
			"f53f268d23a71e85c7d6d83a9504298712b84c1a2ba220441c86eeda0bf0b6e3".into();

		let db = new_db();
		let bc = new_chain(encoded::Block::new(genesis), db.clone());
		let mut batch = db.key_value().transaction();
		insert_block_batch(&mut batch, &bc, encoded::Block::new(b1), vec![]);
		db.key_value().write(batch).unwrap();
		bc.commit();

		let transactions = bc.transactions(&b1_hash).unwrap();
		assert_eq!(transactions.len(), 7);
		for t in transactions {
			assert_eq!(
				bc.transaction(&bc.transaction_address(&t.hash()).unwrap())
					.unwrap(),
				t
			);
		}
	}

	#[test]
	fn test_logs() {
		let t1 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 101.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);
		let t2 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 102.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);
		let t3 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 103.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);
		let t4 = Transaction {
			nonce: 0.into(),
			gas_price: 0.into(),
			gas: 100_000.into(),
			action: Action::Create,
			value: 104.into(),
			data: "601080600c6000396000f3006000355415600957005b60203560003555"
				.from_hex()
				.unwrap(),
			private: None,
		}
		.sign(&secret(), None);
		let tx_hash1 = t1.hash();
		let tx_hash2 = t2.hash();
		let tx_hash3 = t3.hash();
		let tx_hash4 = t4.hash();

		let genesis = BlockBuilder::genesis();
		let b1 = genesis.add_block_with_transactions(vec![t1, t2]);
		let b2 = b1.add_block_with_transactions(iter::once(t3));
		let b3 = genesis.add_block_with(|| BlockOptions {
			transactions: vec![t4.clone()],
			difficulty: U256::from(9),
			..Default::default()
		}); // Branch block
		let b1_hash = b1.last().hash();
		let b1_number = b1.last().number();
		let b2_hash = b2.last().hash();
		let b2_number = b2.last().number();
		let b3_hash = b3.last().hash();
		let b3_number = b3.last().number();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());
		insert_block(
			&db,
			&bc,
			b1.last().encoded(),
			vec![
				Receipt {
					outcome: TransactionOutcome::StateRoot(H256::default()),
					gas_used: 10_000.into(),
					log_bloom: Default::default(),
					logs: vec![
						LogEntry {
							address: Default::default(),
							topics: vec![],
							data: vec![1],
						},
						LogEntry {
							address: Default::default(),
							topics: vec![],
							data: vec![2],
						},
					],
				},
				Receipt {
					outcome: TransactionOutcome::StateRoot(H256::default()),
					gas_used: 10_000.into(),
					log_bloom: Default::default(),
					logs: vec![LogEntry {
						address: Default::default(),
						topics: vec![],
						data: vec![3],
					}],
				},
			],
		);
		insert_block(
			&db,
			&bc,
			b2.last().encoded(),
			vec![Receipt {
				outcome: TransactionOutcome::StateRoot(H256::default()),
				gas_used: 10_000.into(),
				log_bloom: Default::default(),
				logs: vec![LogEntry {
					address: Default::default(),
					topics: vec![],
					data: vec![4],
				}],
			}],
		);
		insert_block(
			&db,
			&bc,
			b3.last().encoded(),
			vec![Receipt {
				outcome: TransactionOutcome::StateRoot(H256::default()),
				gas_used: 10_000.into(),
				log_bloom: Default::default(),
				logs: vec![LogEntry {
					address: Default::default(),
					topics: vec![],
					data: vec![5],
				}],
			}],
		);

		// when
		let logs1 = bc.logs(vec![b1_hash, b2_hash], |_| true, None);
		let logs2 = bc.logs(vec![b1_hash, b2_hash], |_| true, Some(1));
		let logs3 = bc.logs(vec![b3_hash], |_| true, None);

		// then
		assert_eq!(
			logs1,
			vec![
				LocalizedLogEntry {
					entry: LogEntry {
						address: Default::default(),
						topics: vec![],
						data: vec![1]
					},
					block_hash: b1_hash,
					block_number: b1_number,
					transaction_hash: tx_hash1,
					transaction_index: 0,
					transaction_log_index: 0,
					log_index: 0,
				},
				LocalizedLogEntry {
					entry: LogEntry {
						address: Default::default(),
						topics: vec![],
						data: vec![2]
					},
					block_hash: b1_hash,
					block_number: b1_number,
					transaction_hash: tx_hash1,
					transaction_index: 0,
					transaction_log_index: 1,
					log_index: 1,
				},
				LocalizedLogEntry {
					entry: LogEntry {
						address: Default::default(),
						topics: vec![],
						data: vec![3]
					},
					block_hash: b1_hash,
					block_number: b1_number,
					transaction_hash: tx_hash2,
					transaction_index: 1,
					transaction_log_index: 0,
					log_index: 2,
				},
				LocalizedLogEntry {
					entry: LogEntry {
						address: Default::default(),
						topics: vec![],
						data: vec![4]
					},
					block_hash: b2_hash,
					block_number: b2_number,
					transaction_hash: tx_hash3,
					transaction_index: 0,
					transaction_log_index: 0,
					log_index: 0,
				}
			]
		);
		assert_eq!(
			logs2,
			vec![LocalizedLogEntry {
				entry: LogEntry {
					address: Default::default(),
					topics: vec![],
					data: vec![4]
				},
				block_hash: b2_hash,
				block_number: b2_number,
				transaction_hash: tx_hash3,
				transaction_index: 0,
				transaction_log_index: 0,
				log_index: 0,
			}]
		);
		assert_eq!(
			logs3,
			vec![LocalizedLogEntry {
				entry: LogEntry {
					address: Default::default(),
					topics: vec![],
					data: vec![5]
				},
				block_hash: b3_hash,
				block_number: b3_number,
				transaction_hash: tx_hash4,
				transaction_index: 0,
				transaction_log_index: 0,
				log_index: 0,
			}]
		);
	}

	#[test]
	fn test_bloom_filter_simple() {
		let bloom_b1: Bloom = "00000020000000000000000000000000000000000000000002000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000400000000000000000000002000".into();

		let bloom_b2: Bloom = "00000000000000000000000000000000000000000000020000001000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000008000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();

		let bloom_ba: Bloom = "00000000000000000000000000000000000000000000020000000800000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000008000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();

		let genesis = BlockBuilder::genesis();
		let b1 = genesis.add_block_with(|| BlockOptions {
			bloom: bloom_b1.clone(),
			difficulty: 9.into(),
			..Default::default()
		});
		let b2 = b1.add_block_with_bloom(bloom_b2);
		let b3 = b2.add_block_with_bloom(bloom_ba);

		let b1a = genesis.add_block_with_bloom(bloom_ba);
		let b2a = b1a.add_block_with_bloom(bloom_ba);

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());

		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		assert!(blocks_b1.is_empty());
		assert!(blocks_b2.is_empty());

		insert_block(&db, &bc, b1.last().encoded(), vec![]);
		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		assert_eq!(blocks_b1, vec![1]);
		assert!(blocks_b2.is_empty());

		insert_block(&db, &bc, b2.last().encoded(), vec![]);
		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		assert_eq!(blocks_b1, vec![1]);
		assert_eq!(blocks_b2, vec![2]);

		// hasn't been forked yet
		insert_block(&db, &bc, b1a.last().encoded(), vec![]);
		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		let blocks_ba = bc.blocks_with_bloom(Some(&bloom_ba), 0, 5);
		assert_eq!(blocks_b1, vec![1]);
		assert_eq!(blocks_b2, vec![2]);
		assert!(blocks_ba.is_empty());

		// fork has happend
		insert_block(&db, &bc, b2a.last().encoded(), vec![]);
		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		let blocks_ba = bc.blocks_with_bloom(Some(&bloom_ba), 0, 5);
		assert!(blocks_b1.is_empty());
		assert!(blocks_b2.is_empty());
		assert_eq!(blocks_ba, vec![1, 2]);

		// fork back
		insert_block(&db, &bc, b3.last().encoded(), vec![]);
		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 5);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 5);
		let blocks_ba = bc.blocks_with_bloom(Some(&bloom_ba), 0, 5);
		assert_eq!(blocks_b1, vec![1]);
		assert_eq!(blocks_b2, vec![2]);
		assert_eq!(blocks_ba, vec![3]);
	}

	#[test]
	fn test_insert_unordered() {
		let bloom_b1: Bloom = "00000020000000000000000000000000000000000000000002000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000400000000000000000000002000".into();

		let bloom_b2: Bloom = "00000000000000000000000000000000000000000000020000001000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000008000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();

		let bloom_b3: Bloom = "00000000000000000000000000000000000000000000020000000800000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000008000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();

		let genesis = BlockBuilder::genesis();
		let b1 = genesis.add_block_with_bloom(bloom_b1);
		let b2 = b1.add_block_with_bloom(bloom_b2);
		let b3 = b2.add_block_with_bloom(bloom_b3);
		let b1_total_difficulty = genesis.last().difficulty() + b1.last().difficulty();

		let db = new_db();
		let bc = new_chain(genesis.last().encoded(), db.clone());
		let mut batch = db.key_value().transaction();
		bc.insert_unordered_block(
			&mut batch,
			b2.last().encoded(),
			vec![],
			Some(b1_total_difficulty),
			false,
			false,
		);
		bc.commit();
		bc.insert_unordered_block(&mut batch, b3.last().encoded(), vec![], None, true, false);
		bc.commit();
		bc.insert_unordered_block(&mut batch, b1.last().encoded(), vec![], None, false, false);
		bc.commit();
		db.key_value().write(batch).unwrap();

		assert_eq!(bc.best_block_hash(), b3.last().hash());
		assert_eq!(bc.block_hash(1).unwrap(), b1.last().hash());
		assert_eq!(bc.block_hash(2).unwrap(), b2.last().hash());
		assert_eq!(bc.block_hash(3).unwrap(), b3.last().hash());

		let blocks_b1 = bc.blocks_with_bloom(Some(&bloom_b1), 0, 3);
		let blocks_b2 = bc.blocks_with_bloom(Some(&bloom_b2), 0, 3);
		let blocks_b3 = bc.blocks_with_bloom(Some(&bloom_b3), 0, 3);

		assert_eq!(blocks_b1, vec![1]);
		assert_eq!(blocks_b2, vec![2]);
		assert_eq!(blocks_b3, vec![3]);
	}

	#[test]
	fn test_best_block_update() {
		let genesis = BlockBuilder::genesis();
		let next_5 = genesis.add_blocks(5);
		let uncle = genesis.add_block_with_difficulty(9);
		let generator = BlockGenerator::new(iter::once(next_5));

		let db = new_db();
		{
			let bc = new_chain(genesis.last().encoded(), db.clone());

			let mut batch = db.key_value().transaction();
			// create a longer fork
			for block in generator {
				insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
				bc.commit();
			}

			assert_eq!(bc.best_block_number(), 5);
			insert_block_batch(&mut batch, &bc, uncle.last().encoded(), vec![]);
			db.key_value().write(batch).unwrap();
			bc.commit();
		}

		// re-loading the blockchain should load the correct best block.
		let bc = new_chain(genesis.last().encoded(), db);
		assert_eq!(bc.best_block_number(), 5);
	}

	#[test]
	fn epoch_transitions_iter() {
		use common_types::engines::epoch::Transition as EpochTransition;

		let genesis = BlockBuilder::genesis();
		let next_5 = genesis.add_blocks(5);
		let uncle = genesis.add_block_with_difficulty(9);
		let generator = BlockGenerator::new(iter::once(next_5));

		let db = new_db();
		{
			let bc = new_chain(genesis.last().encoded(), db.clone());

			let mut batch = db.key_value().transaction();
			// create a longer fork
			for (i, block) in generator.into_iter().enumerate() {
				insert_block_batch(&mut batch, &bc, block.encoded(), vec![]);
				bc.insert_epoch_transition(
					&mut batch,
					i as u64,
					EpochTransition {
						block_hash: block.hash(),
						block_number: i as u64 + 1,
						proof: vec![],
					},
				);
				bc.commit();
			}

			assert_eq!(bc.best_block_number(), 5);

			insert_block_batch(&mut batch, &bc, uncle.last().encoded(), vec![]);
			bc.insert_epoch_transition(
				&mut batch,
				999,
				EpochTransition {
					block_hash: uncle.last().hash(),
					block_number: 1,
					proof: vec![],
				},
			);

			db.key_value().write(batch).unwrap();
			bc.commit();

			// epoch 999 not in canonical chain.
			assert_eq!(
				bc.epoch_transitions().map(|(i, _)| i).collect::<Vec<_>>(),
				vec![0, 1, 2, 3, 4]
			);
		}

		// re-loading the blockchain should load the correct best block.
		let bc = new_chain(genesis.last().encoded(), db);

		assert_eq!(bc.best_block_number(), 5);
		assert_eq!(
			bc.epoch_transitions().map(|(i, _)| i).collect::<Vec<_>>(),
			vec![0, 1, 2, 3, 4]
		);
	}

	#[test]
	fn epoch_transition_for() {
		use common_types::engines::epoch::Transition as EpochTransition;

		let genesis = BlockBuilder::genesis();
		let fork_7 = genesis.add_blocks_with(7, || BlockOptions {
			difficulty: 9.into(),
			..Default::default()
		});
		let next_10 = genesis.add_blocks(10);
		let fork_generator = BlockGenerator::new(iter::once(fork_7));
		let next_generator = BlockGenerator::new(iter::once(next_10));

		let db = new_db();

		let bc = new_chain(genesis.last().encoded(), db.clone());

		let mut batch = db.key_value().transaction();
		bc.insert_epoch_transition(
			&mut batch,
			0,
			EpochTransition {
				block_hash: bc.genesis_hash(),
				block_number: 0,
				proof: vec![],
			},
		);
		db.key_value().write(batch).unwrap();

		// set up a chain where we have a canonical chain of 10 blocks
		// and a non-canonical fork of 8 from genesis.
		let fork_hash = {
			for block in fork_generator {
				insert_block(&db, &bc, block.encoded(), vec![]);
			}

			assert_eq!(bc.best_block_number(), 7);
			bc.chain_info().best_block_hash
		};

		for block in next_generator {
			insert_block(&db, &bc, block.encoded(), vec![]);
		}

		assert_eq!(bc.best_block_number(), 10);

		let mut batch = db.key_value().transaction();
		bc.insert_epoch_transition(
			&mut batch,
			4,
			EpochTransition {
				block_hash: bc.block_hash(4).unwrap(),
				block_number: 4,
				proof: vec![],
			},
		);
		db.key_value().write(batch).unwrap();

		// blocks where the parent is one of the first 4 will be part of genesis epoch.
		for i in 0..4 {
			let hash = bc.block_hash(i).unwrap();
			assert_eq!(bc.epoch_transition_for(hash).unwrap().block_number, 0);
		}

		// blocks where the parent is the transition at 4 or after will be
		// part of that epoch.
		for i in 4..11 {
			let hash = bc.block_hash(i).unwrap();
			assert_eq!(bc.epoch_transition_for(hash).unwrap().block_number, 4);
		}

		let fork_hashes = bc.ancestry_iter(fork_hash).unwrap().collect::<Vec<_>>();
		assert_eq!(fork_hashes.len(), 8);

		// non-canonical fork blocks should all have genesis transition
		for fork_hash in fork_hashes {
			assert_eq!(bc.epoch_transition_for(fork_hash).unwrap().block_number, 0);
		}
	}
}
