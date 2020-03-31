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

use std::collections::HashMap;

use common_types::encoded::Block;
use common_types::engines::ForkChoice;
use common_types::BlockNumber;
use ethcore_db::keys::{
	BlockDetails, BlockReceipts, CommitmentTreeSerialization, TransactionAddress,
};
use ethereum_types::{Bloom, H256, U256};

use crate::block_info::BlockInfo;
use crate::zcash_primitives::sapling::Node;
use common_types::rewards::Rewards;

/// Block extras update info.
pub struct ExtrasUpdate {
	/// Block info.
	pub info: BlockInfo,
	/// Current block uncompressed rlp bytes
	pub block: Block,
	/// Modified block hashes.
	pub block_hashes: HashMap<BlockNumber, H256>,
	/// Modified block details.
	pub block_details: HashMap<H256, BlockDetails>,
	/// Modified block receipts.
	pub block_receipts: HashMap<H256, BlockReceipts>,
	/// Modified blocks blooms.
	pub blocks_blooms: Option<(u64, Vec<Bloom>)>,
	/// Modified transaction addresses (None signifies removed transactions).
	pub transactions_addresses: HashMap<H256, Option<TransactionAddress>>,
	/// Modified transaction nullifiers
	pub transactions_nullifiers: HashMap<U256, Option<H256>>,
	/// Modified blocks commitment tree root.
	pub commitment_root_blocks: HashMap<Node, Option<H256>>,
	/// Modified blocks commitment tree serialization.
	pub blocks_commitment_sers: HashMap<H256, CommitmentTreeSerialization>,
	/// Modified era rewards.
	pub rewards: Option<Rewards>,
}

/// Extra information in block insertion.
pub struct ExtrasInsert {
	/// The primitive fork choice before applying finalization rules.
	pub fork_choice: ForkChoice,
	/// Is the inserted block considered finalized.
	pub is_finalized: bool,
}
