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

//! Origo Accounts-related rpc interface.
use jsonrpc_core::{Result, BoxFuture};
use jsonrpc_derive::rpc;
use ethereum_types::{H256, U256};
use v1::types::UnspentNote;
use v1::types::AmountRequest;
use v1::types::{TotalReward, RewardInfo};

/// Origo-specific rpc interface.
#[rpc]
pub trait OrigoAccountsInfo {
	/// Returns a new a private address using a random generated seed.
	/// The password is used to encrypt the spending key in key store.
	/// The spending key for this zaddr will be added to the node’s wallet.
	#[rpc(name = "origo_getNewAddress")]
	fn get_new_address(&self, String) -> Result<String>;

	/// Returns a private address generated from the seed.
	/// The password is used to encrypt the spending key in key store.
	/// The spending key for this address will be added to the node’s wallet.
	#[rpc(name = "origo_newAddressFromSeed")]

	fn new_address_from_seed(&self, H256, String) -> Result<String>;


	/// Returns all stored private addresses.
	#[rpc(name = "origo_listAddresses")]
	fn addresses(&self) -> Result<Vec<String>>;

	/// Returns the balance of a taddr or zaddr belonging to the node’s wallet.
	/// Optionally set the minimum number of confirmations a transaction must have.
	/// Use 0 to unconfirmed transactions.
	#[rpc(name = "origo_getBalance")]
	fn get_balance(&self, String, Option<u32>) -> Result<U256>;

	/// Returns array of unspent shielded notes with between
	/// minconf and maxconf (inclusive) confirmations.
	/// Optionally filter to only include notes sent to specified addresses.
	#[rpc(name = "origo_listUnspent")]
	fn list_unspent(&self, String, Option<u32>, Option<u32>, Option<bool>) -> Result<Vec<UnspentNote>>;

	/// Send multiple times. Amounts are decimal numbers with at most 8 digits of precision.
	/// Change generated from a taddr flows to a new taddr address,
	/// while change generated from a zaddr returns to itself.
	/// When sending coinbase UTXOs to a zaddr, change is not allowed.
	/// The entire value of the UTXO(s) must be consumed.
	/// Before Sapling activates, the maximum number of zaddr outputs is 54 due to transaction size limits.
	#[rpc(name = "origo_sendMany")]
	fn send_many(&self, String, Vec<AmountRequest>, String, Option<U256>, Option<U256>, Option<u32>) -> Result<H256>;
}

/// Origo rewards rpc interface.
#[rpc]
pub trait OrigoRewardsInfo {
	/// Returns total reward of best block.
	#[rpc(name = "origo_getTotalReward")]
	fn get_total_reward(&self) -> BoxFuture<TotalReward>;

	/// Returns block with given number.
	#[rpc(name = "origo_getEraRewards")]
	fn get_era_rewards(&self, Option<usize>) -> BoxFuture<Vec<RewardInfo>>;
}
