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

use ethereum_types::{Address, H160, H256, U256};
use std::ops::{Shl, Shr};
use std::str::FromStr;
use BlockNumber;

#[derive(Debug, PartialEq, Clone)]
pub struct RewardConfig {
	/// Total balance that can been mined
	pub total_reward: U256,
	/// Block count of each era
	pub block_count_each_era: u32,
	/// Production rate of plan total reward in the next era
	pub production_rate: u32,
	/// Maximum uncle count of one block
	pub maximum_uncle_count: u32,
}

impl RewardConfig {
	pub fn calc_era_base_reward(&self, mined: U256) -> U256 {
		let gwei = U256::from(1_000_000_000);
		let era_total_reward = (self.total_reward - mined) * self.production_rate / 100;
		let block_reward = era_total_reward / self.block_count_each_era;

		let miner_reward = gwei + gwei.shr(5) * self.maximum_uncle_count;
		let uncles_reward = (gwei * U256::from(7)).shr(3) * self.maximum_uncle_count;
		let base = block_reward * gwei / (miner_reward + uncles_reward);

		base / gwei * gwei
	}

	pub fn calc_author_miner_reward(&self, base: U256, n_uncles: usize) -> U256 {
		let gwei = U256::from(1_000_000_000);
		let mut reward = base + (base * U256::from(n_uncles)).shr(5);
		reward / gwei * gwei
	}

	pub fn calc_uncle_miner_reward(&self, base: U256, miner: u64, uncle: u64) -> U256 {
		let gwei = U256::from(1_000_000_000);
		let mut reward = (base * U256::from(8 + uncle - miner)).shr(3);
		reward / gwei * gwei
	}

	pub fn calc_era_by_block_number(&self, number: BlockNumber) -> usize {
		(number / (self.block_count_each_era as u64)) as usize
	}

	pub fn is_era_last_block(&self, number: BlockNumber) -> bool {
		(number > 0) && ((number + 1) % (self.block_count_each_era as u64) == 0)
	}

	pub fn is_big_than_min_base_reward(&self, base: U256) -> bool {
		let gwei = U256::from(1_000_000_000);
		if base > gwei {
			true
		} else {
			false
		}
	}

	//only can set for test
	pub fn set_test_config(&mut self, total: U256, count: u32, rate: u32, uncles: u32) {
		self.total_reward = total;
		self.block_count_each_era = count;
		self.production_rate = rate;
		self.maximum_uncle_count = uncles;
	}
}

impl Default for RewardConfig {
	fn default() -> Self {
		RewardConfig {
			total_reward: U256::from_str("c7272221823c0be1400000").unwrap(),
			block_count_each_era: 2000000,
			production_rate: 50,
			maximum_uncle_count: 2,
		}
	}
}
