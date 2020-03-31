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

use ethereum_types::U256;

/// Total reward.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotalReward {
	/// Best block number.
	pub number: u64,
	/// Total Reward from genesis to current best block.
	pub total: U256,
}

/// Era rewards.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RewardInfo {
	/// Current era, start from 0.
	pub era: usize,
	/// Total Reward of pre era.
	pub total: U256,
	/// Base Reward of current era.
	pub base: U256,
}
