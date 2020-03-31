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

use jsonrpc_core::futures::future;
use jsonrpc_core::BoxFuture;
use std::sync::Arc;
use v1::traits::OrigoRewardsInfo;
use v1::types::{RewardInfo, TotalReward};
use ethcore::client::BlockChainClient;

/// Rewards rpc implementation.
pub struct OrigoRewardsClient<C> {
	client: Arc<C>,
}

impl<C> OrigoRewardsClient<C> {
	/// Creates new OrigoRewardsClient
	pub fn new(client: &Arc<C>) -> Self {
		OrigoRewardsClient {
			client: client.clone(),
		}
	}
}

impl<C: BlockChainClient + 'static> OrigoRewardsInfo for OrigoRewardsClient<C> {
	fn get_total_reward(&self) -> BoxFuture<TotalReward> {
		Box::new(future::done({
			let (number, total) = self.client.get_total_reward();
			Ok(TotalReward { number, total })
		}))
	}

	fn get_era_rewards(&self, era: Option<usize>) -> BoxFuture<Vec<RewardInfo>> {
		Box::new(future::done({
			let rewards = self.client.get_rewards();
			let mut results = Vec::new();
			let eras = rewards.eras();
			if let Some(r) = era {
				if r <= rewards.cur_era() {
					results.push(RewardInfo {
						era: eras[r].era(),
						total: eras[r].total(),
						base: eras[r].base(),
					});
				}
			} else {
				results = eras
					.iter()
					.map(|eri| RewardInfo {
						era: eri.era(),
						total: eri.total(),
						base: eri.base(),
					})
					.collect();
			}
			Ok(results)
		}))
	}
}
