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

//! Blockchain configuration.

use common_types::reward_config::RewardConfig;

/// Blockchain configuration.
#[derive(Debug, PartialEq, Clone)]
pub struct Config {
	/// Preferred cache size in bytes.
	pub pref_cache_size: usize,
	/// Maximum cache size in bytes.
	pub max_cache_size: usize,
	/// Reward config
	pub reward_config: RewardConfig,
	/// File path prefix for wallet.
	pub file_path_prefix: Option<String>,
}

impl Default for Config {
	fn default() -> Self {
		Config {
			pref_cache_size: 1 << 14,
			max_cache_size: 1 << 20,
			reward_config: RewardConfig::default(),
			file_path_prefix: None,
		}
	}
}

impl Config {
	pub fn new(file_path: String) -> Self {
		Config {
			pref_cache_size: 1 << 14,
			max_cache_size: 1 << 20,
			reward_config: RewardConfig::default(),
			file_path_prefix: Some(file_path),
		}
	}
}

