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

use ethereum_types::{Address, H160, U256};
use heapsize::HeapSizeOf;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

pub const MAX_ERA: usize = 50;

#[derive(Debug, PartialEq, Clone)]
pub struct EraRewardInfo {
	/// era number.
	era: usize,
	/// total Reward have been mined at the begin of one era.
	total: U256,
	/// base reward of current era.
	base: U256,
}

impl EraRewardInfo {
	pub fn new(era: usize, total: U256, base: U256) -> Self {
		EraRewardInfo {
			era: era,
			total: total,
			base: base,
		}
	}

	pub fn era(&self) -> usize {
		self.era
	}

	pub fn total(&self) -> U256 {
		self.total
	}

	pub fn base(&self) -> U256 {
		self.base
	}
}

impl Encodable for EraRewardInfo {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(3);
		s.append(&self.era);
		s.append(&self.total);
		s.append(&self.base);
	}
}

impl Decodable for EraRewardInfo {
	fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
		Ok(EraRewardInfo {
			era: rlp.val_at(0)?,
			total: rlp.val_at(1)?,
			base: rlp.val_at(2)?,
		})
	}
}

impl HeapSizeOf for EraRewardInfo {
	fn heap_size_of_children(&self) -> usize {
		0
	}
}

#[derive(Debug, PartialEq, Clone)]
pub struct Rewards {
	// total reward of current best block.
	total: U256,
	// all era reward information.
	eras: Vec<EraRewardInfo>,
}

impl Rewards {
	pub fn new() -> Self {
		Rewards {
			total: U256::zero(),
			eras: Vec::new(),
		}
	}

	pub fn update_total_reward(&mut self, total: U256) {
		self.total = total;
	}

	// only can add era > 1, the era 0 will been set on first startup.
	pub fn add_new_era_reward(&mut self, info: EraRewardInfo) {
		if self.eras.len() != info.era {
			panic!("Error add new era {} ", info.era);
		}

		if info.era >= MAX_ERA {
			return;
		}

		self.eras.push(info);
	}

	pub fn delete_last_era(&mut self, era: usize) {
		if self.eras.len() == 0 {
			panic!("era empty");
		}

		if self.eras.len() == 1 {
			panic!("can't delete era 0 ");
		}

		if era >= MAX_ERA {
			return
		}

		if self.eras.len() != era + 1 {
			panic!("error delete era {}", era + 1);
		}

		self.eras.pop();
	}

	pub fn get_era_base_reward(&self, era: usize) -> Option<U256> {
		if self.eras.len() <= era {
			None
		} else {
			Some(self.eras[era].base)
		}
	}

	pub fn total(&self) -> U256 {
		self.total
	}

	pub fn cur_era(&self) -> usize {
		if self.eras.len() == 0 {
			panic!("era empty");
		}

		self.eras.len() - 1
	}

	pub fn eras(&self) -> Vec<EraRewardInfo> {
		self.eras.clone()
	}
}

impl HeapSizeOf for Rewards {
	fn heap_size_of_children(&self) -> usize {
		self.eras.heap_size_of_children()
	}
}

impl rlp::Encodable for Rewards {
	fn rlp_append(&self, s: &mut rlp::RlpStream) {
		s.begin_list(2);
		s.append(&self.total);
		s.append_list(&self.eras);
	}
}

impl rlp::Decodable for Rewards {
	fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
		Ok(Rewards {
			total: rlp.val_at(0)?,
			eras: rlp.list_at(1)?,
		})
	}
}
