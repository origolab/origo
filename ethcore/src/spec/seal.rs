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

//! Spec seal.

use rlp::RlpStream;
use ethereum_types::{H256, H520};
use ethjson;
use types::solution::EquihashSolution;

/// Origo seal.
pub struct Origo {
	/// Seal nonce.
	pub nonce: H256,
	/// Seal equihash solution.
	pub solution: EquihashSolution,
}

impl Into<Generic> for Origo {
	fn into(self) -> Generic {
		let mut s = RlpStream::new_list(2);
		s.append(&self.nonce).append(&self.solution);
		Generic(s.out())
	}
}

/// AuthorityRound seal.
pub struct AuthorityRound {
	/// Seal step.
	pub step: usize,
	/// Seal signature.
	pub signature: H520,
}

/// Tendermint seal.
pub struct Tendermint {
	/// Seal round.
	pub round: usize,
	/// Proposal seal signature.
	pub proposal: H520,
	/// Precommit seal signatures.
	pub precommits: Vec<H520>,
}

impl Into<Generic> for AuthorityRound {
	fn into(self) -> Generic {
		let mut s = RlpStream::new_list(2);
		s.append(&self.step).append(&self.signature);
		Generic(s.out())
	}
}

impl Into<Generic> for Tendermint {
	fn into(self) -> Generic {
		let mut stream = RlpStream::new_list(3);
		stream
			.append(&self.round)
			.append(&self.proposal)
			.append_list(&self.precommits);
		Generic(stream.out())
	}
}

pub struct Generic(pub Vec<u8>);

/// Genesis seal type.
pub enum Seal {
	/// Classic ethereum seal.
	Origo(Origo),
	/// AuthorityRound seal.
	AuthorityRound(AuthorityRound),
	/// Tendermint seal.
	Tendermint(Tendermint),
	/// Generic RLP seal.
	Generic(Generic),
}

impl From<ethjson::spec::Seal> for Seal {
	fn from(s: ethjson::spec::Seal) -> Self {
		match s {
			ethjson::spec::Seal::Origo(ogo) => Seal::Origo(Origo {
				nonce: ogo.nonce.into(),
				solution: EquihashSolution::force_convert_from_bytes(ogo.solution)
			}),
			ethjson::spec::Seal::AuthorityRound(ar) => Seal::AuthorityRound(AuthorityRound {
				step: ar.step.into(),
				signature: ar.signature.into()
			}),
			ethjson::spec::Seal::Tendermint(tender) => Seal::Tendermint(Tendermint {
				round: tender.round.into(),
				proposal: tender.proposal.into(),
				precommits: tender.precommits.into_iter().map(Into::into).collect()
			}),
			ethjson::spec::Seal::Generic(g) => Seal::Generic(Generic(g.into())),
		}
	}
}

impl Into<Generic> for Seal {
	fn into(self) -> Generic {
		match self {
			Seal::Generic(generic) => generic,
			Seal::Origo(ogo) => ogo.into(),
			Seal::AuthorityRound(ar) => ar.into(),
			Seal::Tendermint(tender) => tender.into(),
		}
	}
}
