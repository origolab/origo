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

use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};

use ff::{BitIterator, PrimeField, PrimeFieldRepr};
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use sapling_crypto::{
	pedersen_hash::{pedersen_hash, Personalization},
	primitives::{IncomingViewingKey, Note, PaymentAddress},
};
use zcash_primitives::keys::OutgoingViewingKey;
use zcash_primitives::keys::{ExpandedSpendingKey, FullViewingKey};
use zcash_primitives::transaction::components::{OutputDescription, SpendDescription};
use zcash_primitives::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use zcash_primitives::JUBJUB;

use ethereum_types::H256;
use zcash_primitives::merkle_tree::Hashable;
use zcash_primitives::merkle_tree::{CommitmentTree, CommitmentTreeWitness, IncrementalWitness};
use zcash_primitives::sapling::{Node, SAPLING_COMMITMENT_TREE_DEPTH};

pub type TxHash = H256;

pub type SaplingIncomingViewingKey = IncomingViewingKey<Bls12>;

pub type SaplingExtendedSpendingKey = ExtendedSpendingKey;

pub type SaplingExtendedFullViewingKey = ExtendedFullViewingKey;

pub type SaplingExpandedSpendingKey = ExpandedSpendingKey<Bls12>;

pub type SaplingOutgoingViewingKey = OutgoingViewingKey;

pub type SaplingPaymentAddress = PaymentAddress<Bls12>;

pub type SaplingFullViewingKey = FullViewingKey<Bls12>;

pub type SaplingNote = Note<Bls12>;

pub type SaplingSpendDescription = SpendDescription;

pub type SaplingOutputDescription = OutputDescription;

/// A note commitment tree used to store note commitments that Spend transfers produce.
/// It is used to express the existence of value and the capability to spend it.
/// Each node in the incremental Merkle tree is associated with a note commitment.
pub type SaplingMerkleTree = CommitmentTree<Node>;
pub type SaplingWitness = IncrementalWitness<Node>;
pub type SaplingCommitmentTreeWitness = CommitmentTreeWitness<Node>;

// 11(d) + 32(pk_d)
pub const PAYMENT_ADDRESS_LENGTH: usize = 43;
