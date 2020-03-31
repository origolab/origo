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

#![warn(missing_docs)]

mod best_block;
mod block_info;
mod blockchain;
mod cache;
mod config;
mod import_route;
mod update;
pub mod wallet;

#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

extern crate bellman;
extern crate dir;
extern crate zip32;
extern crate pairing;
extern crate group;
extern crate ff;
extern crate zcash_primitives;
extern crate zcash_proofs;
extern crate sapling_crypto;

extern crate backtrace;

pub mod generator;
pub use self::blockchain::{BlockProvider, BlockChain, BlockChainDB, BlockChainDBHandler};
pub use self::cache::CacheSize;
pub use self::config::Config;
pub use self::import_route::ImportRoute;
pub use self::update::ExtrasInsert;
pub use ethcore_db::keys::{BlockReceipts, BlockDetails, TransactionAddress, BlockNumberKey};
pub use common_types::tree_route::TreeRoute;
