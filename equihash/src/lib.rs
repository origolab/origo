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

extern crate either;
extern crate ethereum_types;
extern crate memmap;
extern crate parking_lot;
extern crate primal;
extern crate blake2_rfc;

#[macro_use]
extern crate crunchy;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate rustc_hex;

#[cfg(test)]
extern crate serde_json;

#[cfg(test)]
extern crate tempdir;


pub mod equihash;

use ethereum_types::{U256, U512};
use parking_lot::Mutex;
use std::mem;
use std::path::{Path, PathBuf};


/// Convert an Ethash boundary to its original difficulty. Basically just `f(x) = 2^256 / x`.
pub fn boundary_to_difficulty(boundary: &ethereum_types::H256) -> U256 {
	difficulty_to_boundary_aux(&**boundary)
}

/// Convert an Ethash difficulty to the target boundary. Basically just `f(x) = 2^256 / x`.
pub fn difficulty_to_boundary(difficulty: &U256) -> ethereum_types::H256 {
	difficulty_to_boundary_aux(difficulty).into()
}

fn difficulty_to_boundary_aux<T: Into<U512>>(difficulty: T) -> ethereum_types::U256 {
	let difficulty = difficulty.into();

	assert!(!difficulty.is_zero());

	if difficulty == U512::one() {
		U256::max_value()
	} else {
		// difficulty > 1, so result should never overflow 256 bits
		U256::from((U512::one() << 256) / difficulty)
	}
}

#[test]
fn test_difficulty_to_boundary() {
	use ethereum_types::H256;
	use std::str::FromStr;

	assert_eq!(difficulty_to_boundary(&U256::from(1)), H256::from(U256::max_value()));
	assert_eq!(difficulty_to_boundary(&U256::from(2)), H256::from_str("8000000000000000000000000000000000000000000000000000000000000000").unwrap());
	assert_eq!(difficulty_to_boundary(&U256::from(4)), H256::from_str("4000000000000000000000000000000000000000000000000000000000000000").unwrap());
	assert_eq!(difficulty_to_boundary(&U256::from(32)), H256::from_str("0800000000000000000000000000000000000000000000000000000000000000").unwrap());
}

#[test]
fn test_difficulty_to_boundary_regression() {
	use ethereum_types::H256;

	// the last bit was originally being truncated when performing the conversion
	// https://github.com/paritytech/parity-ethereum/issues/8397
	for difficulty in 1..9 {
		assert_eq!(U256::from(difficulty), boundary_to_difficulty(&difficulty_to_boundary(&difficulty.into())));
		assert_eq!(H256::from(difficulty), difficulty_to_boundary(&boundary_to_difficulty(&difficulty.into())));
		assert_eq!(U256::from(difficulty), boundary_to_difficulty(&boundary_to_difficulty(&difficulty.into()).into()));
		assert_eq!(H256::from(difficulty), difficulty_to_boundary(&difficulty_to_boundary(&difficulty.into()).into()));
	}
}

#[test]
#[should_panic]
fn test_difficulty_to_boundary_panics_on_zero() {
	difficulty_to_boundary(&U256::from(0));
}

#[test]
#[should_panic]
fn test_boundary_to_difficulty_panics_on_zero() {
	boundary_to_difficulty(&ethereum_types::H256::from(0));
}
