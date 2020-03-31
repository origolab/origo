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

use error::{BlockError, Error};
use equihash::equihash::{get_solution_prefix, verify_equihash_solution, OnChainEquihash};
use ethereum_types::{H256, U256};
use rlp::decode;
use rust_crypto::digest::Digest;
use rust_crypto::sha2::Sha256;
use types::header::Header;
use types::solution::EquihashSolution;
use unexpected::OutOfBounds;

fn calc_proof(input: Vec<u8>) -> H256 {
	// do double sha256.
	let mut sha256 = Sha256::new();
	let mut hash_result = [0u8; 32];
	sha256.input(&input);
	sha256.result(&mut hash_result[..]);
	sha256.reset();
	sha256.input(&hash_result);
	sha256.result(&mut hash_result[..]);

	hash_result.reverse();
	let proof = H256::from(&hash_result[..]);
	proof
}

fn check_block_seal(header: &Header) -> Result<(H256, EquihashSolution), Error> {
	trace!(target: "miner", "check_block_seal");
	let seal = header.seal();

	// for equihash, the seal is wrapped with nonce and solution.
	if seal.len() != 2 {
		return Err(BlockError::InvalidSeal.into());
	}

	let nonce = match decode::<H256>(&seal[0]) {
		Ok(n) => n,
		Err(_) => {
			return Err(BlockError::InvalidSeal.into());
		}
	};

	let solution = match decode::<EquihashSolution>(&seal[1]) {
		Ok(s) => s,
		Err(_) => {
			return Err(BlockError::InvalidSeal.into());
		}
	};

	Ok((nonce, solution))
}

pub fn verify_block_pow(header: &Header) -> Result<(), Error> {
	trace!(target: "miner", "verify_block_solution");

	let (nonce, solution) =  match check_block_seal(header) {
		Ok((n, s))=>(n,s),
		Err(e)=> return Err(e),
	};

	let pow_hash = header.pow_hash();
	let mut input = pow_hash.0.to_vec();
	input.extend(nonce.0.to_vec());

	let target = equihash::difficulty_to_boundary(&header.difficulty());
	input.extend(get_solution_prefix::<OnChainEquihash>());
	input.extend(solution.as_ref());

	trace!(target: "miner", "input {:?}", input);

	let proof = calc_proof(input);
	trace!(target: "miner", "verify proof hash {:?} target {:?}", proof, target);

	match target.cmp(&proof) {
		std::cmp::Ordering::Less => {
			return Err(From::from(BlockError::InvalidProofOfWork(OutOfBounds {
				min: None,
				max: Some(U256::from(target)),
				found: U256::from(proof),
			})));
		}
		std::cmp::Ordering::Greater | std::cmp::Ordering::Equal => return Ok(()),
	}
}

/// verify block equihash solution
pub fn verify_block_solution(header: &Header) -> Result<(), Error> {
	trace!(target: "miner", "verify_block_solution");

	let (nonce, solution) =  match check_block_seal(header) {
		Ok((n, s))=>(n,s),
		Err(e)=> return Err(e),
	};

	let pow_hash = header.pow_hash();
	let mut input = pow_hash.0.to_vec();
	input.extend(nonce.0.to_vec());

	trace!(target: "miner", "verify solution input {:?},  solution {:?}", input, solution);
	if (!verify_equihash_solution::<OnChainEquihash>(&input, &solution.as_ref())) {
		return Err(BlockError::InvalidSolution.into());
	}

	Ok(())
}

#[cfg(test)]
mod tests {
	use equihash::equihash::{get_solution_prefix, verify_equihash_solution, OnChainEquihash};
	use ethereum_types::H256;
	use rustc_hex::FromHex;
	use types::header::Header;
	use verification::equihash_verifier::calc_proof;

	#[test]
	//TODO(eric) do equihash verify test
	#[ignore]
	fn test_equihash_on_real_block() {}

	#[test]
	fn test_calc_proof() {
		let pow_hash = "d5475a47f5905fd62e052fd49d0a9aa012da7324288cb0aea60d85f4126321bcf7a84f7fb00b65852b5ac7b5b987fd5f2e52a69a774ff0d998545fd6cfdc2ff0".from_hex().unwrap();
		let nonce = "00ca36c53bce32e882b0c9191f45657e6d649d7500000000fe11f3f696e50000"
			.from_hex()
			.unwrap();
		let solution = "0086d348bbba9af1ced895c390c02fb66f689bc39171f2ffcb05bb4f8b8d1ed215119e6f52a21710e7da5b4a04d15552c76901bc65a7cce3525aa69e01de1656f7bd69aa77caf115f4921b349f906c3f0491a8e27975ce3359a43da16551d244090e2ad80e9564ce8f83f3cdc71cbf295273f7ee2e9059c227e783526735261a6d57884dfcc5678b7fa5aa92e7361541a99ea59a3a491761f728d81df94d1a3e2dc892dfe9ad3820b335e00bc57fc93885e5ec34c8d867ee79d67898ec62e784941bcf2acded10b301f3371fbc5a56bd4b5fa031e1f800ba3b6235976b61454d2516c333be3d8a14465398e8d0e2941c15ed9ea8f19c2daa089c0e9380a3677e642d7c72427cd1ca2a1370be891f6c9ce83288329d9e597b0de7b26af4ae0793d9dce3de891753d483d3a7c0137e70fb46b8b145a1fd0a4987c5b9447d01b22e7cd1d7c7e5189b84794e5f8f43e615776e55d65dad86d011e4036f411e5813df7d3876f7141b645ac4a021408f3e23517607767fd87aed37491d6a81bce0ff703bc7c87863186c840a2f0a4e69f13d9a".from_hex().unwrap();
		let expect_proof = "134ee58f9951f364320d53113035239a620f2c96e0b884b41c5949632ad14f30"
			.from_hex()
			.unwrap();

		let mut input = pow_hash;
		input.extend(nonce);
		input.extend(get_solution_prefix::<OnChainEquihash>());
		input.extend(solution);

		let proof = calc_proof(input);
		assert_eq!(proof, H256::from(&expect_proof[..]));
	}
}
