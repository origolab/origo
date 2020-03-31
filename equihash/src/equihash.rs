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

use blake2_rfc::blake2b::Blake2b;

/// Equihash algorithm instance.
///
/// A brief, yet incomplete overview of the algorithm:
/// (1) prepare indexed set of 2^(N / (K + 1) + 1) N-bits strings (BSTR);
/// (2) select 2^K BSTRs from this set, such that their' XOR is zero;
/// (3) solution is indices of selected BSTRs.
///
/// In case of Zcash Equihash, the BSTR is the hash of block header (excluding solution itself) ++
/// the hash index. The hash could be/is splitted into several BSTRs, which are used as the input
/// for the Wagner's Generalized Birthday problem algorithm.
///
/// The Wagner's algorithm (https://people.eecs.berkeley.edu/~daw/papers/genbday-long.ps) itself
/// works with paded BSTRs (rows).
pub trait Equihash {
	/// Parameter N of Equihash algorithm.
	const N: u32;
	/// Parameter K of Equihash algorithm.
	const K: u32;
	/// Blake2b personalization used by the algorithm instance.
	const BLAKE2B_PERSONALIZATION: [u8; 16];
	///Solution prefix
	const SOLUTION_PREFIX: [u8; 3];

	/// The number of N-bit BSTRs that could be generated from the single computed hash.
	const BSTRS_PER_HASH: usize = (512 / Self::N) as usize;
	/// The size required to fit of every BSTR.
	const HASH_SIZE: usize = Self::BSTRS_PER_HASH * (Self::N as usize) / 8;
	/// Number of bits required to store single BSTR index.
	const BSTR_INDEX_BITS: usize = (Self::N / (Self::K + 1)) as usize;
	/// Number of bytes required to store single BSTR index (there could be extra bits in
	/// binary representation of the index).
	const BSTR_INDEX_BYTES: usize = (Self::BSTR_INDEX_BITS + 7) / 8;
	/// Number of BSTR indices in solution.
	const BSTR_INDICES_IN_SOLUTION: usize = 1usize << Self::K;
	/// The size (in bytes) of compressed Equihash solution (compressed array of BE-encoded BSTRs indices).
	const SOLUTION_COMPRESSED_SIZE: usize =
		Self::BSTR_INDICES_IN_SOLUTION * (Self::BSTR_INDEX_BITS + 1) / 8;
	/// Number of leading zero bytes to pad compressed BSTR index to fit into u32.
	const SOLUTION_PAD_BYTES: usize = 4 - (Self::BSTR_INDEX_BITS + 8) / 8;
	/// The size (in bytes) of single row used by Wagner algorithm.
	const ROW_SIZE: usize = 2 * Self::BSTR_INDEX_BYTES + 4 * Self::BSTR_INDICES_IN_SOLUTION;
	/// The size (in bytes) of the hash part of the row.
	const ROW_HASH_LENGTH: usize = (Self::K as usize + 1) * Self::BSTR_INDEX_BYTES;
}

/// Equihash algorithm instance.
pub struct OnChainEquihash;

impl Equihash for OnChainEquihash {
	const N: u32 = 192;
	const K: u32 = 7;

	const BLAKE2B_PERSONALIZATION: [u8; 16] = [
		0x4f, 0x72, 0x69, 0x67, 0x6f, 0x50, 0x6f, 0x57, //b"OrigoPoW"
		0xc0, 0x00, 0x00, 0x00, //LE(N) 192
		0x07, 0x00, 0x00, 0x00, //LE(K) 7
	];

	const SOLUTION_PREFIX: [u8; 3] = [0xfd, 0x90, 0x01];
}

const HSIZE: usize = 48;

pub struct Hash([u8; HSIZE]);

impl Default for Hash {
	fn default() -> Self {
		Hash([0; HSIZE])
	}
}

impl AsRef<[u8]> for Hash {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl AsMut<[u8]> for Hash {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.0
	}
}

/// Verify equihash solution.
pub fn verify_equihash_solution<Algorithm: Equihash>(input: &[u8], solution: &[u8]) -> bool {
	trace!("input {:?} solution {:?}", input, solution);

	// prepare Blake2b context with personalization
	let mut context = Blake2b::with_params(
		Algorithm::HASH_SIZE,
		&[],
		&[],
		&Algorithm::BLAKE2B_PERSONALIZATION,
	);
	context.update(input);

	// we're using two dynamic vectors here && swap pointers when required
	// for on-chain algorithm instance:
	// sizeof(*rows1) ~ 512 * 2054 ~ 1M
	// sizeof(*rows2) ~ 256 * 2054 ~ 512K
	let mut rows1 = vec![0u8; Algorithm::BSTR_INDICES_IN_SOLUTION * Algorithm::ROW_SIZE];
	let mut rows2 = vec![0u8; Algorithm::BSTR_INDICES_IN_SOLUTION * Algorithm::ROW_SIZE / 2];

	let mut current_rows = &mut rows1;
	let mut backup_rows = &mut rows2;

	let mut hash = Hash::default();
	let mut current_rows_pos = 0;
	for_each_solution_index::<Algorithm, _>(solution, &mut |index| {
		let hash_half_index = (index as usize / Algorithm::BSTRS_PER_HASH) as u32;
		generate_hash(&context, hash_half_index, hash.as_mut());

		let hash_begin = (index as usize % Algorithm::BSTRS_PER_HASH) * Algorithm::N as usize / 8;
		let hash_end = hash_begin + Algorithm::N as usize / 8;
		let sub_hash = &hash.as_ref()[hash_begin..hash_end];

		let mut current_rows_sub_pos = current_rows_pos;
		expand_array(
			sub_hash,
			Algorithm::BSTR_INDEX_BITS,
			0,
			&mut |buffer: &[u8; 4]| {
				current_rows
					[current_rows_sub_pos..current_rows_sub_pos + Algorithm::BSTR_INDEX_BYTES]
					.copy_from_slice(&buffer[0..Algorithm::BSTR_INDEX_BYTES]);
				current_rows_sub_pos += Algorithm::BSTR_INDEX_BYTES;
			},
		);
		current_rows[current_rows_pos + Algorithm::ROW_HASH_LENGTH
			..current_rows_pos + Algorithm::ROW_HASH_LENGTH + 4]
			.copy_from_slice(&index.to_be_bytes());
		current_rows_pos += Algorithm::ROW_SIZE;
	});

	let mut hash_len = Algorithm::ROW_HASH_LENGTH;
	let mut indices_len = 4;
	let mut current_rows_count = current_rows.len() / Algorithm::ROW_SIZE;
	loop {
		if current_rows_count <= 1 {
			break;
		}

		let mut current_row_begin = 0;
		let mut current_row_end = Algorithm::ROW_SIZE;
		let mut next_row_begin = Algorithm::ROW_SIZE;
		let mut next_row_end = Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
		let mut merged_row_begin = 0;
		let mut merged_row_end = Algorithm::ROW_SIZE;
		for _ in 0..current_rows_count / 2 {
			let row1 = &current_rows[current_row_begin..current_row_end];
			let row2 = &current_rows[next_row_begin..next_row_end];
			if !has_collision(row1, row2, Algorithm::BSTR_INDEX_BYTES) {
				return false;
			}
			if indices_before(row2, row1, hash_len, indices_len) {
				return false;
			}
			if !distinct_indices(row1, row2, hash_len, indices_len) {
				return false;
			}

			let merged_row = &mut backup_rows[merged_row_begin..merged_row_end];
			merge_rows(
				row1,
				row2,
				merged_row,
				hash_len,
				indices_len,
				Algorithm::BSTR_INDEX_BYTES,
			);

			current_row_begin += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			current_row_end += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			next_row_begin += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			next_row_end += Algorithm::ROW_SIZE + Algorithm::ROW_SIZE;
			merged_row_begin += Algorithm::ROW_SIZE;
			merged_row_end += Algorithm::ROW_SIZE;
		}

		::std::mem::swap(&mut current_rows, &mut backup_rows);
		hash_len -= Algorithm::BSTR_INDEX_BYTES;
		indices_len *= 2;
		current_rows_count /= 2;
	}

	current_rows[0..Algorithm::ROW_SIZE]
		.iter()
		.take(hash_len)
		.all(|x| *x == 0)
}

pub fn get_solution_prefix<Algorithm: Equihash>() -> Vec<u8> {
	Algorithm::SOLUTION_PREFIX.to_vec()
}

fn for_each_solution_index<Algorithm, ForEach>(solution: &[u8], for_each: &mut ForEach)
where
	Algorithm: Equihash,
	ForEach: FnMut(u32),
{
	trace!(
		"solution.len() {} size {}",
		solution.len(),
		Algorithm::SOLUTION_COMPRESSED_SIZE
	);
	// consensus parameters enforces this
	debug_assert_eq!(
		solution.len(),
		Algorithm::SOLUTION_COMPRESSED_SIZE,
		"Wrong equihash parameters specified in consensus",
	);

	expand_array(
		solution,
		Algorithm::BSTR_INDEX_BITS + 1,
		Algorithm::SOLUTION_PAD_BYTES,
		&mut |buffer: &[u8; 4]| for_each(u32::from_be_bytes(*buffer)),
	);
}

fn expand_array<E: FnMut(&[u8; 4])>(
	compressed: &[u8],
	blen: usize,
	pad: usize,
	expand_single: &mut E,
) {
	let out_width = (blen + 7) / 8 + pad;
	let blen_mask = (1u32 << blen) - 1;

	// The acc_bits least-significant bits of acc_value represent a bit sequence
	// in big-endian order.
	let mut acc_buffer = [0u8; 4];
	let mut acc_bits = 0usize;
	let mut acc_value = 0u32;

	for i in 0usize..compressed.len() {
		acc_value = (acc_value << 8) | (compressed[i] as u32);
		acc_bits += 8;

		// When we have bit_len or more bits in the accumulator, write the next
		// output element.
		if acc_bits >= blen {
			acc_bits -= blen;
			for x in pad..out_width {
				acc_buffer[x] = (
					// Big-endian
					(acc_value >> (acc_bits + (8 * (out_width - x - 1)))) as u8
				) & (
					// Apply blen_mask across byte boundaries
					((blen_mask >> (8 * (out_width - x - 1))) & 0xFF) as u8
				);
			}

			expand_single(&acc_buffer)
		}
	}
}

fn generate_hash(context: &Blake2b, index: u32, hash: &mut [u8]) {
	let mut context = context.clone();
	context.update(&index.to_le_bytes());
	hash.copy_from_slice(context.finalize().as_bytes())
}

fn merge_rows(
	row1: &[u8],
	row2: &[u8],
	merged_row: &mut [u8],
	len: usize,
	indices_len: usize,
	trim: usize,
) {
	let mut merged_row_pos = 0;
	for i in trim..len {
		merged_row[merged_row_pos] = row1[i] ^ row2[i];
		merged_row_pos += 1;
	}

	if indices_before(row1, row2, len, indices_len) {
		merged_row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
		merged_row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
	} else {
		merged_row[len - trim..len - trim + indices_len]
			.clone_from_slice(&row2[len..len + indices_len]);
		merged_row[len - trim + indices_len..len - trim + indices_len + indices_len]
			.clone_from_slice(&row1[len..len + indices_len]);
	}
}

fn distinct_indices(row1: &[u8], row2: &[u8], len: usize, indices_len: usize) -> bool {
	let mut i = 0;
	let mut j = 0;
	while i < indices_len {
		while j < indices_len {
			if row1[len + i..len + i + 4] == row2[len + j..len + j + 4] {
				return false;
			}

			j += 4;
		}

		i += 4;
	}

	true
}

fn has_collision(row1: &[u8], row2: &[u8], collision_byte_length: usize) -> bool {
	for i in 0..collision_byte_length {
		if row1[i] != row2[i] {
			return false;
		}
	}

	true
}

fn indices_before(row1: &[u8], row2: &[u8], len: usize, indices_len: usize) -> bool {
	for i in 0..indices_len {
		if row1[len + i] < row2[len + i] {
			return true;
		} else if row1[len + i] > row2[len + i] {
			return false;
		}
	}

	false
}

fn compress_array(data: &[u8], array: &mut Vec<u8>, bit_len: usize, byte_pad: usize) {
	let in_width = (bit_len + 7) / 8 + byte_pad;
	let bit_len_mask = (1u32 << bit_len) - 1;

	// The acc_bits least-significant bits of acc_value represent a bit sequence
	// in big-endian order.
	let mut acc_bits = 0usize;
	let mut acc_value = 0u32;

	let mut j = 0usize;
	for i in 0usize..array.len() {
		// When we have fewer than 8 bits left in the accumulator, read the next
		// input element.
		if acc_bits < 8 {
			acc_value = acc_value << bit_len;
			for x in byte_pad..in_width {
				acc_value = acc_value
					| ((data[j + x] & (((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF) as u8))
						as u32) << (8 * (in_width - x - 1));
			}
			j += in_width;
			acc_bits += bit_len;
		}

		acc_bits -= 8;
		array[i] = ((acc_value >> acc_bits) & 0xFF) as u8;
	}
}

pub fn copy_from_u32<Algorithm: Equihash>(indices: &[u32]) -> Vec<u8> {
	let collision_bit_length = Algorithm::BSTR_INDEX_BITS;

	let indices_len = indices.len() * 4;
	let min_len = (collision_bit_length + 1) * indices_len / (8 * 4);
	let byte_pad = 4 - ((collision_bit_length + 1) + 7) / 8;

	let mut array = Vec::new();
	for index in indices.iter() {
		array.extend_from_slice(&index.to_be_bytes());
	}

	let mut ret = vec![0u8; min_len];
	compress_array(&array, &mut ret, collision_bit_length + 1, byte_pad);
	ret
}

#[cfg(test)]
mod tests {
	use super::*;

	use rustc_hex::FromHex;

	struct TestEquihash;

	impl Equihash for TestEquihash {
		const N: u32 = 192;
		const K: u32 = 7;
		const BLAKE2B_PERSONALIZATION: [u8; 16] = [
			0x4f, 0x72, 0x69, 0x67, 0x6f, 0x50, 0x6f, 0x57, //b"OrigoPoW"
			0xc0, 0x00, 0x00, 0x00, //LE(N) 192
			0x07, 0x00, 0x00, 0x00, //LE(K) 7
		];

		const SOLUTION_PREFIX: [u8; 3] = [0xfd, 0x90, 0x01];
	}

	fn get_minimal_from_indices(indices: &[u32], collision_bit_length: usize) -> Vec<u8> {
		let indices_len = indices.len() * 4;
		let min_len = (collision_bit_length + 1) * indices_len / (8 * 4);
		let byte_pad = 4 - ((collision_bit_length + 1) + 7) / 8;

		let mut array = Vec::new();
		for index in indices.iter() {
			array.extend_from_slice(&index.to_be_bytes());
		}

		let mut ret = vec![0u8; min_len];
		compress_array(&array, &mut ret, collision_bit_length + 1, byte_pad);
		ret
	}

	fn compress_array(data: &[u8], array: &mut Vec<u8>, bit_len: usize, byte_pad: usize) {
		let in_width = (bit_len + 7) / 8 + byte_pad;
		let bit_len_mask = (1u32 << bit_len) - 1;

		// The acc_bits least-significant bits of acc_value represent a bit sequence
		// in big-endian order.
		let mut acc_bits = 0usize;
		let mut acc_value = 0u32;

		let mut j = 0usize;
		for i in 0usize..array.len() {
			// When we have fewer than 8 bits left in the accumulator, read the next
			// input element.
			if acc_bits < 8 {
				acc_value = acc_value << bit_len;
				for x in byte_pad..in_width {
					acc_value = acc_value
						| ((data[j + x]
							& (((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF) as u8)) as u32)
							<< (8 * (in_width - x - 1));
				}
				j += in_width;
				acc_bits += bit_len;
			}

			acc_bits -= 8;
			array[i] = ((acc_value >> acc_bits) & 0xFF) as u8;
		}
	}

	fn test_equihash_verifier(head: &[u8], nonce: &[u8], solution: &[u8]) -> bool {
		//let solution = get_minimal_from_indices(solution, TestEquihash::BSTR_INDEX_BITS);
		let mut input = head.to_vec();
		input.extend(nonce);
		verify_equihash_solution::<TestEquihash>(&input, &solution)
	}

	#[test]
	fn verify_equihash_solution_works() {
		let input = FromHex::from_hex("8ffdeb60370da10fea9b6dddf918979f198085296bb991e80ae27e64d48f2a8a2aa857f84f67fb4fe36d1daa4748a3593c137d73fca3ea7c2c1443b01a5cbcdd").unwrap();
		let nonce =
			FromHex::from_hex("005755fa46875cb6fa12f6aca184ca13ada95a3700000000672b8ee0c9550000")
				.unwrap();
		let solution = FromHex::from_hex("001a7668293955a472f8caa8f25e407d7d1dc63994b99435f91c0df913c7a4145ff8f977e037b3417f8d41b6858ddb7bd3730661114b84245a1f2cdab27011a4fa5fca3d56652f157db0660725d1a784dc83c5c2df39f0d1d493cf0eede484cafff097e112d028b9bad22207d935df8ce175a84336221e516cbff0d56a479a96ee928717ebf4f1712ad7099d174780366e823f4f523c1498f510940ae80f8f7b3cf198b7132d9ef0af3b2ccfbe12ed27ec46afc626ca4041104926c74ce9a759e115d519bd2140a008b2beadaa240ecb4267c7d0d3e753c5b20455125a9943559e46573b3256e637f40c9e1ea70a0ec78585d49299f7c9cf403d1c489ef4899750dfd158838c93947702fd9b2207f4451c807b531ca3f1d820e73759de658226c6e674f49712dc114578632a093e56ed773f850c690651b4e95b7167298302a1d581a0383e0b3d7ad0bde44fa2c090b88a24772a739de05d214a98edafa61249a6a38551601aa6bad6ede5dcebee21473595c79b2ed1e01850fb7fe589c7848c7ad3e714ecd6fcce84edc87517f4f7d4").unwrap();
		assert!(test_equihash_verifier(&input, &nonce, &solution));
	}
}
