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

use ethjson::bytes::Bytes;
use heapsize::HeapSizeOf;
use rlp::{DecoderError, Encodable, Rlp, RlpStream};
use std::cmp;
use std::{fmt, io};

/// Equihash solution size.
/// n = 192 k =7  size = ((n/k+1)+1)*(2**k)/8
pub const SOLUTION_SIZE: usize = 400;

/// Equihash solution
#[derive(Clone)]
pub struct EquihashSolution([u8; SOLUTION_SIZE]);

///  Equihash solution error
pub enum SolutionError {
	/// solution length error , solution length must be same with SOLUTION_SIZE
	LengthErr,
}

impl EquihashSolution {
	// only for read solution from json file. if bytes length error, return default solution
	pub fn force_convert_from_bytes(s: Bytes) -> EquihashSolution {
		match s.len().cmp(&SOLUTION_SIZE) {
			cmp::Ordering::Equal => {
				let mut sol = [0; SOLUTION_SIZE];
				sol.copy_from_slice(&s);
				EquihashSolution(sol)
			}
			_ => EquihashSolution::default(),
		}
	}

	pub fn try_from(s: Vec<u8>) -> Result<Self, SolutionError> {
		match s.len().cmp(&SOLUTION_SIZE) {
			cmp::Ordering::Less | cmp::Ordering::Greater => Err(SolutionError::LengthErr),
			cmp::Ordering::Equal => {
				let mut sol = [0; SOLUTION_SIZE];
				sol.copy_from_slice(&s);
				Ok(EquihashSolution(sol))
			}
		}
	}
}

impl AsRef<[u8]> for EquihashSolution {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl Default for EquihashSolution {
	fn default() -> Self {
		EquihashSolution([0; SOLUTION_SIZE])
	}
}

impl fmt::Debug for EquihashSolution {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let self_ref: &[u8] = &self.0;
		write!(f, "{:?}", self_ref)
	}
}

impl rlp::Decodable for EquihashSolution {
	fn decode(r: &Rlp) -> Result<Self, DecoderError> {
		r.decoder()
			.decode_value(|value| match value.len().cmp(&SOLUTION_SIZE) {
				cmp::Ordering::Less => Err(DecoderError::RlpIsTooShort),
				cmp::Ordering::Greater => Err(DecoderError::RlpIsTooBig),
				cmp::Ordering::Equal => {
					let mut sol = [0u8; SOLUTION_SIZE];
					sol.copy_from_slice(value);
					Ok(EquihashSolution(sol))
				}
			})
	}
}

impl rlp::Encodable for EquihashSolution {
	fn rlp_append(&self, r: &mut RlpStream) {
		r.encoder().encode_value(&self.0)
	}
}

impl HeapSizeOf for EquihashSolution {
	fn heap_size_of_children(&self) -> usize {
		0
	}
}

impl fmt::LowerHex for EquihashSolution {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if f.alternate() {
			write!(f, "0x")?;
		}

		for i in &self.0[..] {
			write!(f, "{:02x}", i)?;
		}
		Ok(())
	}
}
