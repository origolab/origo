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

use crate::wallet::origo_key_file::OrigoKeyFile;
use crate::wallet::wallet_types::*;
use ethstore::ethkey::{Password, Secret};
use ethstore::Crypto;
//use ethstore::crypto;
use byteorder::{BigEndian, WriteBytesExt};
use ethstore::Error;
use std::num::NonZeroU32;

/// Account representation.
#[derive(Debug, PartialEq, Clone)]
pub struct OrigoAccount {
	/// Account address
	pub address: String,
	/// Account private key derivation definition.
	pub crypto: Crypto,

	pub efvk: Crypto,
}

impl Into<OrigoKeyFile> for OrigoAccount {
	fn into(self) -> OrigoKeyFile {
		OrigoKeyFile {
			address: self.address.into(),
			crypto: self.crypto.into(),
			efvk: self.efvk.into(),
		}
	}
}

impl OrigoAccount {
	/// Create a new origo account
	/// TODO
	pub fn create(
		address: String,
		efvk: &SaplingExtendedFullViewingKey,
		espk: &SaplingExtendedSpendingKey,
		password: &Password,
		iterations: NonZeroU32,
	) -> Result<Self, Error> {
		let mut wtr_efvk = vec![];
		efvk.write(&mut wtr_efvk);

		let none_pass = Password::from("");

		let mut wtr = vec![];
		espk.write(&mut wtr);

		Ok(OrigoAccount {
			address: address,
			crypto: Crypto::with_plain(&wtr[..], password, iterations)?,
			//TODO, password
			efvk: Crypto::with_plain(&wtr_efvk[..], &none_pass, iterations)?,
		})
	}

	pub fn from_file(json: OrigoKeyFile, filename: Option<String>) -> Result<Self, Error> {
		let crypto = Crypto::from(json.crypto);
		let address = json.address;
		let efvk = Crypto::from(json.efvk);

		Ok(OrigoAccount {
			address,
			crypto,
			efvk,
		})
	}
}
