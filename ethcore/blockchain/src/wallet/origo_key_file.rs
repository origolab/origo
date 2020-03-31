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

use crate::wallet::wallet_types::*;

use crate::wallet::origo_account::OrigoAccount;
use ethstore::ethkey::Password;
use ethstore::JsonCrypto;
use serde::de::{DeserializeOwned, Error, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io::Cursor;
use std::io::{Read, Write};

/*pub struct OpaqueOrigoKeyFile {
	origo_key_file: OrigoKeyFile
}

impl Serialize for OpaqueOrigoKeyFile {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where
		S: Serializer,
	{
		self.origo_key_file.serialize(serializer)
	}
}

impl<T> From<T> for OpaqueOrigoKeyFile where T: Into<OrigoKeyFile> {
	fn from(val: T) -> Self {
		OpaqueOrigoKeyFile { origo_key_file: val.into() }
	}
}*/

pub struct OrigoKeyFileWhole {
	files: Vec<OrigoKeyFile>,
}

impl Serialize for OrigoKeyFileWhole {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		self.files.serialize(serializer)
	}
}

/*impl<'a> Deserialize<'a> for OrigoKeyFileWhole {
	fn deserialize<D>(deserializer: D) -> Result<OrigoKeyFileWhole, D::Error>
		where D: Deserializer<'a>
	{
		deserializer.deserialize_seq(OrigoKeyFileFieldVisitor)
	}
}*/

impl OrigoKeyFileWhole {
	pub fn new() -> Self {
		OrigoKeyFileWhole { files: Vec::new() }
	}

	pub fn add_file(&mut self, file: OrigoKeyFile) {
		self.files.push(file);
	}

	pub fn load_keys(
		&mut self,
		pass: &Password,
		decrypt: bool,
	) -> Vec<(
		SaplingExtendedFullViewingKey,
		Option<SaplingExtendedSpendingKey>,
	)> {
		let mut ret = Vec::new();
		println!("in load_keys");
		while let Some(file) = self.files.pop() {
			let origo_account = OrigoAccount::from_file(file, None);

			let origo_account = origo_account.unwrap();

			let none_pass = Password::from("");
			let secret_efvk = origo_account.efvk.decrypt(&none_pass).unwrap();
			let mut rdr_efvk = Cursor::new(secret_efvk);
			let efvk = SaplingExtendedFullViewingKey::read(&mut rdr_efvk).unwrap();

			println!("decrypt = {}", decrypt);
			let mut espk_op = None;
			if decrypt {
				let secret = origo_account.crypto.decrypt(pass).unwrap();
				let mut rdr = Cursor::new(secret);
				let espk = SaplingExtendedSpendingKey::read(&mut rdr).unwrap();
				espk_op = Some(espk);
			}

			ret.push((efvk, espk_op));
		}
		ret
	}

	pub fn load<R>(reader: R) -> Result<Self, serde_json::Error>
	where
		R: Read,
	{
		let files = serde_json::from_reader(reader).unwrap();
		let whole = OrigoKeyFileWhole { files: files };
		Ok(whole)
		//serde_json::from_reader(reader)
	}

	pub fn write<W>(&self, writer: &mut W) -> Result<(), serde_json::Error>
	where
		W: Write,
	{
		serde_json::to_writer(writer, self)
	}
}

#[derive(Debug, PartialEq, Serialize)]
pub struct OrigoKeyFile {
	pub address: String,
	pub crypto: JsonCrypto,
	pub efvk: JsonCrypto,
}

enum OrigoKeyFileField {
	Address,
	Crypto,
	Efvk,
}

impl<'a> Deserialize<'a> for OrigoKeyFileField {
	fn deserialize<D>(deserializer: D) -> Result<OrigoKeyFileField, D::Error>
	where
		D: Deserializer<'a>,
	{
		deserializer.deserialize_any(OrigoKeyFileFieldVisitor)
	}
}

struct OrigoKeyFileFieldVisitor;

impl<'a> Visitor<'a> for OrigoKeyFileFieldVisitor {
	type Value = OrigoKeyFileField;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		write!(formatter, "a valid key file field")
	}

	fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
	where
		E: Error,
	{
		match value {
			"crypto" => Ok(OrigoKeyFileField::Crypto),
			"Crypto" => Ok(OrigoKeyFileField::Crypto),
			"address" => Ok(OrigoKeyFileField::Address),
			"efvk" => Ok(OrigoKeyFileField::Efvk),
			_ => Err(Error::custom(format!("Unknown field: '{}'", value))),
		}
	}
}

impl<'a> Deserialize<'a> for OrigoKeyFile {
	fn deserialize<D>(deserializer: D) -> Result<OrigoKeyFile, D::Error>
	where
		D: Deserializer<'a>,
	{
		static FIELDS: &'static [&'static str] = &["crypto", "Crypto", "address", "efvk"];
		deserializer.deserialize_struct("OrigoKeyFile", FIELDS, OrigoKeyFileVisitor)
	}
}

struct OrigoKeyFileVisitor;
impl<'a> Visitor<'a> for OrigoKeyFileVisitor {
	type Value = OrigoKeyFile;

	fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
		write!(formatter, "a valid key object")
	}

	fn visit_map<V>(self, mut visitor: V) -> Result<Self::Value, V::Error>
	where
		V: MapAccess<'a>,
	{
		let mut address = None;
		let mut crypto = None;
		let mut efvk = None;

		loop {
			match visitor.next_key()? {
				Some(OrigoKeyFileField::Address) => {
					address = Some(visitor.next_value()?);
				}
				Some(OrigoKeyFileField::Crypto) => {
					crypto = Some(visitor.next_value()?);
				}
				Some(OrigoKeyFileField::Efvk) => {
					efvk = Some(visitor.next_value()?);
				}
				None => {
					break;
				}
			}
		}

		let crypto = match crypto {
			Some(crypto) => crypto,
			None => return Err(V::Error::missing_field("crypto")),
		};

		let efvk = match efvk {
			Some(efvk) => efvk,
			None => return Err(V::Error::missing_field("efvk")),
		};

		let result = OrigoKeyFile {
			address: address.unwrap(),
			crypto: crypto,
			efvk: efvk,
		};

		Ok(result)
	}
}

impl OrigoKeyFile {
	pub fn load<R>(reader: R) -> Result<Self, serde_json::Error>
	where
		R: Read,
	{
		serde_json::from_reader(reader)
	}

	pub fn write<W>(&self, writer: &mut W) -> Result<(), serde_json::Error>
	where
		W: Write,
	{
		serde_json::to_writer(writer, self)
	}
}
