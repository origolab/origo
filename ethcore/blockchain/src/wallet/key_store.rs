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

use crate::wallet::origo_account::OrigoAccount;
use crate::wallet::origo_key_file::{OrigoKeyFile, OrigoKeyFileWhole};
use crate::wallet::wallet_types::*;
use ethstore::ethkey::Password;

use crate::wallet::sendmany::{CAmount, SendManyRecipient};
use bech32::{u5, Bech32};
use ethereum_types::H160;
use ethereum_types::U256;
use pairing::bls12_381::Bls12;
use sapling_crypto::jubjub::{edwards, Unknown};
use serde_json;
use serde_json::{Result, Value};
use std::collections::hash_map::HashMap;
use std::io::{self, Read, Write};
use std::str::FromStr;
use zcash_primitives::JUBJUB;

use byteorder::{BigEndian, ReadBytesExt};
//use ethstore::crypto::KEY_ITERATIONS;
use ethstore::Error;
use std::fs::File;
use std::io::Cursor;
use std::num::NonZeroU32;
use dir::Directories;

use backtrace::Backtrace;

lazy_static! {
	static ref KEY_ITERATIONS: NonZeroU32 =
		NonZeroU32::new(10240).expect("KEY_ITERATIONS > 0; qed");
}

use std::collections::HashSet;
// TODO(xin): Change to origo prefix.
const ADDR_PREFIX: &'static str = "ogo";

// Struct used to covert between u5 vector and u8 vector.
struct BitVec {
	// TODO: Change to bit implementation.
	pub vec_: Vec<u8>,
}
impl BitVec {
	pub fn new() -> BitVec {
		BitVec { vec_: Vec::new() }
	}
	pub fn from_u5_vec(u5_v: &[u5]) -> BitVec {
		let mut vec = BitVec { vec_: Vec::new() };
		for x in u5_v {
			let mut x_u8 = x.to_u8();
			let mut b5 = [0u8; 5];
			for i in 0..5 {
				b5[4 - i] = x_u8 % 2;
				x_u8 = x_u8 / 2;
			}
			for x in b5.iter() {
				vec.vec_.push(*x);
			}
		}
		return vec;
	}

	pub fn attach_u8_vec(&mut self, u8_v: &[u8]) {
		for x in u8_v {
			let mut b8 = [0u8; 8];
			let mut tmp = x.clone();
			for i in 0..8 {
				b8[7 - i] = tmp % 2;
				tmp = tmp / 2;
			}
			for b in b8.iter() {
				self.vec_.push(*b);
			}
		}
	}

	pub fn to_u5_vec(&mut self) -> Vec<u8> {
		// Add additional 0 to bit vector such that the total lenght is multiplier of 5.
		let mut u5_vec = Vec::new();
		if self.vec_.len() % 5 != 0 {
			for i in 0..(5 - (self.vec_.len() % 5)) {
				self.vec_.push(0u8);
			}
		}

		for i in 0..self.vec_.len() / 5 {
			let mut num_u8 = 0;
			for j in 0..5 {
				num_u8 += 2_u8.pow(j as u32) * self.vec_[i * 5 + 4 - j];
			}
			u5_vec.push(num_u8);
		}
		return u5_vec;
	}

	pub fn to_u8(&self, start: usize, length: usize) -> Vec<u8> {
		assert!(self.vec_.len() > start + length * 8);
		let mut u8_vec = Vec::with_capacity(length);
		for i in 0..length {
			let mut num_u8 = 0;
			for j in 0..8 {
				num_u8 += 2_u8.pow(j as u32) * self.vec_[i * 8 + 7 - j];
			}
			u8_vec.push(num_u8);
		}
		return u8_vec;
	}
}

pub fn decode_payment_address(address: &str) -> Option<SaplingPaymentAddress> {
	let b32_parsed = match address.parse::<Bech32>() {
		Ok(b) => b,
		Err(_) => return None,
	};
	let u5_vec = b32_parsed.data();
	if u5_vec.len() != (PAYMENT_ADDRESS_LENGTH * 8 - 1 + 5) / 5 {
		return None;
	}
	let bit_vec = BitVec::from_u5_vec(u5_vec);
	let u8_vec = bit_vec.to_u8(0, PAYMENT_ADDRESS_LENGTH);

	let mut diversifier = [0u8; 11];
	diversifier.copy_from_slice(&u8_vec[0..11]);
	let pk_d = &u8_vec[11..PAYMENT_ADDRESS_LENGTH];
	let pk_d = match edwards::Point::<Bls12, Unknown>::read(&mut pk_d.as_ref(), &JUBJUB) {
		Ok(p) => p,
		Err(_) => return None,
	};
	let pk_d = match pk_d.as_prime_order(&JUBJUB) {
		Some(pk_d) => pk_d,
		None => return None,
	};
	let payment_address = SaplingPaymentAddress {
		diversifier: sapling_crypto::primitives::Diversifier(diversifier),
		pk_d: pk_d,
	};
	Some(payment_address)
}

pub fn encode_payment_address(address: &SaplingPaymentAddress) -> String {
	let mut pk_d_vec = [0u8; 32];
	address.pk_d.write(&mut pk_d_vec[0..32]);
	let mut bit_vec = BitVec::new();
	bit_vec.attach_u8_vec(&address.diversifier.0);
	bit_vec.attach_u8_vec(&pk_d_vec);
	let b = Bech32::new_check_data(ADDR_PREFIX.into(), bit_vec.to_u5_vec());
	assert!(b.is_ok());
	let encoded = b.unwrap().to_string();
	return encoded;
}

pub type TxDestination = H160;

pub fn decode_destination(address: &str) -> Option<TxDestination> {
	match TxDestination::from_str(address.trim_start_matches("0x")) {
		Ok(add) => Some(add),
		Err(_) => None,
	}
}

pub fn decode_transparent_destination(address: &str) -> bool {
	match decode_destination(address) {
		Some(_) => true,
		None => false,
	}
}

pub fn decode_outputs(
	aoutputs_str: &str,
) -> (Vec<SendManyRecipient>, Vec<SendManyRecipient>, U256) {
	let v: Vec<Value> = serde_json::from_str(aoutputs_str).unwrap();
	let mut total = U256::from(0);
	let mut t_recipients = Vec::new();
	let mut z_recipients = Vec::new();
	for r in v {
		let recipient = (
			r["address"].as_str().unwrap().to_string(),
			U256::from(r["amount"].as_u64().unwrap()),
			"".to_string(),
		);
		total += recipient.1;
		if decode_transparent_destination(&recipient.0) {
			t_recipients.push(recipient);
		} else {
			z_recipients.push(recipient);
		}
	}
	(z_recipients, t_recipients, total)
}

pub struct KeyStore {
	map_incoming_view_keys: HashMap<SaplingPaymentAddress, SaplingIncomingViewingKey>,
	map_full_viewing_keys: HashMap<SaplingIncomingViewingKey, SaplingFullViewingKey>,
	file_path: String,
	file_name_prefix: String,
}

impl KeyStore {
	pub fn get_map_full_viewing_keys(
		&self,
	) -> &HashMap<SaplingIncomingViewingKey, SaplingFullViewingKey> {
		&self.map_full_viewing_keys
	}

	// This function return the viewing keys not included in the handled_address_option.
	pub fn get_unhandled_viewing_keys(
		&self,
		handled_addresses_option: &Option<HashSet<String>>,
	) -> HashMap<SaplingIncomingViewingKey, SaplingFullViewingKey> {
		let mut handled_incoming_keys = HashSet::new();
		if let Some(handled_addresses) = handled_addresses_option {
			for address in handled_addresses.iter() {
				if let Some(payment_address) = decode_payment_address(address) {
					if let Some(incoming_key) = self.map_incoming_view_keys.get(&payment_address) {
						handled_incoming_keys.insert(incoming_key);
					}
				}
			}
		}

		let mut unhandled_viewing_keys = HashMap::new();
		for (incoming_key, full_key) in self.map_full_viewing_keys.iter() {
			if !handled_incoming_keys.contains(incoming_key) {
				unhandled_viewing_keys.insert(incoming_key.clone(), full_key.clone());
			}
		}
		unhandled_viewing_keys
	}

	pub fn decrypt_key_file(
		&self,
		address: &str,
		pass: String,
	) -> Option<SaplingExtendedSpendingKey> {
        let prefix = &self.file_name_prefix;
		let file_name = format!("{}/{}{}", self.file_path,prefix, address);

		let mut file = File::open(file_name);
		if file.is_err() {
			return None;
		}
		let key_file = OrigoKeyFile::load(&file.unwrap()).unwrap();
		let origo_account = OrigoAccount::from_file(key_file, None);

		let origo_account = origo_account.unwrap();

		if let Ok(secret) = origo_account.crypto.decrypt(&Password::from(pass)) {
			let mut rdr = Cursor::new(secret);
			let espk = SaplingExtendedSpendingKey::read(&mut rdr);
			return espk.ok();
		} else {
			return None;
		}
	}

	pub fn encrypt_key_file_and_add_viewing_key(
		&mut self,
		espk: &SaplingExtendedSpendingKey,
		pass: String,
	) -> io::Result<()> {
		let pass = Password::from(pass);

		let xfvk = SaplingExtendedFullViewingKey::from(espk);
		let (_, address) = xfvk.default_address().unwrap();
		let address_str = encode_payment_address(&address);

		let origo_account = OrigoAccount::create(address_str.clone(), &xfvk, espk, &pass, *KEY_ITERATIONS);
		let origo_key_file: OrigoKeyFile = origo_account.unwrap().into();

        let file_name = format!("{}/{}{}", self.file_path, self.file_name_prefix, address_str);
		let mut file = File::create(file_name)?;
		origo_key_file.write(&mut file);

		self.add_full_viewing_key(xfvk.fvk, address);
		Ok(())
	}

	//It should only used in test
	pub fn new() -> Self {
		KeyStore {
			map_incoming_view_keys: HashMap::new(),
			map_full_viewing_keys: HashMap::new(),
			file_path : "./".to_string(),
			file_name_prefix: "wallet_".to_string(),
		}
	}

	pub fn new_with_file_prefix(file_name_prefix: &str, file_path: &str) -> Self {
		KeyStore {
			map_incoming_view_keys: HashMap::new(),
			map_full_viewing_keys: HashMap::new(),
			file_path: file_path.to_string(),
			file_name_prefix: file_name_prefix.to_string(),
		}
	}

	pub fn decode_z_destination(
		&self,
		address: &str,
		pass: String,
	) -> (
		Option<SaplingPaymentAddress>,
		Option<SaplingExtendedSpendingKey>,
	) {
		let payment_address = decode_payment_address(address);

		match decode_payment_address(address) {
			Some(a) => (Some(a), self.decrypt_key_file(address, pass)),
			None => (None, None),
		}
	}


	pub fn get_incoming_viewing_key(
		&self,
		address: &SaplingPaymentAddress,
	) -> Option<SaplingIncomingViewingKey> {
		match self.map_incoming_view_keys.get(address) {
			Some(&v) => Some(v),
			None => None,
		}
	}

	pub fn get_full_viewing_key(
		&self,
		ivk: &SaplingIncomingViewingKey,
	) -> Option<SaplingFullViewingKey> {
		match self.map_full_viewing_keys.get(ivk) {
			Some(&v) => Some(v),
			None => None,
		}
	}

	pub fn add_full_viewing_key(
		&mut self,
		fvk: SaplingFullViewingKey,
		address: SaplingPaymentAddress,
	) -> bool {
		let ivk = fvk.vk.ivk();
		self.map_full_viewing_keys.insert(ivk, fvk);
		return self.add_incoming_viewing_key(ivk, address);
	}

	pub fn get_sapling_payment_addresses(&self) -> Vec<SaplingPaymentAddress> {
		let mut set = Vec::new();
		for (k, _) in &self.map_incoming_view_keys {
			set.push(k.clone());
		}
		set
	}

	fn add_incoming_viewing_key(
		&mut self,
		ivk: SaplingIncomingViewingKey,
		address: SaplingPaymentAddress,
	) -> bool {
		self.map_incoming_view_keys.insert(address, ivk);
		true
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{OsRng, Rand};

	#[test]
	fn test_decode_payment_address() {
		let address =
			"ogo14j53eenhdjp85dlfctsttmtgav8sqkkttsl6qxvpmn74jk7edsyzp08r550dzu96hu9gwtzk9w2";
		let option = decode_payment_address(address);
		match option {
			Some(p) => assert_eq!(
				address,
				encode_payment_address(&p),
				"encoded address doesn't equal."
			),
			None => panic!("Can't decode address"),
		}
	}

	#[test]
	fn test_decode_outputs() {
		let output = r#"[{"address": "ztfaW34Gj9FrnGUEf833ywDVL62NWXBM81u6EQnM6VR45eYnXhwztecW1SjxA7JrmAXKJhxhj3vDNEpVCQoSvVoSpmbhtjf" ,"amount": 5},
                         {"address": "0x793ea9692Ada1900fBd0B80FFFEc6E431fe8b391" ,"amount": 6}]"#;
		let k = KeyStore::new();
		let (zaddr_recipients, taddr_recipients, total_amount) = decode_outputs(output);
		assert_eq!(total_amount, U256::from(11));
		assert_eq!(zaddr_recipients.len(), 1);
		assert_eq!(zaddr_recipients[0], ("ztfaW34Gj9FrnGUEf833ywDVL62NWXBM81u6EQnM6VR45eYnXhwztecW1SjxA7JrmAXKJhxhj3vDNEpVCQoSvVoSpmbhtjf".to_string(),
                                        U256::from(5), "".to_string()));
		assert_eq!(zaddr_recipients.len(), 1);
		assert_eq!(taddr_recipients.len(), 1);
		assert_eq!(
			taddr_recipients[0],
			(
				"0x793ea9692Ada1900fBd0B80FFFEc6E431fe8b391".to_string(),
				U256::from(6),
				"".to_string()
			)
		);
	}

	#[test]
	fn test_key_store_basic() {
		let extsk = SaplingExtendedSpendingKey::master(&[]);
		let mut key_store = KeyStore::new();
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;
		let old_spending_key = extsk.clone();
		let old_address = to.clone();

		key_store.add_full_viewing_key(extfvk.fvk, to);
		assert_eq!(key_store.map_full_viewing_keys.len(), 1);
		assert_eq!(key_store.map_incoming_view_keys.len(), 1);

		let addresses = key_store.get_sapling_payment_addresses();
		assert_eq!(addresses.len(), 1);
		assert_eq!(addresses[0], old_address);
	}

	#[test]
	fn test_get_unhandled_viewing_keys() {
		let extsk = SaplingExtendedSpendingKey::master(&[]);
		let mut key_store = KeyStore::new();
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let to = extfvk.default_address().unwrap().1;
		let old_address = to.clone();
		key_store.add_full_viewing_key(extfvk.fvk, to);

		let seed = [0u8; 32];
		let extsk = SaplingExtendedSpendingKey::master(&seed);
		let extfvk = SaplingExtendedFullViewingKey::from(&extsk);
		let ovk = extfvk.fvk.ovk;
		let new_address_vk = extfvk.fvk.vk.ivk();
		let to = extfvk.default_address().unwrap().1;
		key_store.add_full_viewing_key(extfvk.fvk, to);

		let filter_viewing_keys = key_store.get_unhandled_viewing_keys(&None);
		assert_eq!(filter_viewing_keys.len(), 2);
		let mut handled_addresses = HashSet::new();
		handled_addresses.insert(encode_payment_address(&old_address));
		let filter_viewing_keys = key_store.get_unhandled_viewing_keys(&Some(handled_addresses));
		assert_eq!(filter_viewing_keys.len(), 1);
		assert!(filter_viewing_keys.contains_key(&new_address_vk));
	}
}
