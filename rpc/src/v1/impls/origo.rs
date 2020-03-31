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

//! Origo Accounts-related rpc implementation.
use std::collections::hash_set::HashSet;
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::Arc;

use ethcore::{
	decode_payment_address, decode_transparent_destination, encode_payment_address, SendMany,
	SendManyInputs, Wallet,
};

use accounts::AccountProvider;
use ethereum_types::{clean_0x, Address, H256, U256, U64};
use jsonrpc_core::types::Error as JsonError;
use jsonrpc_core::types::ErrorCode;
use jsonrpc_core::Result;
use std::sync::RwLock;
use types::transaction::{*, MAX_VALUE_ALLOWED};
use v1::helpers::dispatch::Dispatcher;
use v1::helpers::errors;
use v1::helpers::dispatch::full::OrigoChainID;
use v1::traits::OrigoAccountsInfo;
use v1::types::{AmountRequest, UnspentNote};

/// Account management (personal) rpc implementation.
pub struct OrigoAccountsClient<D: Dispatcher + OrigoChainID> {
	accounts: Arc<AccountProvider>,
	dispatcher: D,
	wallet: Arc<RwLock<Wallet>>,
}

impl<D: Dispatcher + OrigoChainID + 'static> OrigoAccountsClient<D> {
	/// Creates new PersonalClient
	pub fn new(store: &Arc<AccountProvider>, dispatcher: D, wallet: &Arc<RwLock<Wallet>>) -> Self {
		OrigoAccountsClient {
			accounts: store.clone(),
			dispatcher,
			wallet: wallet.clone(),
		}
	}
}

impl<D: Dispatcher + OrigoChainID + 'static > OrigoAccountsInfo for OrigoAccountsClient<D> {
	// output: The new shielded address
	// (e.g. zcU1Cd6zYyZCd2VJF8yKgmzjxdiiU1rgTTjEwoN1CGUWCziPkUTXUjXmX7TMqdMNsTfuiGN1jQoVN4kGxUR4sAPN4XZ7pxb)
	fn get_new_address(&self, password: String) -> Result<String> {
		let address = self.wallet.write().unwrap().create_new_private_address(Some(password));
		Ok(address)
	}


	fn new_address_from_seed(&self, seed: H256, password: String) -> Result<String> {
		Ok(self.wallet.write().unwrap().add_address_from_seed(
			(*seed).try_into().expect("Length should equal."), password).0)
	}

	fn addresses(&self) -> Result<Vec<String>> {
		Ok(self.wallet.read().unwrap().list_addresses())
	}

	/// address: The selected address. It may be a transparent or private address.
	/// minconf: optional, default = 1, Only include transactions confirmed at least this many times
	/// Output: The total amount in ZEC received for this address
	fn get_balance(&self, address: String, minconf: Option<u32>) -> Result<U256> {
		//let result = U256::from(10);
		//Ok(result)
		let wallet_read = self.wallet.read().unwrap();
		let entries = wallet_read.get_filtered_address_notes(&address);
		let mut balance = 0;
		for entry in entries.iter() {
			balance += entry.note.value
		}
		Ok(U256::from(balance) * CONVERSION_FACTOR)
	}

	/// addresses: A json array of zaddrs to filter on. Duplicate addresses not allowed.
	/// minconf: The minimum confirmations to filter, default=1
	/// maxconf: The maximum confirmations to filter, default=9999999
	/// include_watch_only: whether include watchonly addresses
	fn list_unspent(
		&self,
		address: String,
		minconf: Option<u32>,
		maxconf: Option<u32>,
		include_watch_only: Option<bool>,
	) -> Result<Vec<UnspentNote>> {
		let wallet_read = self.wallet.read().unwrap();
		let zaddrs = wallet_read.key_store.get_sapling_payment_addresses();
		let notes = wallet_read.get_filtered_address_notes(&address);
		let mut result: Vec<UnspentNote> = Vec::new();

		for entry in notes.iter() {
			let memo = match entry.memo.to_utf8() {
				Some(Ok(memo)) => memo,
				_ => "Invalid memo.".to_string(),
			};
			let note_desc = UnspentNote {
				txid: entry.hash.to_string(),
				outindex: From::from(entry.index as u64),
				confirmations: U64::zero(),
				address: encode_payment_address(&entry.address),
				amount: U256::from(entry.note.value) * CONVERSION_FACTOR,
				spendable: true,
				memo,
				change: false,
				jsindex: U64::zero(),
				jsoutindex: U64::zero(),
			};
			result.push(note_desc);
		}
		Ok(result)
	}

	/// from: The taddr or zaddr to send the funds from
	/// amounts: An array of json objects representing the amounts to send.
	/// [{
	/// 	"address":address  (string, required) The address is a taddr or zaddr
	///		"amount":amount    (numeric, required) The numeric amount in ZEC is the value
	/// 	"memo":memo        (string, optional) If the address is a zaddr,
	/// 					    raw data represented in hexadecimal string format
	/// }, ... ]
	/// password: The password to unlock from address.
	/// gas_price: optional, default=1, The gas price of the transaction.
	/// gas: optional, default=21000, The gas limit of the transaction.
	/// min_conf: optional, default=1, Only use funds confirmed at least this many times.
	/// Output:
	/// 	operationid: An operationid to pass to z_getoperationstatus to get the result of the operation.
	fn send_many(
		&self,
		from: String,
		amounts: Vec<AmountRequest>,
		password: String,
		gas: Option<U256>,
		gas_price: Option<U256>,
		min_conf: Option<u32>
	) -> Result<H256> {
		// Process inputs.
		let min_conf = match min_conf {
			Some(min_conf) => min_conf,
			None => 0,
		};
		let gas = match gas {
			Some(gas) => gas,
			None => U256::from(21000),
		};
		let gas_price = match gas_price {
			Some(gas_price) => gas_price,
			None => U256::from(1000000),
		};
		let mut shield_to = Vec::new();
		let mut to = Vec::new();

		for amount in amounts.iter() {
			if amount.amount > MAX_VALUE_ALLOWED {
				return Err(errors::private_tx_error(String::from("Amount sent is bigger than (2^63-1)*(10^9)")));
			}
			let memo = match amount.memo.clone() {
				Some(memo) => memo,
				None => "".to_string(),
			};
			if let Some(_) = decode_payment_address(&amount.address) {
				shield_to.push((amount.address.clone(), amount.amount.clone(), memo));
			} else if decode_transparent_destination(&amount.address) {
				println!("public Address {:?}", amount.address);
				to.push((amount.address.clone(), amount.amount.clone(), memo));
			} else {
				return Err(errors::invalid_params("to", &amount.address));
			}
		}
		// Check amounts are valid.
		if shield_to.len() > 0 && to.len() > 0 {
			return Err(errors::invalid_params("amounts",
											  "Both transparent and private address appeared in amounts."));
		} else if shield_to.is_empty() && to.is_empty() {
			return Err(errors::invalid_params("amounts",
											  "No valid address appears in amounts."));
		}
		let chain_id = match self.dispatcher.get_chain_id() {
			Some(v) => v,
			None => 0,
		};
		let inputs = SendManyInputs {
			from,
			value_from_public: U256::from(0),
			shield_to,
			to,
			min_conf,
			gas_price,
			nonce: U256::from(0),
			gas,
			data: vec![],
			chain_id,
		};
		let mut sendmany = SendMany::new(self.wallet.clone());
		match sendmany.pre_send_many(&inputs, password) {
			Ok(tx) => {
				let dispatcher = self.dispatcher.clone();
				return dispatcher
					.dispatch_transaction(PendingTransaction::new(tx.sign_for_private(chain_id), None));
			}
			Err(e) => {
				return Err(errors::private_tx_error(e.0.into()));
			}
		}
	}
}
