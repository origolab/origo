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

use ethereum_types::{U256, H256, Address};
use bytes::Bytes;

use v1::types::{Origin, TransactionCondition, AmountRequest as Request};
use types::transaction;

/// Transaction request coming from RPC
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct TransactionRequest {
	/// Sender
	pub from: Option<Address>,
	/// Recipient
	pub to: Option<Address>,
	/// Gas Price
	pub gas_price: Option<U256>,
	/// Gas
	pub gas: Option<U256>,
	/// Value of transaction in wei
	pub value: Option<U256>,
	/// Additional data sent with transaction
	pub data: Option<Bytes>,
	/// Transaction's nonce
	pub nonce: Option<U256>,
	/// Delay until this condition is met.
	pub condition: Option<TransactionCondition>,
	/// shield amounts in shield transaction
	pub shield_amounts: Option<Vec<AmountRequest>>,
}

/// Transaction request coming from RPC with default values filled in.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct FilledTransactionRequest {
	/// Sender
	pub from: Address,
	/// Indicates if the sender was filled by default value.
	pub used_default_from: bool,
	/// Recipient
	pub to: Option<Address>,
	/// Gas Price
	pub gas_price: U256,
	/// Gas
	pub gas: U256,
	/// Value of transaction in wei
	pub value: U256,
	/// Additional data sent with transaction
	pub data: Bytes,
	/// Transaction's nonce
	pub nonce: Option<U256>,
	/// Delay until this condition is met.
	pub condition: Option<TransactionCondition>,
	/// For private transaction.
	pub private: Option<transaction::PrivateTransaction>,
}

impl Hash for FilledTransactionRequest {
	fn hash<H: Hasher>(&self, state: &mut H) {
		self.from.hash(state);
		self.used_default_from.hash(state);
		self.to.hash(state);
		self.gas_price.hash(state);
		self.gas.hash(state);
		self.value.hash(state);
		self.data.hash(state);
		self.nonce.hash(state);
		self.condition.hash(state);
	}
}

impl From<FilledTransactionRequest> for TransactionRequest {
	fn from(r: FilledTransactionRequest) -> Self {
		TransactionRequest {
			from: Some(r.from),
			to: r.to,
			gas_price: Some(r.gas_price),
			gas: Some(r.gas),
			value: Some(r.value),
			data: Some(r.data),
			nonce: r.nonce,
			condition: r.condition,
			shield_amounts: None,
		}
	}
}

/// Call request
#[derive(Debug, Default, PartialEq)]
pub struct CallRequest {
	/// From
	pub from: Option<Address>,
	/// To
	pub to: Option<Address>,
	/// Gas Price
	pub gas_price: Option<U256>,
	/// Gas
	pub gas: Option<U256>,
	/// Value
	pub value: Option<U256>,
	/// Data
	pub data: Option<Vec<u8>>,
	/// Nonce
	pub nonce: Option<U256>,
}

/// Amount request
#[derive(Debug, Default, Eq, PartialEq, Clone, Hash, Serialize, Deserialize)]
pub struct AmountRequest {
	/// The address is a taddr or zaddr
	pub address: String,
	/// The numeric amount in ZEC is the value
	pub amount: U256,
	/// If the address is a zaddr, raw data represented in hexadecimal string format
	pub memo: Option<String>,
}

impl From<Request> for AmountRequest {
	fn from(r: Request) -> Self {
		AmountRequest {
			address: r.address,
			amount: r.amount,
			memo: r.memo,
		}
	}
}

/// Confirmation object
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ConfirmationRequest {
	/// Id of this confirmation
	pub id: U256,
	/// Payload to confirm
	pub payload: ConfirmationPayload,
	/// Request origin
	pub origin: Origin,
}

/// Payload to confirm in Trusted Signer
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum ConfirmationPayload {
	/// Transaction
	SendTransaction(FilledTransactionRequest),
	/// Sign Transaction
	SignTransaction(FilledTransactionRequest),
	/// Sign a message with an Ethereum specific security prefix.
	EthSignMessage(Address, Bytes),
	/// Sign a message
	SignMessage(Address, H256),
	/// Decrypt request
	Decrypt(Address, Bytes),
}

impl ConfirmationPayload {
	pub fn sender(&self) -> Address {
		match *self {
			ConfirmationPayload::SendTransaction(ref request) => request.from,
			ConfirmationPayload::SignTransaction(ref request) => request.from,
			ConfirmationPayload::EthSignMessage(ref address, _) => *address,
			ConfirmationPayload::SignMessage(ref address, _) => *address,
			ConfirmationPayload::Decrypt(ref address, _) => *address,
		}
	}
}
