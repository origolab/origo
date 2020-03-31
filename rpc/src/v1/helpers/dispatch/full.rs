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

use std::sync::Arc;

use dir::Directories;
use ethcore::client::BlockChainClient;
use ethcore::miner::{self, MinerService};
use ethcore::{SendMany, SendManyInputs, Wallet, DUMMY_WALLET_PASS};
use ethereum_types::{Address, H256, U256};
use parking_lot::Mutex;
use types::transaction::{PendingTransaction, SignedTransaction, MAX_VALUE_ALLOWED};
use jsonrpc_core::futures::{future, Future, IntoFuture};
use jsonrpc_core::{BoxFuture, Result};
use v1::helpers::{errors, nonce, FilledTransactionRequest, TransactionRequest};
use v1::types::RichRawTransaction as RpcRichRawTransaction;

use super::prospective_signer::ProspectiveSigner;
use super::{default_gas_price, Accounts, Dispatcher, PostSign, SignWith};
use v1::helpers::errors::transaction;

/// A dispatcher which uses references to a client and miner in order to sign
/// requests locally.

pub trait OrigoChainID {
	fn get_chain_id(&self) -> Option<u64>;
}

#[derive(Debug)]
pub struct FullDispatcher<C, M> {
	client: Arc<C>,
	miner: Arc<M>,
	nonces: Arc<Mutex<nonce::Reservations>>,
	gas_price_percentile: usize,
}

impl<C: miner::BlockChainClient + BlockChainClient, M: MinerService> OrigoChainID
	for FullDispatcher<C, M>
{
	fn get_chain_id(&self) -> Option<u64> {
		self.client.signing_chain_id()
	}
}

impl<C, M> FullDispatcher<C, M> {
	/// Create a `FullDispatcher` from Arc references to a client and miner.
	pub fn new(
		client: Arc<C>,
		miner: Arc<M>,
		nonces: Arc<Mutex<nonce::Reservations>>,
		gas_price_percentile: usize,
	) -> Self {
		FullDispatcher {
			client,
			miner,
			nonces,
			gas_price_percentile,
		}
	}
}

impl<C, M> Clone for FullDispatcher<C, M> {
	fn clone(&self) -> Self {
		FullDispatcher {
			client: self.client.clone(),
			miner: self.miner.clone(),
			nonces: self.nonces.clone(),
			gas_price_percentile: self.gas_price_percentile,
		}
	}
}

impl<C: miner::BlockChainClient, M: MinerService> FullDispatcher<C, M> {
	fn state_nonce(&self, from: &Address) -> U256 {
		self.miner.next_nonce(&*self.client, from)
	}

	/// Post transaction to the network.
	///
	/// If transaction is trusted we are more likely to assume it is coming from a local account.
	pub fn dispatch_transaction(
		client: &C,
		miner: &M,
		signed_transaction: PendingTransaction,
		trusted: bool,
	) -> Result<H256> {
		if signed_transaction.is_private() {
			signed_transaction.verify_private_tx_basic().map_err(errors::transaction)?;
		}
		let hash = signed_transaction.transaction.hash();

		// use `import_claimed_local_transaction` so we can decide (based on config flags) if we want to treat
		// it as local or not. Nodes with public RPC interfaces will want these transactions to be treated like
		// external transactions.
		miner
			.import_claimed_local_transaction(client, signed_transaction, trusted)
			.map_err(errors::transaction)
			.map(|_| hash)
	}
}

impl<C: miner::BlockChainClient + BlockChainClient, M: MinerService> Dispatcher
	for FullDispatcher<C, M>
{
	fn fill_optional_fields(
		&self,
		request: TransactionRequest,
		default_sender: Address,
		force_nonce: bool,
	) -> BoxFuture<FilledTransactionRequest> {
		let request = request;
		let from = request.from.unwrap_or(default_sender);
		let nonce = if force_nonce {
			request.nonce.or_else(|| Some(self.state_nonce(&from)))
		} else {
			request.nonce
		};
		let mut private = None;
		let gas_price = request.gas_price.unwrap_or_else(|| {
				default_gas_price(&*self.client, &*self.miner, self.gas_price_percentile)
		});
		let gas = request.gas.unwrap_or_else(|| self.miner.sensible_gas_limit());
		let data = request.data.unwrap_or_else(Vec::new);
		if let Some(shield_amounts) =  request.shield_amounts {
			// We don't really need wallet here, create a dummy one.
			let mut walelt_dir = &Directories::default().wallet[..];
			// TODO(xin): remove the #[cfg(test)]. We should allow test to set its own wallet_dir.
			#[cfg(test)] {
				walelt_dir = "./";
			}
			let wallet = Arc::new(std::sync::RwLock::new(Wallet::new_from_file("dummy_wallet_", walelt_dir)));
			let mut sendmany = SendMany::new(wallet.clone());
			let mut shield_to = Vec::new();
			for amount in shield_amounts.iter() {
				if amount.amount > MAX_VALUE_ALLOWED {
					return Box::new(future::err(errors::private_tx_error(String::from("Amount sent is bigger than (2^63-1)*(10^9)"))));
				}
				let memo = match amount.memo.clone() {
					Some(memo) => memo,
					None => "".to_string(),
				};
				shield_to.push((amount.address.clone(), amount.amount.clone(), memo));
			}
			let mut value_from_public = U256::from(0);
			if let Some(v) = request.value {
				value_from_public = v;
			}
			let addresses = wallet.read().unwrap().list_addresses();
			// Generate a new address to send shield transaction if wallet is empty.
			let from:String = if !addresses.is_empty() {
				addresses[0].clone()
			} else {
				wallet.write().unwrap().create_new_private_address(None)
			};

			let chain_id = match self.client.signing_chain_id() {
				Some(v) => v,
				None => 0,
			};
			let nonce = match nonce {
				Some(v) => v,
				None => U256::from(0),
			};
			let inputs = SendManyInputs {
				value_from_public,
				from,
				shield_to,
				to: Vec::new(),
				min_conf: 0,
				gas_price,
				nonce,
				gas,
				data: data.clone(),
				chain_id,
			};
			//TODO, None("") for password?
			//Change password to correspond funciton create_new_private_address's impl
			match sendmany.pre_send_many(&inputs, DUMMY_WALLET_PASS.to_string()) {
				Ok(tx) => {
					private = tx.private;
				},
				Err(e) => {
					return Box::new(future::err(errors::private_tx_error(e.0.into())));
				}
			}
		}

		return Box::new(future::ok(FilledTransactionRequest {
			from,
			used_default_from: request.from.is_none(),
			to: request.to,
			nonce,
			gas_price,
			gas,
			value: request.value.unwrap_or_else(|| 0.into()),
			data,
			condition: request.condition,
			private,
		}))
	}

	fn sign<P>(
		&self,
		filled: FilledTransactionRequest,
		signer: &Arc<Accounts>,
		password: SignWith,
		post_sign: P,
	) -> BoxFuture<P::Item>
	where
		P: PostSign + 'static,
		<P::Out as IntoFuture>::Future: Send,
	{
		let chain_id = self.client.signing_chain_id();

		if let Some(nonce) = filled.nonce {
			let future = signer
				.sign_transaction(filled, chain_id, nonce, password)
				.into_future()
				.and_then(move |signed| post_sign.execute(signed));
			Box::new(future)
		} else {
			let state = self.state_nonce(&filled.from);
			let reserved = self.nonces.lock().reserve(filled.from, state);

			Box::new(ProspectiveSigner::new(
				signer.clone(),
				filled,
				chain_id,
				reserved,
				password,
				post_sign,
			))
		}
	}

	fn enrich(&self, signed_transaction: SignedTransaction) -> RpcRichRawTransaction {
		RpcRichRawTransaction::from_signed(signed_transaction)
	}

	fn dispatch_transaction(&self, signed_transaction: PendingTransaction) -> Result<H256> {
		Self::dispatch_transaction(&*self.client, &*self.miner, signed_transaction, true)
	}
}
