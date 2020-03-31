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
use std::str::FromStr;
use std::fs;

use bytes::ToPretty;
use accounts::AccountProvider;
use ethereum_types::{Address, H520, U256};
use ethcore::client::TestBlockChainClient;
use ethcore::Wallet;
use jsonrpc_core::IoHandler;
use parking_lot::Mutex;
use types::transaction::{Action, Transaction, PrivateTransaction};
use parity_runtime::Runtime;
use hash::keccak;

use v1::{OrigoAccountsClient, OrigoAccountsInfo, Metadata, PersonalClient, Personal};
use v1::helpers::{nonce, eip191};
use v1::helpers::dispatch::{eth_data_hash, FullDispatcher};
use v1::tests::helpers::TestMinerService;
use v1::types::{EIP191Version, PresignedTransaction};
use rustc_hex::ToHex;
use serde_json::to_value;
use serde_json;
use ethkey::Secret;

struct OrigoTester {
	_runtime: Runtime,
	accounts: Arc<AccountProvider>,
	io: IoHandler<Metadata>,
	miner: Arc<TestMinerService>,
	/// zcash wallet
	pt_wallet: Arc<std::sync::RwLock<Wallet>>,
}

fn blockchain_client() -> Arc<TestBlockChainClient> {
	let client = TestBlockChainClient::new();
	Arc::new(client)
}

fn accounts_provider() -> Arc<AccountProvider> {
	Arc::new(AccountProvider::transient_provider())
}

fn miner_service() -> Arc<TestMinerService> {
	Arc::new(TestMinerService::default())
}

struct Config {
	pub allow_experimental_rpcs: bool,
	pub wallet_file_path: &'static str,
	pub wallet_file_prefix: &'static str,
}

#[derive(Deserialize, Debug)]
struct Response {
	pub jsonrpc: String,
	pub result: String,
	pub id: u8,
}

#[derive(Deserialize, Debug)]
struct SequenceResponse {
	pub jsonrpc: String,
	pub result: Vec<String>,
	pub id: u8,
}

fn setup_with(c: &Config) -> OrigoTester {
	let runtime = Runtime::with_thread_count(1);
	let accounts = accounts_provider();
	let client = blockchain_client();
	let miner = miner_service();
	let reservations = Arc::new(Mutex::new(nonce::Reservations::new(runtime.executor())));
	let pt_wallet = Arc::new(std::sync::RwLock::new(Wallet::new_from_file(c.wallet_file_prefix, c.wallet_file_path)));

	let dispatcher = FullDispatcher::new(client, miner.clone(), reservations.clone(), 50);
	let origo = OrigoAccountsClient::new(&accounts, dispatcher, &pt_wallet);

	let client = blockchain_client();
	let dispatcher = FullDispatcher::new(client, miner.clone(), reservations, 50);
	let personal = PersonalClient::new(&accounts, dispatcher, false, c.allow_experimental_rpcs);

	let mut io = IoHandler::default();
	io.extend_with(origo.to_delegate());
	io.extend_with(personal.to_delegate());

	let tester = OrigoTester {
		_runtime: runtime,
		accounts: accounts,
		io: io,
		miner: miner,
		pt_wallet: pt_wallet,
	};

	tester
}

fn cleanup_with(c: &Config) {
	fs::remove_file(c.wallet_file_path);
}

#[test]
fn get_new_address() {
	let config = Config {
		allow_experimental_rpcs : true,
		wallet_file_path: "./",
		wallet_file_prefix: "test_wallet", 
	};
	let tester = setup_with(&config);

	let request = r#"{"jsonrpc": "2.0", "method": "origo_getNewAddress", "params": [""], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let response: Response = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	let first_address = response.result;

	let request = r#"{"jsonrpc": "2.0", "method": "origo_listAddresses", "params": [], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let address_list_str = res.expect("response should not empty");
	assert!(address_list_str.contains(first_address.as_str()));

	cleanup_with(&config);
}

//#[test]
fn new_address_from_seed() {
	let config = Config {
		allow_experimental_rpcs : true,
		wallet_file_path: "./",
		wallet_file_prefix: "test_wallet", 
	};
	let tester = setup_with(&config);

	let request = r#"{"jsonrpc": "2.0", "method": "origo_newAddressFromSeed","params": ["0x0000000000000000000000000000000000000000000000000000000000000000", ""], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let response: Response = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	let address = response.result;
	assert_eq!(address, "ogo180m058urhazk8j98zvz9fsq5zd0vd9dpsc8c6ednwd2xkc3l8z9thmxsezepzx4aascp6nrlkd6");

	cleanup_with(&config);
}

#[test]
fn get_balance() {
	let config = Config {
		allow_experimental_rpcs : true,
		wallet_file_path: "./",
		wallet_file_prefix: "test_wallet", 
	};
	let tester = setup_with(&config);

	let first_address = "ogo180m058urhazk8j98zvz9fsq5zd0vd9dpsc8c6ednwd2xkc3l8z9thmxsezepzx4aascp6nrlkd6";
	let request = r#"{"jsonrpc": "2.0", "method": "origo_getBalance", "params": [""#.to_owned() + format!("{}", first_address).as_ref() + r#""], "id": 1}"#;
	let res = tester.io.handle_request_sync(request.as_str());
	let response: Response = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	assert_eq!(response.result, "0x0");

	cleanup_with(&config);
}

#[test]
fn list_unspent() {
	let config = Config {
		allow_experimental_rpcs : true,
		wallet_file_path: "./",
		wallet_file_prefix: "test_wallet", 
	};
	let tester = setup_with(&config);

	let first_address = "ogo180m058urhazk8j98zvz9fsq5zd0vd9dpsc8c6ednwd2xkc3l8z9thmxsezepzx4aascp6nrlkd6";
	let request = r#"{"jsonrpc": "2.0", "method": "origo_listUnspent", "params": [""#.to_owned() + format!("{}", first_address).as_ref() + r#""], "id": 1}"#;
	let res = tester.io.handle_request_sync(request.as_str());
	let response: SequenceResponse = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	assert_eq!(response.result.len(), 0);

	cleanup_with(&config);
}

#[ignore]
#[test]
fn origo_get_new_address() {
	let config = Config {
		allow_experimental_rpcs : true,
		wallet_file_path: "./",
		wallet_file_prefix: "test_wallet", 
	};
	let tester = setup_with(&config);

	// Create public address for user A.
	let first_address_public = tester.accounts.new_account(&"password123".into()).unwrap();
	tester.accounts.unlock_account_temporarily(first_address_public, "password123".into()).unwrap();

	// Create private address for first user A.
	let request = r#"{"jsonrpc": "2.0", "method": "origo_getNewAddress", "params": [], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let response: Response = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	let first_address = response.result;

	// Create private address for second user B.
	let request = r#"{"jsonrpc": "2.0", "method": "origo_getNewAddress", "params": [], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let response: Response = serde_json::from_str(res.expect("response should not empty").as_str()).unwrap();
	let second_address = response.result;

	// List all the private addresses, including A and B.
	let request = r#"{"jsonrpc": "2.0", "method": "origo_listAddresses", "params": [], "id": 1}"#;
	let res = tester.io.handle_request_sync(request);
	let address_list_str = res.expect("response should not empty");
	assert!(address_list_str.contains(first_address.as_str()));
	assert!(address_list_str.contains(second_address.as_str()));

	// Submit the public_to_private transaction.
	let request = r#"{
				 "jsonrpc": "2.0",
				 "method": "personal_sendShieldTransaction",
				 "params": [{
					"from": ""#.to_owned() + format!("0x{:x}", first_address_public).as_ref() + r#"",
					"gas": "0x76c0",
					"gasPrice": "0x9184e72a000",
					"value": "0x20",
					"shieldAmounts": [{"address": ""# + format!("{}", first_address).as_ref() + r#"",
									  "amount": 32,
									  "memo":"test"
									}]
				 }, "password123"],
				 "id": 1
				 }"#;

	let res = tester.io.handle_request_sync(request.as_str());
	assert!(res.expect("response should not empty").starts_with(r#"{"jsonrpc":"2.0","result":""#));

	// List the unspent transaction for user A private address.
	let request = r#"{"jsonrpc": "2.0", "method": "origo_listUnspent", "params": [""#.to_owned() + format!("{}", first_address).as_ref() + r#""], "id": 1}"#;
	let res = tester.io.handle_request_sync(request.as_str());
	// println!("res:{}", res.);
	assert!(res.expect("response should not empty").starts_with(r#"{"jsonrpc":"2.0","result":""#));

	cleanup_with(&config);
}
