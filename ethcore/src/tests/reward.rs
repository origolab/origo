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

use block::*;
use blockchain::BlockChainDB;
use blockchain::Config;
use client::*;
use client::{BlockChainClient, Client, ClientConfig, BlockChainReset};
use engines::EthEngine;
use ethereum::{new_era_reward_test, new_medietas, new_reward_test};
use ethereum_types::H256;
use ethereum_types::{Address, U256};
use ethkey::KeyPair;
use hash::keccak;
use io::*;
use miner::Miner;
use std::ops::Shr;
use std::str::FromStr;
use std::sync::Arc;
use tempdir::TempDir;
use test_helpers;
use test_helpers::get_temp_state_db;
use trace::trace::Action::Reward;
use trace::{LocalizedTrace, RewardType};
use types::reward_config::RewardConfig;
use types::rewards::{EraRewardInfo, Rewards, MAX_ERA};
use types::solution::SOLUTION_SIZE;
use types::transaction::{Action, Transaction};
use types::view;
use types::views::BlockView;
use verification::queue::kind::blocks::Unverified;

fn db_total_reward_check(bcdb: &Arc<BlockChainDB>, total: U256) {
	let db_rewards = bcdb
		.key_value()
		.get(db::COL_EXTRA, b"Rewards")
		.expect("Low level database error when fetching 'era reward' . Some issue with disk?")
		.map(|v| rlp::decode(&v.into_vec()).expect("era rewards decoding value from db failed"));
	let rewards: Rewards = db_rewards.unwrap();
	assert_eq!(rewards.total(), total);
}

fn db_rewards_check(bcdb: &Arc<BlockChainDB>, r: Rewards) {
	let db_rewards = bcdb
		.key_value()
		.get(db::COL_EXTRA, b"Rewards")
		.expect("Low level database error when fetching 'era reward' . Some issue with disk?")
		.map(|v| rlp::decode(&v.into_vec()).expect("era rewards decoding value from db failed"));
	let rewards: Rewards = db_rewards.unwrap();
	assert_eq!(rewards, r);
}

#[test]
fn medietas_json_reward_test() {
	let tempdir = TempDir::new("").unwrap();
	let spec = new_medietas(&tempdir.path());
	let reward_config = RewardConfig::default();
	assert_eq!(reward_config, spec.params().reward_config);
}

#[test]
fn block_reward_test() {
	let db = test_helpers::new_db();
	let spec = new_reward_test();

	let engine = &*spec.engine;

	let reward_config = RewardConfig::default();
	let mut base_reward = reward_config.calc_era_base_reward(U256::zero());
	assert_eq!(base_reward, U256::from_str("128ff8f22963b1200").unwrap());
	let mut rewards = Rewards::new();
	rewards.add_new_era_reward(EraRewardInfo::new(0, U256::zero(), base_reward));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("269d10257dc76dc1d99000").unwrap());
	assert_eq!(base_reward, U256::from_str("ef69e2754a009a00").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		1,
		U256::from_str("269d10257dc76dc1d99000").unwrap(),
		base_reward,
	));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("45bd85b2124de0e4423000").unwrap());
	assert_eq!(base_reward, U256::from_str("c0fe74fc74649600").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		2,
		U256::from_str("45bd85b2124de0e4423000").unwrap(),
		base_reward,
	));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("5ed4fc58bbb7c816bbf000").unwrap());
	assert_eq!(base_reward, U256::from_str("9b93180bb410c000").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		3,
		U256::from_str("5ed4fc58bbb7c816bbf000").unwrap(),
		base_reward,
	));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("730f02d1b36e86fd3d7000").unwrap());
	assert_eq!(base_reward, U256::from_str("7d69101cc2445e00").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		4,
		U256::from_str("730f02d1b36e86fd3d7000").unwrap(),
		base_reward,
	));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("835d13214abe95739ac000").unwrap());
	assert_eq!(base_reward, U256::from_str("65183f7a59fba000").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		5,
		U256::from_str("835d13214abe95739ac000").unwrap(),
		base_reward,
	));

	base_reward =
		reward_config.calc_era_base_reward(U256::from_str("9081d5783afd758a620000").unwrap());
	assert_eq!(base_reward, U256::from_str("517e5afdf9b01e00").unwrap());
	rewards.add_new_era_reward(EraRewardInfo::new(
		6,
		U256::from_str("9081d5783afd758a620000").unwrap(),
		base_reward,
	));

	// Create client
	let mut client_config = ClientConfig::default();
	client_config.tracing.enabled = true;
	client_config.verifier_type = VerifierType::CanonNoSeal;
	client_config.check_seal = false;

	let client = Client::new(
		client_config,
		&spec,
		db,
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
		None,
	)
	.unwrap();

	spec.engine.update_rewards(rewards);

	// engine 2 blocks per era, define in the json.
	// client and blockchain use default configure, 200000 blocks one era.
	// Create test data:
	// genesis
	//    |
	// b1  era 0
	//    |
	// b2  era 1
	//    |
	// b3  with transaction and uncle    era 1
	//    |
	// b4  era 2

	let genesis_header = spec.genesis_header();
	let genesis_gas = genesis_header.gas_limit().clone();

	let mut db = spec
		.ensure_db_good(get_temp_state_db(), &Default::default())
		.unwrap();
	let mut rolling_timestamp = 40;
	let mut last_hashes = vec![];
	let genesis_header = genesis_header.clone();
	last_hashes.push(genesis_header.hash());

	let kp = KeyPair::from_secret_slice(&keccak("")).unwrap();
	let author = kp.address();

	let solution: [char; SOLUTION_SIZE] = ['0'; SOLUTION_SIZE];
	let ss: String = solution.into_iter().collect();

	// Add root block first
	let mut b1_block = OpenBlock::new(
		engine,
		Default::default(),
		false,
		db,
		&genesis_header,
		Arc::new(last_hashes.clone()),
		author.clone(),
		(3141562.into(), 31415620.into()),
		vec![],
		false,
		None,
	)
	.unwrap();
	rolling_timestamp += 100;
	b1_block.set_timestamp(rolling_timestamp);

	let b1_block = b1_block
		.close_and_lock()
		.unwrap()
		.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
		.unwrap();

	if let Err(e) = client.import_block(Unverified::from_rlp(b1_block.rlp_bytes()).unwrap()) {
		panic!(
			"error importing block which is valid by definition: {:?}",
			e
		);
	}
	client.flush_queue();
	client.import_verified_blocks();

	let mut author_mined = U256::from_str("128ff8f22963b1200").unwrap();
	assert_eq!(
		b1_block.state.balance(&author.clone()).unwrap(),
		author_mined,
	);

	let b1_header = view!(BlockView, &b1_block.rlp_bytes()).header();
	db = b1_block.drain().state.drop().1;

	last_hashes.push(b1_header.hash());

	// Add parent block
	let mut b2_block = OpenBlock::new(
		engine,
		Default::default(),
		false,
		db,
		&b1_header,
		Arc::new(last_hashes.clone()),
		author.clone(),
		(3141562.into(), 31415620.into()),
		vec![],
		false,
		None,
	)
	.unwrap();
	rolling_timestamp += 100;
	b2_block.set_timestamp(rolling_timestamp);

	let b2_block = b2_block
		.close_and_lock()
		.unwrap()
		.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
		.unwrap();

	if let Err(e) = client.import_block(Unverified::from_rlp(b2_block.rlp_bytes()).unwrap()) {
		panic!(
			"error importing block which is valid by definition: {:?}",
			e
		);
	}
	client.flush_queue();
	client.import_verified_blocks();

	author_mined += U256::from_str("ef69e2754a009a00").unwrap();
	assert_eq!(
		b2_block.state.balance(&author.clone()).unwrap(),
		author_mined
	);

	let b2_header = view!(BlockView, &b2_block.rlp_bytes()).header();
	db = b2_block.drain().state.drop().1;

	last_hashes.push(b2_header.hash());

	// Add testing block with transaction and uncle
	let mut b3_block = OpenBlock::new(
		engine,
		Default::default(),
		true,
		db,
		&b2_header,
		Arc::new(last_hashes.clone()),
		author.clone(),
		(3141562.into(), 31415620.into()),
		vec![],
		false,
		None,
	)
	.unwrap();
	rolling_timestamp += 100;
	b3_block.set_timestamp(rolling_timestamp);

	let mut n = 0;
	for _ in 0..1 {
		b3_block
			.push_transaction(
				Transaction {
					nonce: n.into(),
					gas_price: 100000.into(),
					gas: 100000.into(),
					action: Action::Create,
					data: vec![],
					value: U256::zero(),
					private: None,
				}
				.sign(kp.secret(), Some(spec.network_id())),
				None,
			)
			.unwrap();
		n += 1;
	}

	let dbu = spec
		.ensure_db_good(get_temp_state_db(), &Default::default())
		.unwrap();
	let uncle_author: Address = "0000000000000000000000000000000000000006".into();
	let mut b3_uncle = OpenBlock::new(
		engine,
		Default::default(),
		true,
		dbu,
		&genesis_header,
		Arc::new(last_hashes.clone()),
		uncle_author.clone(),
		(3141562.into(), 31415620.into()),
		vec![],
		false,
		None,
	)
	.unwrap();
	b3_uncle.set_timestamp(rolling_timestamp);

	b3_block.push_uncle(b3_uncle.header.clone()).unwrap();

	let b3_block = b3_block
		.close_and_lock()
		.unwrap()
		.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
		.unwrap();

	let res = client.import_block(Unverified::from_rlp(b3_block.rlp_bytes()).unwrap());
	if res.is_err() {
		panic!("error importing block: {:#?}", res.err().unwrap());
	}
	client.flush_queue();
	client.import_verified_blocks();

	author_mined += U256::from_str("f6e53188e38d1600").unwrap();
	assert_eq!(
		b3_block.state.balance(&author.clone()).unwrap(),
		author_mined
	);

	let uncle_mined = U256::from_str("b38f69d7cacc5c00").unwrap();
	assert_eq!(
		b3_block.state.balance(&uncle_author.clone()).unwrap(),
		uncle_mined
	);

	let b3_header = view!(BlockView, &b3_block.rlp_bytes()).header();
	db = b3_block.drain().state.drop().1;
	last_hashes.push(b3_header.hash());

	let mut b4_block = OpenBlock::new(
		engine,
		Default::default(),
		true,
		db,
		&b3_header,
		Arc::new(last_hashes.clone()),
		author.clone(),
		(3141562.into(), 31415620.into()),
		vec![],
		false,
		None,
	)
	.unwrap();
	rolling_timestamp += 100;
	b4_block.set_timestamp(rolling_timestamp);

	let b4_block = b4_block
		.close_and_lock()
		.unwrap()
		.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
		.unwrap();

	let res = client.import_block(Unverified::from_rlp(b4_block.rlp_bytes()).unwrap());
	if res.is_err() {
		panic!("error importing block: {:#?}", res.err().unwrap());
	}
	client.flush_queue();
	client.import_verified_blocks();

	author_mined += U256::from_str("c0fe74fc74649600").unwrap();
	assert_eq!(
		b4_block.state.balance(&author.clone()).unwrap(),
		author_mined
	);

	assert_eq!(
		b4_block.state.balance(&uncle_author.clone()).unwrap(),
		uncle_mined
	);

	let b4_header = view!(BlockView, &b4_block.rlp_bytes()).header();
	//db = b4_block.drain().state.drop().1;
	last_hashes.push(b4_header.hash());

	let total_block_number = 4;
	// Test0. Check overall filter
	let filter = TraceFilter {
		range: (BlockId::Number(1)..BlockId::Number(total_block_number)),
		from_address: vec![],
		to_address: vec![],
		after: None,
		count: None,
	};

	let traces = client.filter_traces(filter);
	assert!(traces.is_some(), "Filtered traces should be present");
	let traces_vec = traces.unwrap();
	let block_reward_traces: Vec<LocalizedTrace> = traces_vec
		.clone()
		.into_iter()
		.filter(|trace| match (trace).action {
			Reward(ref a) => a.reward_type == RewardType::Block,
			_ => false,
		})
		.collect();
	assert_eq!(block_reward_traces.len(), total_block_number as usize);
	for i in 0..3 {
		match block_reward_traces[i].action {
			Reward(ref reward) =>
				if i == 0 {
					assert_eq!(reward.value, U256::from_str("128ff8f22963b1200").unwrap());
				} else if i == 1 {
					assert_eq!(reward.value, U256::from_str("ef69e2754a009a00").unwrap());
				} else if i == 2 {
					assert_eq!(reward.value, U256::from_str("f6e53188e38d1600").unwrap());
				} else {
					assert_eq!(reward.value, U256::from_str("c0fe74fc74649600").unwrap());
				},
			_ => assert!(false),
		}
	}
	let uncle_reward_traces: Vec<LocalizedTrace> = traces_vec
		.clone()
		.into_iter()
		.filter(|trace| match (trace).action {
			Reward(ref a) => a.reward_type == RewardType::Uncle,
			_ => false,
		})
		.collect();
	assert_eq!(uncle_reward_traces.len(), 1);
	match uncle_reward_traces[0].action {
		Reward(ref reward) => assert_eq!(reward.value, U256::from_str("b38f69d7cacc5c00").unwrap()),
		_ => assert!(false),
	}

	// Check block filter
	let traces = client.block_traces(BlockId::Number(2));
	assert_eq!(traces.unwrap().len(), 1);
	let traces = client.block_traces(BlockId::Number(3));
	assert_eq!(traces.unwrap().len(), 3);
}

#[test]
fn calc_era_rewards_on_block_insert_test() {
	let gwei = U256::from(1_000_000_000);
	let bcdb = test_helpers::new_db();
	let spec = new_era_reward_test();

	let mut reward_config = RewardConfig::default();
	let count = spec.params().reward_config.block_count_each_era;
	let mut total = U256::from(1_000_000_000) * gwei * gwei;
	reward_config.set_test_config(total, count, 50, 0);

	let base_reward = reward_config.calc_era_base_reward(U256::zero());
	assert_eq!(base_reward, U256::from(50_000_000) * gwei * gwei);

	let mut rewards = Rewards::new();
	rewards.add_new_era_reward(EraRewardInfo::new(0, U256::zero(), base_reward));
	spec.engine.update_rewards(rewards.clone());

	let engine = &*spec.engine;

	total = total - base_reward;
	reward_config.set_test_config(total, count, 50, 0);

	// Create client
	let mut client_config = ClientConfig::default();
	client_config.tracing.enabled = true;
	client_config.verifier_type = VerifierType::CanonNoSeal;
	client_config.check_seal = false;
	client_config.blockchain.reward_config = reward_config;
	client_config.history = 1000;

	let client = Client::new(
		client_config,
		&spec,
		bcdb.clone(),
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
		None,
	)
	.unwrap();

	client.update_rewards(rewards);

	// engine 10 blocks per era, define in the json.
	// Create test data:
	// genesis
	//    |
	// b1-b9  era 0
	//    |
	// b10- b19  era 1
	//    |
	// b20 - b29  era 2
	// ...
	// b500 - b509 era 50
	//    ...
	// b600 - b609 era 60

	let genesis_header = spec.genesis_header();
	let genesis_gas = genesis_header.gas_limit().clone();

	let mut db = spec
		.ensure_db_good(get_temp_state_db(), &Default::default())
		.unwrap();
	let mut rolling_timestamp = 40;
	let mut last_hashes = vec![];
	let mut parent_header = genesis_header.clone();
	last_hashes.push(parent_header.hash());

	let kp = KeyPair::from_secret_slice(&keccak("")).unwrap();
	let author = kp.address();

	let solution: [char; SOLUTION_SIZE] = ['0'; SOLUTION_SIZE];
	let ss: String = solution.into_iter().collect();

	for _ in 1..610 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db,
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());
	}

	let mut rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards, engine_rewards.unwrap());
	assert_eq!(rewards.cur_era(), MAX_ERA - 1);
	let eras = rewards.eras();

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), base_reward);

	// era 0  need exclude genesis block
	let mut mined = base_reward * (count - 1);
	let mut base = base_reward.shr(1);

	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), mined);
	assert_eq!(eras[1].base(), base);

	for i in 2..MAX_ERA {
		assert_eq!(eras[i].era(), i);

		let cur_min = base / gwei * gwei * count;
		mined += cur_min;
		base = (total - mined) * 50 as u32 / 100 / count / gwei * gwei;
		assert_eq!(eras[i].total(), mined);
		assert_eq!(eras[i].base(), base);
	}

	assert_eq!(rewards.get_era_base_reward(MAX_ERA), None);
	assert_eq!(rewards.get_era_base_reward(MAX_ERA + 1), None);

	db_rewards_check(&bcdb, rewards.clone());
	assert_eq!(client.get_total_reward().1, mined + base * count);

	// do block reset test.
	client.reset(110);
	db_rewards_check(&bcdb, rewards.clone());

	client.reset(111);
	let total = rewards.eras()[49].total();
	let base = rewards.eras()[49].base();
	rewards.update_total_reward(total + base * U256::from(9));
	db_rewards_check(&bcdb, rewards.clone());

	client.reset(120);
	rewards.update_total_reward(total);
	db_rewards_check(&bcdb, rewards.clone());


	client.reset(121);
	let total = rewards.eras()[48].total();
	let base = rewards.eras()[48].base();
	rewards.update_total_reward(total + base * U256::from(9));
	rewards.delete_last_era(49);
	db_rewards_check(&bcdb, rewards.clone());

	client.reset(122);
	rewards.update_total_reward(total + base * U256::from(8));
	db_rewards_check(&bcdb, rewards);
}

#[test]
fn calc_era_rewards_on_fork_choince_test1() {
	let gwei = U256::from(1_000_000_000);
	let bcdb = test_helpers::new_db();
	let spec = new_era_reward_test();

	let mut reward_config = RewardConfig::default();
	let count = spec.params().reward_config.block_count_each_era;
	let total = U256::from(1_800) * gwei;
	reward_config.set_test_config(total, count, 50, 2);
	let base_reward = reward_config.calc_era_base_reward(U256::zero());
	assert_eq!(base_reward, U256::from(32) * gwei);

	let mut era_rewards = Rewards::new();
	era_rewards.add_new_era_reward(EraRewardInfo::new(0, U256::zero(), base_reward));
	spec.engine.update_rewards(era_rewards.clone());
	let engine = &*spec.engine;

	// Create client
	let mut client_config = ClientConfig::default();
	client_config.tracing.enabled = true;
	client_config.verifier_type = VerifierType::CanonNoSeal;
	client_config.check_seal = false;
	client_config.blockchain.reward_config = reward_config;

	let client = Client::new(
		client_config,
		&spec,
		bcdb.clone(),
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
		None,
	)
	.unwrap();

	client.update_rewards(era_rewards);

	let genesis_header = spec.genesis_header();
	let genesis_gas = genesis_header.gas_limit().clone();

	let mut db = spec
		.ensure_db_good(get_temp_state_db(), &Default::default())
		.unwrap();
	let mut rolling_timestamp = 40;
	let mut last_hashes = vec![];
	let mut parent_header = genesis_header.clone();
	last_hashes.push(parent_header.hash());

	let kp = KeyPair::from_secret_slice(&keccak("")).unwrap();
	let author = kp.address();

	let solution: [char; SOLUTION_SIZE] = ['0'; SOLUTION_SIZE];
	let ss: String = solution.into_iter().collect();

	let uncle_author: Address = "0000000000000000000000000000000000000006".into();

	// engine 10 blocks per era, define in the json.
	// Create test data:
	// genesis
	//    |
	//  step 1.  b1 ..b8-  b9  - b10  (block 9  have one uncle)
	//  step 2.       b8'- b9' - b10' --- b19' - b20' (block 19' have one uncle)
	//  step 3.                       --- b19'' - b20'' - b30''
	//  step 4.       b8'''  ---      ---               - b30'''  b31'''

	// step 1. insert block b1 .. b10, block 9  have one uncle.
	let mut db7 = db.boxed_clone();
	let mut block7_header = genesis_header.clone();
	let mut b7_hashes = last_hashes.clone();

	for i in 1..11 {
		if i == 8 {
			block7_header = parent_header.clone();
			db7 = db.boxed_clone();
			b7_hashes = last_hashes.clone();
		}

		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db,
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		if i == 9 {
			let mut uncle = OpenBlock::new(
				engine,
				Default::default(),
				true,
				db7.boxed_clone(),
				&block7_header,
				Arc::new(b7_hashes.clone()),
				uncle_author.clone(),
				(3141562.into(), 31415620.into()),
				vec![],
				false,
				None,
			)
			.unwrap();
			uncle.set_timestamp(rolling_timestamp);
			block.push_uncle(uncle.header.clone()).unwrap();
		}

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	let eras = rewards.eras();

	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());
	assert_eq!(rewards.cur_era(), 1);

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(317) * gwei);
	assert_eq!(eras[1].base(), U256::from(26) * gwei);

	db_rewards_check(&bcdb, rewards);
	let mut total_mined = U256::from(343) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 2. insert block b8'.. b20', b19' have one uncle.
	db = db7.boxed_clone();
	parent_header = block7_header.clone();
	for i in 8..11 {
		last_hashes.pop();
	}

	let mut db17 = db.boxed_clone();
	let mut block17_header = genesis_header.clone();
	let mut db18 = db.boxed_clone();
	let mut block18_header = genesis_header.clone();

	for i in 8..21 {
		if i == 18 {
			block17_header = parent_header.clone();
			db17 = db.boxed_clone();
		} else if i == 19 {
			block18_header = parent_header.clone();
			db18 = db.boxed_clone();
		}

		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db,
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		if i == 19 {
			let mut b17_hashes = last_hashes.clone();
			b17_hashes.pop();

			let mut uncle = OpenBlock::new(
				engine,
				Default::default(),
				true,
				db17.boxed_clone(),
				&block17_header,
				Arc::new(b17_hashes.clone()),
				uncle_author.clone(),
				(3141562.into(), 31415620.into()),
				vec![],
				false,
				None,
			)
			.unwrap();
			uncle.set_timestamp(rolling_timestamp);
			block.push_uncle(uncle.header.clone()).unwrap();
		}

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 11 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 11 {
			total_mined = U256::from(340) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	let eras = rewards.eras();

	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());
	assert_eq!(rewards.cur_era(), 2);

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(288) * gwei);
	assert_eq!(eras[1].base(), U256::from(26) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(570) * gwei);
	assert_eq!(eras[2].base(), U256::from(21) * gwei);

	db_rewards_check(&bcdb, rewards);
	total_mined = U256::from(591) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 3. insert block b19''.. b30''.
	db = db18.boxed_clone();
	parent_header = block18_header.clone();
	for i in 19..21 {
		last_hashes.pop();
	}

	for i in 19..31 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db,
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}

		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 21 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 21 {
			total_mined = U256::from(592) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 3);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(288) * gwei);
	assert_eq!(eras[1].base(), U256::from(26) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(548) * gwei);
	assert_eq!(eras[2].base(), U256::from(22) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(768) * gwei);
	assert_eq!(eras[3].base(), U256::from(18) * gwei);

	db_rewards_check(&bcdb, rewards);
	total_mined = U256::from(786) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 4. insert block       b8'''  ---      ---     - b30'''  b31'''.
	db = db7.boxed_clone();
	parent_header = block7_header.clone();
	last_hashes = b7_hashes.clone();

	let ancestor_db = db7;
	let ancestor_header = block7_header;
	let ancestor_hashes = b7_hashes;

	for i in 8..32 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header.clone(),
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}

		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 31 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 31 {
			total_mined = U256::from(804) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 3);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(288) * gwei);
	assert_eq!(eras[1].base(), U256::from(26) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(548) * gwei);
	assert_eq!(eras[2].base(), U256::from(22) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(768) * gwei);
	assert_eq!(eras[3].base(), U256::from(18) * gwei);

	db_rewards_check(&bcdb, rewards);
}

#[test]
fn calc_era_rewards_on_fork_choince_test2() {
	let gwei = U256::from(1_000_000_000);
	let bcdb = test_helpers::new_db();
	let spec = new_era_reward_test();

	let mut reward_config = RewardConfig::default();
	let count = spec.params().reward_config.block_count_each_era;
	let total = U256::from(1_800) * gwei;
	reward_config.set_test_config(total, count, 50, 2);
	let base_reward = reward_config.calc_era_base_reward(U256::zero());
	assert_eq!(base_reward, U256::from(32) * gwei);

	let mut rewards = Rewards::new();
	rewards.add_new_era_reward(EraRewardInfo::new(0, U256::zero(), base_reward));
	spec.engine.update_rewards(rewards.clone());
	let engine = &*spec.engine;

	// Create client
	let mut client_config = ClientConfig::default();
	client_config.tracing.enabled = true;
	client_config.verifier_type = VerifierType::CanonNoSeal;
	client_config.check_seal = false;
	client_config.blockchain.reward_config = reward_config;

	let client = Client::new(
		client_config,
		&spec,
		bcdb.clone(),
		Arc::new(Miner::new_for_tests(&spec, None)),
		IoChannel::disconnected(),
		None,
	)
	.unwrap();

	client.update_rewards(rewards);

	let genesis_header = spec.genesis_header();
	let genesis_gas = genesis_header.gas_limit().clone();
	let genesis_db = spec
		.ensure_db_good(get_temp_state_db(), &Default::default())
		.unwrap();
	let mut rolling_timestamp = 40;
	let mut genesis_hashes = vec![];
	genesis_hashes.push(genesis_header.hash());

	let kp = KeyPair::from_secret_slice(&keccak("")).unwrap();
	let author = kp.address();

	let solution: [char; SOLUTION_SIZE] = ['0'; SOLUTION_SIZE];
	let ss: String = solution.into_iter().collect();

	let uncle_author: Address = "0000000000000000000000000000000000000006".into();
	let uncle_author2: Address = "0000000000000000000000000000000000000007".into();

	// engine 10 blocks per era, define in the json.
	// Create test data:
	// genesis
	//    |
	//  step 1.  b1  ---   - b30  b31  (every block have one uncle, except block 1,8,15...)
	//  step 2.  b1'       - b30'      b36' (every block have two uncle, except block 1,8,15..)
	//  step 3.            - b30''            b38''
	//  step 4.            - b30'''                  b39''''
	//  step 5.            - b30''''                       b40''''

	// step 1. insert block b1 - b31.
	let mut db = genesis_db.boxed_clone();
	let mut parent_header = genesis_header.clone();
	let mut last_hashes = genesis_hashes.clone();

	let mut ancestor_db = db.boxed_clone();
	let mut ancestor_header = parent_header.clone();
	let mut ancestor_hashes = last_hashes.clone();

	for i in 1..32 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		if (i - 1) % 7 != 0 {
			let mut uncle = OpenBlock::new(
				engine,
				Default::default(),
				true,
				ancestor_db.boxed_clone(),
				&ancestor_header,
				Arc::new(ancestor_hashes.clone()),
				uncle_author.clone(),
				(3141562.into(), 31415620.into()),
				vec![],
				false,
				None,
			)
			.unwrap();
			uncle.set_timestamp(rolling_timestamp);
			block.push_uncle(uncle.header.clone()).unwrap();
		}

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		if (i - 1) % 7 == 0 {
			ancestor_header = parent_header.clone();
			ancestor_db = db.boxed_clone();
			ancestor_hashes = last_hashes.clone();
		}

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 3);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(431) * gwei);
	assert_eq!(eras[1].base(), U256::from(24) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(797) * gwei);
	assert_eq!(eras[2].base(), U256::from(17) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(1031) * gwei);
	assert_eq!(eras[3].base(), U256::from(13) * gwei);

	db_rewards_check(&bcdb, rewards);
	let mut total_mined = U256::from(1077) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 2. insert block b10 - b36.
	let mut db = genesis_db.boxed_clone();
	let mut parent_header = genesis_header.clone();
	let mut last_hashes = genesis_hashes.clone();

	let mut ancestor_db = db.boxed_clone();
	let mut ancestor_header = parent_header.clone();
	let mut ancestor_hashes = last_hashes.clone();

	let mut b29_db = db.boxed_clone();
	let mut b29_header = parent_header.clone();
	let mut b29_hashes = last_hashes.clone();

	for i in 1..37 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		if (i - 1) % 7 != 0 {
			let mut uncle = OpenBlock::new(
				engine,
				Default::default(),
				true,
				ancestor_db.boxed_clone(),
				&ancestor_header,
				Arc::new(ancestor_hashes.clone()),
				uncle_author.clone(),
				(3141562.into(), 31415620.into()),
				vec![],
				false,
				None,
			)
			.unwrap();
			uncle.set_timestamp(rolling_timestamp);
			block.push_uncle(uncle.header.clone()).unwrap();

			let mut uncle2 = OpenBlock::new(
				engine,
				Default::default(),
				true,
				ancestor_db.boxed_clone(),
				&ancestor_header,
				Arc::new(ancestor_hashes.clone()),
				uncle_author2.clone(),
				(3141562.into(), 31415620.into()),
				vec![],
				false,
				None,
			)
			.unwrap();
			uncle2.set_timestamp(rolling_timestamp);
			block.push_uncle(uncle2.header.clone()).unwrap();
		}

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		if (i - 1) % 7 == 0 {
			ancestor_header = parent_header.clone();
			ancestor_db = db.boxed_clone();
			ancestor_hashes = last_hashes.clone();
		}

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i == 29 {
			b29_header = parent_header.clone();
			b29_db = db.boxed_clone();
			b29_hashes = last_hashes.clone();
		}

		if i < 32 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 32 {
			total_mined = U256::from(1314) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 3);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(574) * gwei);
	assert_eq!(eras[1].base(), U256::from(21) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(1005) * gwei);
	assert_eq!(eras[2].base(), U256::from(14) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(1251) * gwei);
	assert_eq!(eras[3].base(), U256::from(9) * gwei);

	db_rewards_check(&bcdb, rewards);
	total_mined = U256::from(1368) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 3. b30'' - b38''.
	let mut db = b29_db.boxed_clone();
	let mut parent_header = b29_header.clone();
	let mut last_hashes = b29_hashes.clone();

	for i in 30..39 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 37 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 37 {
			total_mined = U256::from(1323) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 3);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(574) * gwei);
	assert_eq!(eras[1].base(), U256::from(21) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(1005) * gwei);
	assert_eq!(eras[2].base(), U256::from(14) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(1251) * gwei);
	assert_eq!(eras[3].base(), U256::from(9) * gwei);

	db_rewards_check(&bcdb, rewards);
	total_mined = U256::from(1332) * gwei;
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 4. b30'' - b39''.
	let mut db = b29_db.boxed_clone();
	let mut parent_header = b29_header.clone();
	let mut last_hashes = b29_hashes.clone();

	for i in 30..40 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 39 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 39 {
			total_mined = U256::from(1341) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 4);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(574) * gwei);
	assert_eq!(eras[1].base(), U256::from(21) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(1005) * gwei);
	assert_eq!(eras[2].base(), U256::from(14) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(1251) * gwei);
	assert_eq!(eras[3].base(), U256::from(9) * gwei);
	assert_eq!(eras[4].era(), 4);
	assert_eq!(eras[4].total(), U256::from(1341) * gwei);
	assert_eq!(eras[4].base(), U256::from(8) * gwei);

	db_rewards_check(&bcdb, rewards);
	assert_eq!(client.get_total_reward().1, total_mined);

	// step 5. b30'' - b40''.
	let mut db = b29_db.boxed_clone();
	let mut parent_header = b29_header.clone();
	let mut last_hashes = b29_hashes.clone();

	for i in 30..41 {
		let mut block = OpenBlock::new(
			engine,
			Default::default(),
			false,
			db.boxed_clone(),
			&parent_header,
			Arc::new(last_hashes.clone()),
			author.clone(),
			(3141562.into(), 31415620.into()),
			vec![],
			false,
			None,
		)
		.unwrap();
		rolling_timestamp += 100;
		block.set_timestamp(rolling_timestamp);

		let block = block
			.close_and_lock()
			.unwrap()
			.seal(engine, vec![rlp::encode(&H256::zero()), rlp::encode(&ss)])
			.unwrap();

		if let Err(e) = client.import_block(Unverified::from_rlp(block.rlp_bytes()).unwrap()) {
			panic!(
				"error importing block which is valid by definition: {:?}",
				e
			);
		}
		client.flush_queue();
		client.import_verified_blocks();

		parent_header = view!(BlockView, &block.rlp_bytes()).header();
		db = block.drain().state.drop().1;
		last_hashes.push(parent_header.hash());

		if i < 40 {
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		} else if i == 40 {
			total_mined = U256::from(1349) * gwei;
			db_total_reward_check(&bcdb, total_mined);
			assert_eq!(client.get_total_reward().1, total_mined);
		}
	}

	let rewards = client.get_rewards();
	let engine_rewards = engine.get_rewards();
	assert_eq!(rewards.cur_era(), 4);
	let eras = rewards.eras();
	assert_eq!(rewards.eras(), engine_rewards.unwrap().eras());

	assert_eq!(eras[0].era(), 0);
	assert_eq!(eras[0].total(), U256::zero());
	assert_eq!(eras[0].base(), U256::from(32) * gwei);
	assert_eq!(eras[1].era(), 1);
	assert_eq!(eras[1].total(), U256::from(574) * gwei);
	assert_eq!(eras[1].base(), U256::from(21) * gwei);
	assert_eq!(eras[2].era(), 2);
	assert_eq!(eras[2].total(), U256::from(1005) * gwei);
	assert_eq!(eras[2].base(), U256::from(14) * gwei);
	assert_eq!(eras[3].era(), 3);
	assert_eq!(eras[3].total(), U256::from(1251) * gwei);
	assert_eq!(eras[3].base(), U256::from(9) * gwei);
	assert_eq!(eras[4].era(), 4);
	assert_eq!(eras[4].total(), U256::from(1341) * gwei);
	assert_eq!(eras[4].base(), U256::from(8) * gwei);

	db_rewards_check(&bcdb, rewards);
	assert_eq!(client.get_total_reward().1, total_mined);
}
