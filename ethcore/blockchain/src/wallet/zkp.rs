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

use bellman::groth16::{
	prepare_verifying_key, Parameters, PreparedVerifyingKey, VerifyingKey as BellmanVerifyingKey,
};
use group::EncodedPoint;
use pairing::bls12_381::{Bls12, G1Uncompressed, G2Uncompressed};
use rustc_hex::FromHex;
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde_derive::Deserialize;
use std::fmt;
use std::path::Path;
use zcash_proofs::load_parameters_from_bytes;

// TODO(xin): Add hash check back.
const SPEND_PARAM_PATH: &str = "res/sapling-spend.params";
const SPEND_PARAM_HASH : &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";

const OUTPUT_PARAM_PATH: &str = "res/sapling-output.params";
const OUTPUT_PARAM_HASH : &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";

pub type SaplingPreparedVerifyingKey = PreparedVerifyingKey<Bls12>;
pub type SaplingParam = Parameters<Bls12>;

lazy_static! {
	pub static ref SPEND_VK: SaplingPreparedVerifyingKey =
		{ load_sapling_spend_verifying_key().unwrap() };
	pub static ref OUTPUT_VK: SaplingPreparedVerifyingKey =
		{ load_sapling_output_verifying_key().unwrap() };
	pub static ref SPEND_PARAM: SaplingParam =
		{ load_parameters_from_bytes(&include_bytes!("../../res/sapling-spend.params")[..]).0 };
	pub static ref OUTPUT_PARAM: SaplingParam =
		{ load_parameters_from_bytes(&include_bytes!("../../res/sapling-output.params")[..]).0 };
}

fn clean_0x(s: &str) -> &str {
	if s.starts_with("0x") {
		&s[2..]
	} else {
		s
	}
}

#[derive(Debug, Clone)]
struct Point<EP: EncodedPoint>(EP::Affine);

impl<'de, EP: EncodedPoint> Deserialize<'de> for Point<EP> {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct EncodedPointVisitor<EP: EncodedPoint>(::std::marker::PhantomData<EP>);

		impl<'de, EP: EncodedPoint> Visitor<'de> for EncodedPointVisitor<EP> {
			type Value = Point<EP>;

			fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
				formatter.write_str("a hex string")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: de::Error,
			{
				let mut point = EP::empty();
				let point_raw = clean_0x(value)
					.from_hex::<Vec<_>>()
					.map_err(|e| de::Error::custom(format!("Expected hex string: {}", e)))?;
				if point.as_ref().len() != point_raw.len() {
					return Err(de::Error::custom(format!(
						"Expected hex string of length {}",
						point.as_ref().len()
					)));
				}

				point.as_mut().copy_from_slice(&point_raw);
				point
					.into_affine()
					.map_err(|e| de::Error::custom(format!("Invalid curve point: {}", e)))
					.map(Point)
			}
		}

		deserializer.deserialize_str(EncodedPointVisitor::<EP>(Default::default()))
	}
}

type G1 = Point<G1Uncompressed>;
type G2 = Point<G2Uncompressed>;
#[derive(Clone, Deserialize)]
struct VerifyingKey {
	#[serde(rename = "alphaG1")]
	pub alpha_g1: G1,
	#[serde(rename = "betaG1")]
	pub beta_g1: G1,
	#[serde(rename = "betaG2")]
	pub beta_g2: G2,
	#[serde(rename = "gammaG2")]
	pub gamma_g2: G2,
	#[serde(rename = "deltaG1")]
	pub delta_g1: G1,
	#[serde(rename = "deltaG2")]
	pub delta_g2: G2,
	#[serde(rename = "ic")]
	pub ic: Vec<G1>,
}

impl From<VerifyingKey> for BellmanVerifyingKey<Bls12> {
	fn from(vk: VerifyingKey) -> BellmanVerifyingKey<Bls12> {
		BellmanVerifyingKey {
			alpha_g1: vk.alpha_g1.0,
			beta_g1: vk.beta_g1.0,
			beta_g2: vk.beta_g2.0,
			gamma_g2: vk.gamma_g2.0,
			delta_g1: vk.delta_g1.0,
			delta_g2: vk.delta_g2.0,
			ic: vk.ic.into_iter().map(|p| p.0).collect(),
		}
	}
}

pub fn load_sapling_spend_verifying_key() -> Result<SaplingPreparedVerifyingKey, String> {
	let spend_vk_json = include_bytes!("../../res/sapling-spend-verifying-key.json");
	let spend_vk = serde_json::from_slice::<VerifyingKey>(&spend_vk_json[..]).unwrap();
	Ok(prepare_verifying_key(&spend_vk.into()))
}

pub fn load_sapling_output_verifying_key() -> Result<SaplingPreparedVerifyingKey, String> {
	let output_vk_json = include_bytes!("../../res/sapling-output-verifying-key.json");
	let output_vk = serde_json::from_slice::<VerifyingKey>(&output_vk_json[..]).unwrap();
	Ok(prepare_verifying_key(&output_vk.into()))
}

pub fn load_sapling_spend_param() {}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn load_vk_key() {
		assert_eq!(load_sapling_spend_verifying_key().is_ok(), true);
		assert_eq!(load_sapling_output_verifying_key().is_ok(), true);
	}

	#[test]
	fn load_parameters() {
		let (_, _) =
			load_parameters_from_bytes(&include_bytes!("../../res/sapling-spend.params")[..]);
		let (_, _) =
			load_parameters_from_bytes(&include_bytes!("../../res/sapling-output.params")[..]);
	}
}
