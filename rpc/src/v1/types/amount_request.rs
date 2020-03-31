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

use v1::helpers::AmountRequest as Request;
use ethereum_types::U256;
/// Amount Request, which is similar to Call Request
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
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

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use rustc_hex::FromHex;
	use serde_json;
	use super::AmountRequest;
	use ethereum_types::U256;
	
	#[test]
	fn amount_request_deserialize() {
		let s = r#"{
			"address":"0000000000000000000000000000000000000001",
			"amount": "0x32",
			"memo":"test"
		}"#;
		let deserialized: AmountRequest = serde_json::from_str(s).unwrap();

		assert_eq!(deserialized, AmountRequest {
			address: "0000000000000000000000000000000000000001".to_string(),
			amount: U256::from(50u64),
			memo: Some("test".to_string()),
		});
	}
}
