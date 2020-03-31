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

//! Sends HTTP notifications to a list of URLs every time new work is available.

extern crate equihash;
extern crate fetch;
extern crate parity_runtime;
extern crate url;
extern crate hyper;

use self::fetch::{Fetch, Request, Client as FetchClient, Method};
use self::parity_runtime::Executor;
use self::url::Url;
use self::hyper::header::{self, HeaderValue};

use ethereum_types::{H256, U256, H512};
use parking_lot::Mutex;

use futures::Future;

/// Trait for notifying about new mining work
pub trait NotifyWork : Send + Sync {
	/// Fired when new mining job available
	fn notify(&self, pow_hash: H512, difficulty: U256, number: u64);
}

/// POSTs info about new work to given urls.
pub struct WorkPoster {
	urls: Vec<Url>,
	client: FetchClient,
	executor: Executor,
}

impl WorkPoster {
	/// Create new `WorkPoster`.
	pub fn new(urls: &[String], fetch: FetchClient, executor: Executor) -> Self {
		let urls = urls.into_iter().filter_map(|u| {
			match Url::parse(u) {
				Ok(url) => Some(url),
				Err(e) => {
					warn!("Error parsing URL {} : {}", u, e);
					None
				}
			}
		}).collect();
		WorkPoster {
			client: fetch,
			executor: executor,
			urls: urls,
		}
	}
}

impl NotifyWork for WorkPoster {
	fn notify(&self, pow_hash: H512, difficulty: U256, number: u64) {
		// TODO: move this to engine
		let target = equihash::difficulty_to_boundary(&difficulty);
		let body = format!(
			r#"{{ "result": ["0x{:x}","0x{:x}","0x{:x}"] }}"#,
			pow_hash, target, number
		);

		for u in &self.urls {
			let u = u.clone();
			self.executor.spawn(self.client.fetch(
				Request::new(u.clone(), Method::POST)
					.with_header(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))
					.with_body(body.clone()), Default::default()
			).map_err(move |e| {
				warn!("Error sending HTTP notification to {} : {}, retrying", u, e);
			}).map(|_| ()));
		}
	}
}
