#[macro_use]
extern crate lazy_static;

extern crate aes;
extern crate blake2_rfc;
extern crate byteorder;
extern crate chacha20_poly1305_aead;
extern crate crypto_api_chachapoly;
extern crate ff;
extern crate fpe;
extern crate pairing;
extern crate rand;
extern crate rlp;
extern crate sapling_crypto;
extern crate heapsize;

use sapling_crypto::jubjub::JubjubBls12;

pub mod keys;
pub mod merkle_tree;
pub mod note_encryption;
pub mod prover;
pub mod sapling;
mod serialize;
pub mod transaction;
pub mod zip32;


#[cfg(test)]
mod test_vectors;

lazy_static! {
    pub static ref JUBJUB: JubjubBls12 = { JubjubBls12::new() };
}
