pub mod keystore;
use crate::exn;
pub use keystore::*;
use xuanmi_base_support::{TraitStdResultToOutcome, *};
mod signature;

const BYTES_HEX: &'static str = "bytes_hex:";
const SCALAR_HEX: &'static str = "scalar_hex:";
const POINT_HEX: &'static str = "point_hex:";

pub fn bytes_from_hex(hex: &str) -> Outcome<Vec<u8>> {
    const ERR_BYTES: &'static str = "Hex string of bytes should begin with \"bytes_hex\"";
    if hex.len() < BYTES_HEX.len() {
        throw!(name = exn::PrefixException, ctx = ERR_BYTES);
    }
    if &hex[..BYTES_HEX.len()] != BYTES_HEX {
        throw!(name = exn::PrefixException, ctx = ERR_BYTES);
    }
    hex::decode(&hex[BYTES_HEX.len()..]).catch(exn::HexToException, "")
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex_str = String::from(BYTES_HEX);
    hex_str.push_str(hex::encode(bytes).as_str());
    hex_str
}
