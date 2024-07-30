use rlp::{Encodable, RlpStream};

use crate::wallet::Address;

/// Basic account on the blockchain
/// Stored in the node's DB
#[derive(Clone, Debug)]
pub struct Account {
    pub address: Address,
    pub nonce: u64,
    pub balance: u64,
}

/// RLP Encoding
impl Encodable for Account {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3)
            .append(&self.address)
            .append(&self.nonce)
            .append(&self.balance);
    }
}
