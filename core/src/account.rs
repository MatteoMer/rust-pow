use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};

use crate::wallet::Address;

/// Basic account on the blockchain
/// Stored in the node's DB
#[derive(Clone, Debug, Copy)]
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

impl Decodable for Account {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        Ok(Account {
            address: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            balance: rlp.val_at(2)?,
        })
    }
}
