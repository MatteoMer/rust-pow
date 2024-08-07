use num_bigint::BigUint;
use rand::Rng;

use crate::block::Block;

pub struct Miner {}

impl Miner {
    pub fn new() -> Self {
        Self {}
    }

    pub fn mine(&self, block: &mut Block) {
        let target = block.header.target.clone();
        let mut rng = rand::thread_rng();

        loop {
            // computing block hash with current nonce
            let actual_hash = block.compute_hash();

            // compare hash to target
            let actual_hash_int = BigUint::from_bytes_be(actual_hash.as_bytes());

            if actual_hash_int < target {
                break;
            }
            block.header.nonce = rng.gen();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::block::BlockHeader;

    use super::*;

    #[test]
    fn test_mine() {
        // Easier target for quicker test
        let target: BigUint = BigUint::from_bytes_be(&[
            0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let mut block = Block {
            header: BlockHeader {
                previous_block_hash: blake3::hash(&[0; 32]),
                merkle_root: blake3::hash(&[0; 32]),
                timestamp: chrono::Utc::now().timestamp().try_into().unwrap(),
                target,
                nonce: 0,
            },
            transactions: vec![],
            transaction_count: 0,
        };

        let miner = Miner::new();
        miner.mine(&mut block);

        let hash = block.compute_hash();
        let target = block.header.target.clone();
        let hash_int = BigUint::from_bytes_be(hash.as_bytes());
        assert!(hash_int < target, "Mined hash should be less than target");
        assert_eq!(blake3::hash(&rlp::encode(&block)), hash);
    }
}
