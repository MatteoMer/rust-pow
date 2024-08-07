use core::block::Block;
use std::{error::Error, fmt::Display, path::Path};

use leveldb::{
    database::Database,
    iterator::{Iterable, LevelDBIterator},
    kv::KV,
    options::{Options, ReadOptions, WriteOptions},
};
use num_bigint::BigUint;
use num_traits::FromBytes;

struct Node {
    db: Database<i32>,
}

#[derive(Debug)]
enum NodeError {
    DatabaseError(leveldb::error::Error),
    InvalidBlock,
    BlockNotFound,
    DecodingError(rlp::DecoderError),
}

impl Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NodeError::DatabaseError(e) => write!(f, "Database error: {}", e),
            NodeError::InvalidBlock => write!(f, "The block is invalid"),
            NodeError::BlockNotFound => write!(f, "Block not found"),
            NodeError::DecodingError(e) => write!(f, "Error decoding block: {}", e),
        }
    }
}

impl Error for NodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NodeError::DatabaseError(e) => Some(e),
            NodeError::DecodingError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<leveldb::error::Error> for NodeError {
    fn from(err: leveldb::error::Error) -> Self {
        NodeError::DatabaseError(err)
    }
}

impl From<rlp::DecoderError> for NodeError {
    fn from(err: rlp::DecoderError) -> Self {
        NodeError::DecodingError(err)
    }
}

/// TODO: p2p
impl Node {
    /// Create a new node and sync it to the latest block
    fn new() -> Result<Self, NodeError> {
        let path = Path::new("blockchain_db");
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(path, options)?;
        let mut node = Node { db };
        node.sync()?;
        Ok(node)
    }

    fn sync(&mut self) -> Result<(), NodeError> {
        Ok(())
    }

    fn add_new_block(&mut self, block: &Block) -> Result<(), NodeError> {
        let previous_block = self.get_last_block()?;

        // TODO: add tx verification?
        match previous_block {
            Some(prev) => {
                eprintln!(
                    "{:?} < {:?}",
                    BigUint::from_be_bytes(block.compute_hash().as_bytes()),
                    block.header.target
                );
                if BigUint::from_be_bytes(block.compute_hash().as_bytes()) > block.header.target
                    || prev.compute_hash() != block.header.previous_block_hash
                {
                    return Err(NodeError::InvalidBlock);
                }
            }
            None => {
                // Genesis block
                if block.header.previous_block_hash
                    != blake3::Hash::from_hex(
                        "0000000000000000000000000000000000000000000000000000000000000000",
                    )
                    .unwrap()
                {
                    return Err(NodeError::InvalidBlock);
                }
            }
        }
        self.save_block_to_db(block)?;
        Ok(())
    }

    fn save_block_to_db(&mut self, block: &Block) -> Result<(), NodeError> {
        let index = self.get_chain_length()?;
        let encoded_block = rlp::encode(block);
        self.db
            .put(WriteOptions::new(), index, encoded_block.as_ref())?;
        Ok(())
    }

    fn get_block(&self, index: i32) -> Result<Option<Block>, NodeError> {
        match self.db.get(ReadOptions::new(), index)? {
            Some(value) => {
                let block: Block = rlp::decode(&value)?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    fn get_last_block(&self) -> Result<Option<Block>, NodeError> {
        let chain_length = self.get_chain_length()?;
        if chain_length == 0 {
            Ok(None)
        } else {
            Ok(self.get_block(chain_length - 1)?)
        }
    }

    fn get_chain_length(&self) -> Result<i32, NodeError> {
        let iter = self.db.iter(ReadOptions::new());
        iter.seek_to_last();
        Ok(if iter.valid() { iter.key() + 1 } else { 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hash;
    use core::{block::BlockHeader, miner::Miner};
    use leveldb::options::Options;
    use num_bigint::BigUint;
    use tempfile::TempDir;

    fn create_test_block(previous_hash: Hash) -> Block<'static> {
        let target: BigUint = BigUint::from_bytes_be(&[
            0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        let mut block = Block {
            header: BlockHeader {
                previous_block_hash: previous_hash,
                merkle_root: Hash::from_hex(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                timestamp: 12345,
                target,
                nonce: 0,
            },
            transaction_count: 0,
            transactions: vec![],
        };

        Miner::new().mine(&mut block);
        block
    }

    fn setup_test_node() -> (Node, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test_db");
        let mut options = Options::new();
        options.create_if_missing = true;
        let db = Database::open(&path, options).unwrap();
        (Node { db }, temp_dir)
    }

    #[test]
    fn test_new_node() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("blockchain_db");
        std::env::set_var("blockchain_db", path.to_str().unwrap());

        let node = Node::new();
        assert!(node.is_ok());
    }

    #[test]
    fn test_add_genesis_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );

        assert!(node.add_new_block(&genesis_block).is_ok());
        assert_eq!(node.get_chain_length().unwrap(), 1);
    }

    #[test]
    fn test_add_invalid_genesis_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let invalid_genesis_block = create_test_block(
            Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        );

        assert!(matches!(
            node.add_new_block(&invalid_genesis_block),
            Err(NodeError::InvalidBlock)
        ));
    }

    #[test]
    fn test_add_valid_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();

        let next_block = create_test_block(genesis_block.compute_hash());
        assert!(node.add_new_block(&next_block).is_ok());
        assert_eq!(node.get_chain_length().unwrap(), 2);
    }

    #[test]
    fn test_add_multiple_valid_blocks() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();

        let next_block = create_test_block(genesis_block.compute_hash());
        assert!(node.add_new_block(&next_block).is_ok());
        assert_eq!(node.get_chain_length().unwrap(), 2);
        let next_block = create_test_block(next_block.compute_hash());
        assert!(node.add_new_block(&next_block).is_ok());
        assert_eq!(node.get_chain_length().unwrap(), 3);
    }

    #[test]
    fn test_add_invalid_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();

        let invalid_block = create_test_block(
            Hash::from_hex("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(),
        );
        assert!(matches!(
            node.add_new_block(&invalid_block),
            Err(NodeError::InvalidBlock)
        ));
    }

    #[test]
    fn test_get_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();

        let retrieved_block = node.get_block(0).unwrap().unwrap();
        assert_eq!(retrieved_block.compute_hash(), genesis_block.compute_hash());
    }

    #[test]
    fn test_get_nonexistent_block() {
        let (node, _temp_dir) = setup_test_node();
        assert!(node.get_block(0).unwrap().is_none());
    }

    #[test]
    fn test_get_last_block() {
        let (mut node, _temp_dir) = setup_test_node();
        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();

        let last_block = node.get_last_block().unwrap().unwrap();
        assert_eq!(last_block.compute_hash(), genesis_block.compute_hash());
    }

    #[test]
    fn test_get_chain_length() {
        let (mut node, _temp_dir) = setup_test_node();
        assert_eq!(node.get_chain_length().unwrap(), 0);

        let genesis_block = create_test_block(
            Hash::from_hex("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
        );
        node.add_new_block(&genesis_block).unwrap();
        assert_eq!(node.get_chain_length().unwrap(), 1);
    }
}
