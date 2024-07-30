use crate::transaction::Transaction;
use blake3::{Hash as Blake3Hash, Hasher};
use rlp::Encodable;

const NBITS: u32 = 0x1f00ffff;

pub enum BlockState {
    Unmined,
    Mined { hash: Blake3Hash },
}

impl Encodable for BlockState {
    fn rlp_append(&self, stream: &mut rlp::RlpStream) {
        match self {
            BlockState::Unmined => {
                stream.begin_list(1);
                stream.append(&0u8); // 0 indicates Unmined state
            }
            BlockState::Mined { hash } => {
                stream.begin_list(2);
                stream.append(&1u8); // 1 indicates Mined state
                stream.append(&hash.as_bytes().as_slice());
            }
        }
    }
}

pub struct BlockHeader {
    pub previous_block_hash: Blake3Hash,
    pub timestamp: u64,
    pub merkle_root: Blake3Hash,
    pub n_bits: u32,
    pub nonce: u32,
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(5)
            .append(&self.timestamp)
            .append(&self.n_bits)
            .append(&self.nonce)
            .append(&self.merkle_root.as_bytes().as_slice())
            .append(&self.previous_block_hash.as_bytes().as_slice());
    }
}

pub struct Block<'a> {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction<'a>>,
    pub transaction_count: u64,
    pub state: BlockState,
}

impl Encodable for Block<'_> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(4)
            .append(&self.header)
            .append_list(&self.transactions)
            .append(&self.transaction_count)
            .append(&self.state);
    }
}

impl<'a> Block<'a> {
    pub fn new(previous_block_hash: Blake3Hash) -> Self {
        let timestamp = chrono::Utc::now().timestamp();
        Self {
            header: BlockHeader {
                previous_block_hash,
                merkle_root: blake3::hash(&[0; 32]),
                timestamp: timestamp.try_into().unwrap(),
                n_bits: NBITS,
                nonce: 0,
            },
            transactions: vec![],
            transaction_count: 0,
            state: BlockState::Unmined,
        }
    }

    pub fn is_mined(&self) -> bool {
        matches!(self.state, BlockState::Mined { .. })
    }

    /// Append and validate tx (verifying signature) and TODO: verify within node
    pub fn append_transaction(&mut self, tx: Transaction<'a>) {
        tx.verify_signature();
        self.transactions.push(tx);
        self.transaction_count += 1;
        self.header.merkle_root = self.compute_merkle_root();
    }

    pub fn compute_merkle_root(&self) -> Blake3Hash {
        let transaction_hashes: Vec<Blake3Hash> =
            self.transactions.iter().map(|tx| tx.tx_id).collect();

        Self::merkle_root_recursive(&transaction_hashes)
    }

    fn merkle_root_recursive(hashes: &[Blake3Hash]) -> Blake3Hash {
        match hashes.len() {
            0 => Blake3Hash::from([0u8; 32]),
            1 => hashes[0],
            _ => {
                let mid = (hashes.len() + 1) / 2;
                let left = Self::merkle_root_recursive(&hashes[..mid]);
                let right = Self::merkle_root_recursive(&hashes[mid..]);
                let mut hasher = Hasher::new();
                hasher.update(left.as_bytes());
                hasher.update(right.as_bytes());
                hasher.finalize()
            }
        }
    }

    pub fn compute_hash(&self) -> Blake3Hash {
        blake3::hash(&rlp::encode(self))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::transaction::{tests::*, UnsignedTransaction};

    use super::*;

    #[test]
    fn test_new_block() {
        let previous_hash = blake3::hash(b"previous block hash");
        let block = Block::new(previous_hash);

        assert_eq!(block.header.previous_block_hash, previous_hash);
        assert_eq!(block.header.n_bits, NBITS);
        assert_eq!(block.header.nonce, 0);
        assert!(block.header.timestamp <= chrono::Utc::now().timestamp().try_into().unwrap());
        assert_eq!(block.transactions.len(), 0);
        assert_eq!(block.transaction_count, 0);
    }

    #[test]
    fn test_append_transaction() {
        let previous_hash = blake3::hash(b"previous block hash");
        let mut block = Block::new(previous_hash);

        let sender_wallet = create_mock_wallet();
        let receiver_wallet = create_mock_wallet();
        let sender = mock_account_from_wallet(&sender_wallet, 100);
        let receiver = mock_account_from_wallet(&receiver_wallet, 0);

        let unsigned_tx = UnsignedTransaction::new(sender, receiver, 50, sender_wallet.public_key);
        let tx = unsigned_tx.sign(sender_wallet.private_key);

        block.append_transaction(tx);

        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transaction_count, 1);
        assert_ne!(block.header.merkle_root, blake3::hash(&[0; 32]));
    }

    #[test]
    fn test_compute_merkle_root() {
        let previous_hash = blake3::hash(b"previous block hash");
        let mut block = Block::new(previous_hash);

        let sender_wallet = create_mock_wallet();
        let receiver_wallet = create_mock_wallet();
        let sender = mock_account_from_wallet(&sender_wallet, 100);
        let receiver = mock_account_from_wallet(&receiver_wallet, 0);

        let unsigned_tx1 = UnsignedTransaction::new(
            sender.clone(),
            receiver.clone(),
            50,
            sender_wallet.public_key,
        );
        let tx1 = unsigned_tx1.sign(sender_wallet.private_key);

        let unsigned_tx2 = UnsignedTransaction::new(sender, receiver, 30, sender_wallet.public_key);
        let tx2 = unsigned_tx2.sign(sender_wallet.private_key);

        block.append_transaction(tx1);
        let merkle_root_1 = block.header.merkle_root;

        block.append_transaction(tx2);
        let merkle_root_2 = block.header.merkle_root;

        assert_ne!(merkle_root_1, merkle_root_2);
        assert_eq!(block.header.merkle_root, block.compute_merkle_root());
    }

    #[test]
    fn test_merkle_root_recursive() {
        let hash1 = blake3::hash(b"transaction 1");
        let hash2 = blake3::hash(b"transaction 2");
        let hash3 = blake3::hash(b"transaction 3");

        let root_1 = Block::merkle_root_recursive(&[hash1]);
        assert_eq!(root_1, hash1);

        let root_2 = Block::merkle_root_recursive(&[hash1, hash2]);
        let expected_root_2 = {
            let mut hasher = Hasher::new();
            hasher.update(hash1.as_bytes());
            hasher.update(hash2.as_bytes());
            hasher.finalize()
        };
        assert_eq!(root_2, expected_root_2);

        let root_3 = Block::merkle_root_recursive(&[hash1, hash2, hash3]);
        let expected_root_3 = {
            let mut hasher = Hasher::new();
            hasher.update(expected_root_2.as_bytes());
            hasher.update(hash3.as_bytes());
            hasher.finalize()
        };
        assert_eq!(root_3, expected_root_3);
    }

    #[test]
    fn test_transaction_verification() {
        let previous_hash = blake3::hash(b"previous block hash");
        let mut block = Block::new(previous_hash);

        let sender_wallet = create_mock_wallet();
        let receiver_wallet = create_mock_wallet();
        let sender = mock_account_from_wallet(&sender_wallet, 100);
        let receiver = mock_account_from_wallet(&receiver_wallet, 0);

        let unsigned_tx = UnsignedTransaction::new(sender, receiver, 50, sender_wallet.public_key);
        let tx = unsigned_tx.sign(sender_wallet.private_key);

        // This should not panic
        block.append_transaction(tx.clone());

        // Manually verify the transaction
        tx.verify_signature();
    }

    #[test]
    fn test_block_state_encoding() {
        let unmined_state = BlockState::Unmined;
        let mined_state = BlockState::Mined {
            hash: blake3::hash(b"mined block hash"),
        };

        let mut unmined_stream = rlp::RlpStream::new();
        unmined_state.rlp_append(&mut unmined_stream);
        let unmined_encoded = unmined_stream.out();

        let mut mined_stream = rlp::RlpStream::new();
        mined_state.rlp_append(&mut mined_stream);
        let mined_encoded = mined_stream.out();

        assert_ne!(unmined_encoded, mined_encoded);
        assert_eq!(unmined_encoded[0], 0xc1); // List of 1 item
        assert_eq!(unmined_encoded[1], 0x80); // Encoded representation of 0
        assert_eq!(mined_encoded[0], 0xe2); // List of 2 items
        assert_eq!(mined_encoded[1], 0x01); // Mined state indicator
    }

    #[test]
    fn test_block_header_encoding() {
        let header = BlockHeader {
            previous_block_hash: blake3::hash(b"previous block"),
            timestamp: 1625097600,
            merkle_root: blake3::hash(b"merkle root"),
            n_bits: NBITS,
            nonce: 12345,
        };

        let mut stream = rlp::RlpStream::new();
        header.rlp_append(&mut stream);
        let encoded = stream.out();

        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0xf8); // List indicator
    }
}
