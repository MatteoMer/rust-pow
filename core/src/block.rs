use crate::transaction::Transaction;
use blake3::{Hash as Blake3Hash, Hasher};
use num_bigint::BigUint;
use rlp::Encodable;

#[derive(Clone)]
pub struct BlockHeader {
    pub previous_block_hash: Blake3Hash,
    pub timestamp: u64,
    pub merkle_root: Blake3Hash,
    pub target: BigUint,
    pub nonce: u32,
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(5)
            .append(&self.timestamp)
            .append(&self.target.to_bytes_le())
            .append(&self.nonce)
            .append(&self.merkle_root.as_bytes().as_slice())
            .append(&self.previous_block_hash.as_bytes().as_slice());
    }
}

#[derive(Clone)]
pub struct Block<'a> {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction<'a>>,
    pub transaction_count: u64,
}

impl Encodable for Block<'_> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(3)
            .append(&self.header)
            .append_list(&self.transactions)
            .append(&self.transaction_count);
    }
}

impl<'a> Block<'a> {
    pub fn new(previous_block_hash: Blake3Hash) -> Self {
        let target: BigUint = BigUint::from_bytes_be(&[
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);

        let timestamp = chrono::Utc::now().timestamp();
        Self {
            header: BlockHeader {
                previous_block_hash,
                merkle_root: blake3::hash(&[0; 32]),
                timestamp: timestamp.try_into().unwrap(),
                target,
                nonce: 0,
            },
            transactions: vec![],
            transaction_count: 0,
        }
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
    fn test_block_header_encoding() {
        let target = BigUint::from_bytes_be(&[
            0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);

        let header = BlockHeader {
            previous_block_hash: blake3::hash(b"previous block"),
            timestamp: 1625097600,
            merkle_root: blake3::hash(b"merkle root"),
            target,
            nonce: 12345,
        };

        let mut stream = rlp::RlpStream::new();
        header.rlp_append(&mut stream);
        let encoded = stream.out();

        // Check that the encoded data starts with a list indicator
        assert!(encoded[0] >= 0xf8, "Expected a list indicator >= 0xf8");

        // Decode the RLP data
        let decoded: rlp::Rlp = rlp::Rlp::new(&encoded);
        assert_eq!(
            decoded.item_count().unwrap(),
            5,
            "BlockHeader should have 5 fields"
        );

        // Check each field
        let decoded_timestamp: u64 = decoded.val_at(0).unwrap();
        assert_eq!(decoded_timestamp, 1625097600, "Timestamp mismatch");

        let decoded_nonce: u32 = decoded.val_at(2).unwrap();
        assert_eq!(decoded_nonce, 12345, "Nonce mismatch");

        let decoded_merkle_root: Vec<u8> = decoded.val_at(3).unwrap();
        assert_eq!(
            decoded_merkle_root.len(),
            32,
            "Merkle root should be 32 bytes"
        );
        assert_eq!(
            decoded_merkle_root,
            header.merkle_root.as_bytes(),
            "Merkle root mismatch"
        );

        let decoded_previous_hash: Vec<u8> = decoded.val_at(4).unwrap();
        assert_eq!(
            decoded_previous_hash.len(),
            32,
            "Previous block hash should be 32 bytes"
        );
        assert_eq!(
            decoded_previous_hash,
            header.previous_block_hash.as_bytes(),
            "Previous block hash mismatch"
        );
    }
    #[test]
    fn test_compute_hash() {
        // Create two identical blocks
        let previous_hash = blake3::hash(b"previous block hash");
        let mut block1 = Block::new(previous_hash);
        let mut block2 = Block::new(previous_hash);

        // Verify that identical blocks have the same hash
        assert_eq!(
            block1.compute_hash(),
            block2.compute_hash(),
            "Identical blocks should have the same hash"
        );

        // Create a transaction
        let sender_wallet = create_mock_wallet();
        let receiver_wallet = create_mock_wallet();
        let sender = mock_account_from_wallet(&sender_wallet, 100);
        let receiver = mock_account_from_wallet(&receiver_wallet, 0);
        let unsigned_tx = UnsignedTransaction::new(
            sender.clone(),
            receiver.clone(),
            50,
            sender_wallet.public_key,
        );
        let tx = unsigned_tx.sign(sender_wallet.private_key);

        // Add the transaction to block1
        block1.append_transaction(tx.clone());

        // Verify that the hash has changed after adding a transaction
        assert_ne!(
            block1.compute_hash(),
            block2.compute_hash(),
            "Block hash should change after adding a transaction"
        );

        // Add the same transaction to block2
        block2.append_transaction(tx);

        // Verify that the hashes are the same again
        assert_eq!(
            block1.compute_hash(),
            block2.compute_hash(),
            "Blocks with the same transactions should have the same hash"
        );

        // Change the nonce of block1
        block1.header.nonce += 1;

        // Verify that the hash has changed after modifying the nonce
        assert_ne!(
            block1.compute_hash(),
            block2.compute_hash(),
            "Block hash should change after modifying the nonce"
        );

        // Create a new block with a different previous hash
        let different_previous_hash = blake3::hash(b"different previous block hash");
        let block3 = Block::new(different_previous_hash);

        // Verify that the hash is different for a block with a different previous hash
        assert_ne!(
            block1.compute_hash(),
            block3.compute_hash(),
            "Blocks with different previous hashes should have different hashes"
        );

        // Verify that computing the hash multiple times for the same block yields the same result
        let hash1 = block1.compute_hash();
        let hash2 = block1.compute_hash();
        assert_eq!(
            hash1, hash2,
            "Computing the hash multiple times for the same block should yield the same result"
        );
    }
}
