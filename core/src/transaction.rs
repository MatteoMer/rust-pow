use crate::account::Account;
use rlp::Encodable;
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

use blake3::Hash as Blake3Hash;

#[derive(Clone, Debug, Copy)]
pub struct UnsignedTransaction {
    pub sender: Account,
    pub receiver: Account,
    pub amount: u64,
    pub nonce: u64,
}

impl Encodable for UnsignedTransaction {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(4)
            .append(&self.sender)
            .append(&self.receiver)
            .append(&self.amount)
            .append(&self.nonce);
    }
}

#[derive(Clone, Debug, Copy)]
pub struct Transaction<'a> {
    pub fields: &'a UnsignedTransaction,
    pub signature: Signature,
    pub signing_key: PublicKey,
    pub tx_id: Blake3Hash,
}

impl<'a> Encodable for Transaction<'a> {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        let signature = self.signature.serialize_compact();
        s.begin_list(5)
            .append(self.fields)
            .append(&self.signing_key.serialize().as_slice())
            .append(&signature[0..32].as_ref()) // r
            .append(&signature[32..64].as_ref()) // s
            .append(&self.tx_id.as_bytes().as_slice());
    }
}

impl UnsignedTransaction {
    // TODO: check if tx is valid
    pub fn new(sender: Account, receiver: Account, amount: u64) -> Self {
        let nonce = &sender.nonce + 1;
        Self {
            sender,
            receiver,
            amount,
            nonce,
        }
    }

    pub fn sign<'a>(&'a self, private_key: SecretKey) -> Transaction<'a> {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        if blake3::hash(public_key.to_string().as_bytes()) != self.sender.address.addr {
            panic!("Invalid private key");
        }

        let message = self.message();
        let signature = secp.sign_ecdsa(&message, &private_key);

        Transaction {
            fields: self,
            signature,
            signing_key: public_key,
            tx_id: blake3::hash(&rlp::encode(self)),
        }
    }

    pub fn message(&self) -> Message {
        let rlp_encoded_tx = rlp::encode(self);
        Message::from_digest_slice(blake3::hash(&rlp_encoded_tx).as_bytes().as_slice())
            .expect("32 bytes")
    }
}

impl Transaction<'_> {
    pub fn verify_signature(&self) {
        let secp = Secp256k1::new();
        assert!(secp
            .verify_ecdsa(&self.fields.message(), &self.signature, &self.signing_key)
            .is_ok());
    }
}

#[cfg(test)]
pub mod tests {
    use crate::wallet::{Address, Wallet};

    use super::*;
    use rand::thread_rng;

    pub fn create_mock_wallet() -> Wallet {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        Wallet {
            address: Address {
                addr: blake3::hash(public_key.to_string().as_bytes()),
            },
            public_key,
            private_key,
        }
    }

    pub fn mock_account_from_wallet(wallet: &Wallet, balance: u64) -> Account {
        Account {
            address: wallet.address.clone(),
            balance,
            nonce: 0,
        }
    }

    pub fn create_mock_account(balance: u64) -> Account {
        let mut rng = thread_rng();
        let secp = Secp256k1::new();
        let (_, public_key) = secp.generate_keypair(&mut rng);

        Account {
            address: Address {
                addr: blake3::hash(public_key.to_string().as_bytes()),
            },
            balance,
            nonce: 0,
        }
    }

    /// Create a valid tx, sender signs it, verify that signature is valid. no execution of the tx
    /// itself
    #[test]
    fn test_create_and_verify_valid_tx() {
        let alice_wallet = create_mock_wallet();
        let alice_acc = mock_account_from_wallet(&alice_wallet, 10);

        let bob_acc = create_mock_account(0);

        let tx = UnsignedTransaction::new(alice_acc, bob_acc, 5);

        let signed_tx = tx.sign(alice_wallet.private_key);
        let secp = Secp256k1::new();
        assert!(secp
            .verify_ecdsa(
                &tx.message(),
                &signed_tx.signature,
                &alice_wallet.public_key
            )
            .is_ok());
    }

    /// Create a valid tx, sender signs it, verify that signature fails if provided pkey is wrong. no execution of the tx
    /// itself
    #[test]
    fn test_create_and_verify_invalid_signer() {
        let alice_wallet = create_mock_wallet();
        let alice_acc = mock_account_from_wallet(&alice_wallet, 10);

        let bob_wallet = create_mock_wallet();
        let bob_acc = mock_account_from_wallet(&bob_wallet, 0);

        let tx = UnsignedTransaction::new(alice_acc, bob_acc, 5);

        let signed_tx = tx.sign(alice_wallet.private_key);
        let secp = Secp256k1::new();
        assert!(secp
            .verify_ecdsa(&tx.message(), &signed_tx.signature, &bob_wallet.public_key)
            .is_err());
    }
}
