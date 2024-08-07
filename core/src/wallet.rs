use pem::{encode, Pem};
use rand::thread_rng;
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::{
    env,
    fs::{File, OpenOptions},
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use blake3::Hash as Blake3Hash;

const PEM_TYPE: &str = "EC PRIVATE KEY";

#[derive(Clone, Debug, Copy)]
pub struct Address {
    pub addr: Blake3Hash,
}

/// RLP Encoding
impl Encodable for Address {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.addr.as_bytes().as_slice());
    }
}

impl Decodable for Address {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        let bytes: Vec<u8> = rlp.as_val()?;
        Ok(Address {
            addr: Blake3Hash::from_bytes(
                bytes
                    .try_into()
                    .map_err(|_| DecoderError::Custom("Invalid address length"))?,
            ),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Wallet {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl Wallet {
    fn get_default_key_file_path() -> Result<PathBuf, Error> {
        let home = env::var("HOME")
            .or_else(|_| env::var("USERPROFILE"))
            .map_err(|_| Error::new(ErrorKind::NotFound, "Home directory not found"))?;
        Ok(PathBuf::from(home).join(".rust_pow.key"))
    }

    pub fn load_private_key(custom_path: Option<&Path>) -> Self {
        let path = custom_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| Wallet::get_default_key_file_path().unwrap());
        let mut file = File::open(path).unwrap();
        let mut pem_string = String::new();
        file.read_to_string(&mut pem_string).unwrap();

        let pem = pem::parse(&mut pem_string).unwrap();
        if pem.tag() != PEM_TYPE {
            panic!("Invalid PEM type");
        }
        let secp = Secp256k1::new();
        let private_key = SecretKey::from_slice(pem.contents())
            .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
            .unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &private_key);

        Self {
            private_key,
            public_key,
            address: Address {
                addr: blake3::hash(public_key.to_string().as_bytes()),
            },
        }
    }

    /// Generate and load a private key using computer randomnes
    /// It won't override an exisiting private key to avoid losing funds
    pub fn generate_and_load_private_key(custom_path: Option<&Path>) -> Self {
        let path = custom_path
            .map(Path::to_path_buf)
            .unwrap_or_else(|| Wallet::get_default_key_file_path().unwrap());

        if path.exists() {
            return Wallet::load_private_key(Some(&path));
        }

        // Generating the private key.
        let mut rng = thread_rng();

        let secp = Secp256k1::new();
        let (private_key, public_key) = secp.generate_keypair(&mut rng);

        let pem = Pem::new(PEM_TYPE, private_key.secret_bytes().to_vec());
        let pem_string = encode(&pem);

        // Writing the private key to the specified file.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true) // This will fail if the file already exists
            .open(&path)
            .unwrap();

        file.write_all(pem_string.as_bytes()).unwrap();

        Self {
            private_key,
            public_key,
            address: Address {
                addr: blake3::hash(public_key.to_string().as_bytes()),
            },
        }
    }
}
