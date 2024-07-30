use wallet::Wallet;

mod account;
mod block;
mod transaction;
mod wallet;

fn main() {
    println!("[rust-proof-of-work] creating a wallet");

    let wallet = Wallet::generate_and_load_private_key(None);
    println!(
        "public key: {}, wallet: {}",
        wallet.public_key, wallet.address.addr
    );
}
