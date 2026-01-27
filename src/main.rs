use ed25519_keygen::{Entropy};

fn main() {

    let entropy = Entropy::generate(32);
    println!("Generated entropy: {:?}", entropy.bytes);
    println!("Entropy in hex: {}", entropy.display_hex());
}
