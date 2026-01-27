use ed25519_keygen::{Entropy, sha256, to_hex};

fn main() {

    let entropy = Entropy::generate(32);
    println!("Generated entropy: {:?}", entropy.bytes);
    println!("Entropy in hex: {}", entropy.display_hex());

    let hash = sha256(entropy.bytes.as_slice());
    let result = to_hex(&hash);

    println!("Computed SHA-256 hash of the entropy. {:?}", hash);

    println!("SHA-256 hash of entropy: {}", result);
}
