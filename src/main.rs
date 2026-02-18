use ed25519_keygen::{Entropy, append_checksum, extract_11bit_chunks, hmac_sha512, indices_to_mnemonic, to_hex};

fn main() {
    let mut entropy = Entropy::generate(16);
    println!("Generated entropy: {:?}", entropy.bytes);
    println!("Entropy in hex: {}", entropy.display_hex());

    append_checksum(&mut entropy.bytes);

    println!("Entropy with checksum: {:?}", entropy.bytes);
    println!("Entropy with checksum in hex: {}", to_hex(&entropy.bytes));

    let indices = extract_11bit_chunks(&entropy.bytes);
    println!("Extracted 11-bit chunks: {:?}", indices);

    let mnemonic = indices_to_mnemonic(&indices);
    println!("Generated mnemonic: {}", mnemonic);

    let hmac_test = hmac_sha512("key".as_bytes(), "The quick brown fox jumps over the lazy dog".as_bytes());
    println!("HMAC-SHA512: {}", to_hex(&hmac_test));
}
