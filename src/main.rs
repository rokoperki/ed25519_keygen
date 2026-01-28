use ed25519_keygen::{Entropy, append_checksum, extract_11bit_chunks, indices_to_mnemonic, sha256, to_hex};

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
}
