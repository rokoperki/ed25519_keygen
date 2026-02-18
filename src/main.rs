use ed25519_keygen::{
    append_checksum, extract_11bit_chunks, hmac_sha512, indices_to_mnemonic, pbkdf2_hmac_sha512,
    to_hex, Entropy,
};

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

    let pbkdf2_key = pbkdf2_hmac_sha512(mnemonic.as_bytes(), "mnemonic".as_bytes(), 2048, 64);
    println!("Derived key (hex): {}", to_hex(&pbkdf2_key));
}
