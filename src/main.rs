use ed25519_keygen::{
    append_checksum, extract_11bit_chunks, indices_to_mnemonic, pbkdf2_hmac_sha512, to_hex,
    Entropy, ExtendedKey,
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

    let pbkdf2_seed = pbkdf2_hmac_sha512(mnemonic.as_bytes(), "mnemonic".as_bytes(), 2048, 64);
    println!("Derived seed (hex): {}", to_hex(&pbkdf2_seed));

    let seed: [u8; 64] = pbkdf2_seed.try_into().unwrap();
    let private_key = ExtendedKey::derive_solana_key(&seed, 0);
    println!("Private key (hex): {}", to_hex(&private_key));
}
