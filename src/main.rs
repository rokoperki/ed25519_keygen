use ed25519_keygen::{
    append_checksum, base58_encode, extract_11bit_chunks, indices_to_mnemonic, pbkdf2_hmac_sha512,
    public_key_from_seed, to_hex, Entropy, ExtendedKey,
};

fn main() {
    let mut entropy = Entropy::generate(16);
    println!("Entropy (hex):    {}", entropy.display_hex());

    append_checksum(&mut entropy.bytes);

    let indices = extract_11bit_chunks(&entropy.bytes);
    let mnemonic = indices_to_mnemonic(&indices);
    println!("Mnemonic:         {}", mnemonic);

    let pbkdf2_seed = pbkdf2_hmac_sha512(mnemonic.as_bytes(), "mnemonic".as_bytes(), 2048, 64);
    let seed: [u8; 64] = pbkdf2_seed.try_into().unwrap();

    let private_key = ExtendedKey::derive_solana_key(&seed, 0);
    println!("Private key (hex): {}", to_hex(&private_key));

    let public_key = public_key_from_seed(&private_key);
    println!("Public key (hex):  {}", to_hex(&public_key));
    println!("Solana address:    {}", base58_encode(&public_key));
}
