use ed25519_keygen::{
    append_checksum, base58_encode, extract_11bit_chunks, indices_to_mnemonic, pbkdf2_hmac_sha512,
    public_key_from_seed, to_hex, Entropy, ExtendedKey,
};

fn separator(title: &str) {
    println!("\n{}", "─".repeat(60));
    println!("  {}", title);
    println!("{}", "─".repeat(60));
}

fn main() {
    separator("STEP 1 — Entropy (128 bits of randomness)");
    let mut entropy = Entropy::generate(16);
    println!("  Raw bytes : {:?}", entropy.bytes);
    println!("  Hex       : {}", entropy.display_hex());

    separator("STEP 2 — BIP-39: entropy → mnemonic");
    append_checksum(&mut entropy.bytes);
    println!("  With checksum (hex): {}", to_hex(&entropy.bytes));

    let indices = extract_11bit_chunks(&entropy.bytes);
    println!("  11-bit indices: {:?}", indices);

    let mnemonic = indices_to_mnemonic(&indices);
    println!("\n  ┌─────────────────────────────────────────┐");
    println!("  │  {}  │", mnemonic);
    println!("  └─────────────────────────────────────────┘");

    separator("STEP 3 — PBKDF2-HMAC-SHA512 (2048 iterations)");
    println!("  password : \"{}\"", mnemonic);
    println!("  salt     : \"mnemonic\"");
    println!("  iters    : 2048");
    let pbkdf2_seed = pbkdf2_hmac_sha512(mnemonic.as_bytes(), b"mnemonic", 2048, 64);
    println!("\n  Seed (64 bytes):");
    println!("    {}", to_hex(&pbkdf2_seed[..32]));
    println!("    {}", to_hex(&pbkdf2_seed[32..]));

    separator("STEP 4 — SLIP-0010 key derivation (m/44'/501'/0'/0')");
    let seed: [u8; 64] = pbkdf2_seed.try_into().unwrap();
    let private_key = ExtendedKey::derive_solana_key(&seed, 0);
    println!("  Private key (32 bytes):");
    println!("    {}", to_hex(&private_key));

    separator("STEP 5 — Ed25519: private key → public key");
    let public_key = public_key_from_seed(&private_key);
    println!("  SHA-512(private key) → clamp → scalar × G");
    println!("\n  Public key (32 bytes):");
    println!("    {}", to_hex(&public_key));

    separator("RESULT — Solana wallet address");
    println!("\n  {}\n", base58_encode(&public_key));
}
