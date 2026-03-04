use crate::hmac_sha512;

pub struct ExtendedKey {
    key: [u8; 32],
    chain_code: [u8; 32],
}

impl ExtendedKey {
    //derive master key from seed
    pub fn from_seed(seed: &[u8; 64]) -> Self {
        let i = hmac_sha512(b"ed25519 seed", seed);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);

        ExtendedKey { key, chain_code }
    }

    //derive hardened child key
    pub fn derive_hardened(&self, index: u32) -> Self {
        let hardened_index = index | 0x80000000;

        let mut data = Vec::with_capacity(37);
        data.push(0x00);
        data.extend_from_slice(&self.key);
        data.extend_from_slice(&hardened_index.to_be_bytes());

        let i = hmac_sha512(&self.chain_code, &data);

        let mut key = [0u8; 32];
        let mut chain_code = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain_code.copy_from_slice(&i[32..]);

        ExtendedKey { key, chain_code }
    }

    pub fn derive_solana_key(seed: &[u8; 64], account: u32) -> [u8; 32] {
        let master = Self::from_seed(seed);
        let purpose = master.derive_hardened(44);
        let coin = purpose.derive_hardened(501);
        let account = coin.derive_hardened(account);
        let change = account.derive_hardened(0);

        change.key
    }
}
