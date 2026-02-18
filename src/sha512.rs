// SHA-512 uses:
// - 64-bit words (u64) instead of 32-bit (u32)
// - 8 initial hash values from fractional parts of sqrt of first 8 primes
// - 80 round constants from fractional parts of cbrt of first 80 primes
// - 80 compression rounds instead of 64
// - 128-byte (1024-bit) blocks instead of 64-byte
// - 128-bit message length encoding instead of 64-bit

const H_INIT: [u64; 8] = [
    0x6a09e667f3bcc908, // √2
    0xbb67ae8584caa73b, // √3
    0x3c6ef372fe94f82b, // √5
    0xa54ff53a5f1d36f1, // √7
    0x510e527fade682d1, // √11
    0x9b05688c2b3e6c1f, // √13
    0x1f83d9abfb41bd6b, // √17
    0x5be0cd19137e2179, // √19
];

const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, // ∛2,  ∛3,  ∛5,  ∛7
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, // ∛11, ∛13, ∛17, ∛19
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, // ∛23, ∛29, ∛31, ∛37
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694, // ∛41, ∛43, ∛47, ∛53
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, // ∛59, ∛61, ∛67, ∛71
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, // ∛73, ∛79, ∛83, ∛89
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, // ∛97, ∛101,∛103,∛107
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70, // ∛109,∛113,∛127,∛131
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, // ∛137,∛139,∛149,∛151
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b, // ∛157,∛163,∛167,∛173
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, // ∛179,∛181,∛191,∛193
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, // ∛197,∛199,∛211,∛223
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, // ∛227,∛229,∛233,∛239
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, // ∛241,∛251,∛257,∛263
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, // ∛269,∛271,∛277,∛281
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, // ∛283,∛293,∛307,∛311
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, // ∛313,∛317,∛331,∛337
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b, // ∛347,∛349,∛353,∛359
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, // ∛367,∛373,∛379,∛383
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817, // ∛389,∛391,∛397,∛401
];

#[inline]
fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

#[inline]
fn ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Big Sigma 0 - used on variable 'a' in compression
/// Σ₀(x) = ROTR²⁸(x) ⊕ ROTR³⁴(x) ⊕ ROTR³⁹(x)
#[inline]
fn big_sigma0(x: u64) -> u64 {
    rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
}

/// Big Sigma 1 - used on variable 'e' in compression
/// Σ₁(x) = ROTR¹⁴(x) ⊕ ROTR¹⁸(x) ⊕ ROTR⁴¹(x)
#[inline]
fn big_sigma1(x: u64) -> u64 {
    rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)
}

/// Small sigma 0 - used in message schedule
/// σ₀(x) = ROTR¹(x) ⊕ ROTR⁸(x) ⊕ SHR⁷(x)
#[inline]
fn small_sigma0(x: u64) -> u64 {
    rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7)
}

/// Small sigma 1 - used in message schedule
/// σ₁(x) = ROTR¹⁹(x) ⊕ ROTR⁶¹(x) ⊕ SHR⁶(x)
#[inline]
fn small_sigma1(x: u64) -> u64 {
    rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6)
}

pub struct Sha512 {
    state: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_len: u128, // 128-bit to handle the full SHA-512 message length field
}

impl Sha512 {
    pub fn new() -> Self {
        Sha512 {
            state: H_INIT,
            buffer: [0u8; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn create_message_schedule(block: &[u8]) -> [u64; 80] {
        let mut w = [0u64; 80];

        for i in 0..16 {
            w[i] = u64::from_be_bytes([
                block[i * 8],
                block[i * 8 + 1],
                block[i * 8 + 2],
                block[i * 8 + 3],
                block[i * 8 + 4],
                block[i * 8 + 5],
                block[i * 8 + 6],
                block[i * 8 + 7],
            ]);
        }

        for i in 16..80 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        w
    }

    fn process_block(&mut self, block: &[u8]) {
        let w = Self::create_message_schedule(block);

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..80 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);

            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}

impl Sha512 {
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u128;
        let mut offset = 0;

        if self.buffer_len > 0 {
            let needed = 128 - self.buffer_len;

            if data.len() >= needed {
                self.buffer[self.buffer_len..128].copy_from_slice(&data[..needed]);
                self.process_block(&self.buffer.clone());
                self.buffer_len = 0;
                offset = needed;
            } else {
                self.buffer[self.buffer_len..self.buffer_len + data.len()]
                    .copy_from_slice(data);
                self.buffer_len += data.len();
                return;
            }
        }

        while offset + 128 <= data.len() {
            self.process_block(&data[offset..offset + 128]);
            offset += 128;
        }

        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }
}

impl Sha512 {
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len * 8;

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // Need 16 bytes for the 128-bit length field (at bytes 112..128)
        if self.buffer_len > 112 {
            for i in self.buffer_len..128 {
                self.buffer[i] = 0;
            }
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }

        for i in self.buffer_len..112 {
            self.buffer[i] = 0;
        }

        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());

        self.process_block(&self.buffer.clone());

        let mut result = [0u8; 64];
        for (i, word) in self.state.iter().enumerate() {
            result[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
        }

        result
    }
}

pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let block_size = 128;

    // Step 1: Prepare the key — always block_size bytes
    let k: Vec<u8> = if key.len() > block_size {
        // Hash the key, then zero-pad to block_size
        let hashed = sha512(key);
        let mut padded = vec![0u8; block_size];
        padded[..64].copy_from_slice(&hashed);
        padded
    } else {
        // Zero-pad to block_size
        let mut padded = vec![0u8; block_size];
        padded[..key.len()].copy_from_slice(key);
        padded
    };

    // Step 2: Create inner and outer padded keys
    let mut i_key_pad = vec![0x36u8; block_size];
    let mut o_key_pad = vec![0x5cu8; block_size];

    for i in 0..block_size {
        i_key_pad[i] ^= k[i];
        o_key_pad[i] ^= k[i];
    }

    // Step 3: HMAC = H(o_key_pad || H(i_key_pad || message))
    let inner_hash = sha512(&[i_key_pad.as_slice(), message].concat());
    sha512(&[o_key_pad.as_slice(), &inner_hash].concat())
}