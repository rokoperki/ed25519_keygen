const H_INIT: [u32; 8] = [
    0x6a09e667, // √2
    0xbb67ae85, // √3
    0x3c6ef372, // √5
    0xa54ff53a, // √7
    0x510e527f, // √11
    0x9b05688c, // √13
    0x1f83d9ab, // √17
    0x5be0cd19, // √19
];

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, // ∛2,  ∛3,  ∛5,  ∛7
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, // ∛11, ∛13, ∛17, ∛19
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, // ∛23, ∛29, ∛31, ∛37
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, // ∛41, ∛43, ∛47, ∛53
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, // ∛59, ∛61, ∛67, ∛71
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, // ∛73, ∛79, ∛83, ∛89
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, // ∛97, ∛101,∛103,∛107
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, // ∛109,∛113,∛127,∛131
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, // ∛137,∛139,∛149,∛151
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, // ∛157,∛163,∛167,∛173
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, // ∛179,∛181,∛191,∛193
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, // ∛197,∛199,∛211,∛223
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, // ∛227,∛229,∛233,∛239
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, // ∛241,∛251,∛257,∛263
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, // ∛269,∛271,∛277,∛281
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, // ∛283,∛293,∛307,∛311
];

#[inline]
fn rotr(x: u32, n: u32) -> u32 {
    // Right shift by n, then OR with left shift by (32-n)
    // This "catches" the bits that would fall off
    (x >> n) | (x << (32 - n))
}

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    // (x AND y): keeps y bits where x is 1
    // (!x AND z): keeps z bits where x is 0
    // XOR combines them (they never overlap)
    (x & y) ^ (!x & z)
}

#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    // Each AND finds positions where 2 specific inputs are both 1
    // XOR combines them all
    (x & y) ^ (x & z) ^ (y & z)
}

/// Big Sigma 0 - used on variable 'a' in compression
/// Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x)
#[inline]
fn big_sigma0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

/// Big Sigma 1 - used on variable 'e' in compression
/// Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x)
#[inline]
fn big_sigma1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

/// Small sigma 0 - used in message schedule
/// σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
///
/// Note: SHR is shift (not rotate) - zeros fill in from left
#[inline]
fn small_sigma0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

/// Small sigma 1 - used in message schedule
/// σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
#[inline]
fn small_sigma1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_len: u64,
}

impl Sha256 {
    pub fn new() -> Self {
        Sha256 {
            state: H_INIT,
            buffer: [0u8; 64],
            buffer_len: 0,
            total_len: 0,
        }
    }

    fn create_message_schedule(block: &[u8]) -> [u32; 64] {
        let mut w = [0u32; 64];

        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        for i in 16..64 {
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

        for i in 0..64 {
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

impl Sha256 {
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        let mut offset = 0;
        
        if self.buffer_len > 0 {
            let needed = 64 - self.buffer_len;
            
            if data.len() >= needed {
                self.buffer[self.buffer_len..64].copy_from_slice(&data[..needed]);
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
        
        while offset + 64 <= data.len() {
            self.process_block(&data[offset..offset + 64]);
            offset += 64;
        }
        
        if offset < data.len() {
            let remaining = data.len() - offset;
            self.buffer[..remaining].copy_from_slice(&data[offset..]);
            self.buffer_len = remaining;
        }
    }
}

impl Sha256 {
    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.total_len * 8;
        
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        
        if self.buffer_len > 56 {
            for i in self.buffer_len..64 {
                self.buffer[i] = 0;
            }
            self.process_block(&self.buffer.clone());
            self.buffer_len = 0;
        }
        
        for i in self.buffer_len..56 {
            self.buffer[i] = 0;
        }
        
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        
        self.process_block(&self.buffer.clone());
        
        let mut result = [0u8; 32];
        for (i, word) in self.state.iter().enumerate() {
            result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        
        result
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}