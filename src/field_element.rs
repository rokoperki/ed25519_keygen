#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FieldElement {
    // Five 51-bit limbs in radix 2^51.
    // Value = limbs[0] + limbs[1]*2^51 + limbs[2]*2^102 + limbs[3]*2^153 + limbs[4]*2^204
    limbs: [u64; 5],
}

const MASK51: u64 = (1u64 << 51) - 1;

impl FieldElement {
    pub fn zero() -> Self {
        FieldElement { limbs: [0; 5] }
    }

    pub fn one() -> Self {
        FieldElement { limbs: [1, 0, 0, 0, 0] }
    }

    // Decode from 32-byte little-endian
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |b: &[u8]| -> u64 {
            u64::from_le_bytes(b.try_into().unwrap())
        };
        let mut limbs = [0u64; 5];
        limbs[0] =  load8(&bytes[0..8])          & MASK51;  // bits   0-50
        limbs[1] = (load8(&bytes[6..14])  >>  3) & MASK51;  // bits  51-101
        limbs[2] = (load8(&bytes[12..20]) >>  6) & MASK51;  // bits 102-152
        limbs[3] = (load8(&bytes[19..27]) >>  1) & MASK51;  // bits 153-203
        limbs[4] = (load8(&bytes[24..32]) >> 12) & MASK51;  // bits 204-254
        FieldElement { limbs }
    }

    // Encode as 32-byte little-endian
    pub fn to_bytes(&self) -> [u8; 32] {
        let fe = self.reduce();
        let l = fe.limbs;
        let mut b = [0u8; 32];

        b[0]  =  l[0]        as u8;
        b[1]  = (l[0] >>  8) as u8;
        b[2]  = (l[0] >> 16) as u8;
        b[3]  = (l[0] >> 24) as u8;
        b[4]  = (l[0] >> 32) as u8;
        b[5]  = (l[0] >> 40) as u8;
        b[6]  = ((l[0] >> 48) | (l[1] << 3))  as u8;
        b[7]  = (l[1] >>  5) as u8;
        b[8]  = (l[1] >> 13) as u8;
        b[9]  = (l[1] >> 21) as u8;
        b[10] = (l[1] >> 29) as u8;
        b[11] = (l[1] >> 37) as u8;
        b[12] = ((l[1] >> 45) | (l[2] << 6))  as u8;
        b[13] = (l[2] >>  2) as u8;
        b[14] = (l[2] >> 10) as u8;
        b[15] = (l[2] >> 18) as u8;
        b[16] = (l[2] >> 26) as u8;
        b[17] = (l[2] >> 34) as u8;
        b[18] = (l[2] >> 42) as u8;
        b[19] = ((l[2] >> 50) | (l[3] << 1))  as u8;
        b[20] = (l[3] >>  7) as u8;
        b[21] = (l[3] >> 15) as u8;
        b[22] = (l[3] >> 23) as u8;
        b[23] = (l[3] >> 31) as u8;
        b[24] = (l[3] >> 39) as u8;
        b[25] = ((l[3] >> 47) | (l[4] << 4))  as u8;
        b[26] = (l[4] >>  4) as u8;
        b[27] = (l[4] >> 12) as u8;
        b[28] = (l[4] >> 20) as u8;
        b[29] = (l[4] >> 28) as u8;
        b[30] = (l[4] >> 36) as u8;
        b[31] = (l[4] >> 44) as u8;

        b
    }

    // addition: (a + b) mod p
    pub fn add(&self, other: &Self) -> Self {
        let mut limbs = [0u64; 5];
        for i in 0..5 {
            limbs[i] = self.limbs[i] + other.limbs[i];
        }

        // Propagate carries through limbs[0..4]
        for i in 0..4 {
            let carry = limbs[i] >> 51;
            limbs[i] &= MASK51;
            limbs[i + 1] += carry;
        }

        // Overflow from limb[4] represents 2^255.
        // Since p = 2^255 - 19, we have 2^255 ≡ 19 (mod p).
        let carry = limbs[4] >> 51;
        limbs[4] &= MASK51;
        limbs[0] += carry * 19;

        // One final carry from limb[0] in case the *19 pushed it over
        let carry = limbs[0] >> 51;
        limbs[0] &= MASK51;
        limbs[1] += carry;

        FieldElement { limbs }
    }

    // subtraction: (a - b) mod p
    pub fn sub(&self, other: &Self) -> Self {
        let mut limbs = [0u64; 5];
        // Add 2p before subtracting to guarantee non-negative limbs.
        // 2p expressed limb-wise: [2*(2^51-19), 2*MASK51, 2*MASK51, 2*MASK51, 2*MASK51]
        limbs[0] = self.limbs[0] + (2 * (1u64 << 51) - 38) - other.limbs[0];
        for i in 1..5 {
            limbs[i] = self.limbs[i] + (2 * MASK51) - other.limbs[i];
        }

        for i in 0..4 {
            let carry = limbs[i] >> 51;
            limbs[i] &= MASK51;
            limbs[i + 1] += carry;
        }
        let carry = limbs[4] >> 51;
        limbs[4] &= MASK51;
        limbs[0] += carry * 19;
        let carry = limbs[0] >> 51;
        limbs[0] &= MASK51;
        limbs[1] += carry;

        FieldElement { limbs }
    }

    // negation: -a mod p
    pub fn neg(&self) -> Self {
        FieldElement::zero().sub(self)
    }

    // multiplication: (a * b) mod p
    pub fn mul(&self, other: &Self) -> Self {
        let a = &self.limbs;
        let b = &other.limbs;

        // Schoolbook multiplication using u128 to avoid overflow (each limb ≤ 2^51,
        // so products fit in 102 bits < 128 bits).
        let mut c = [0u128; 9];
        for i in 0..5 {
            for j in 0..5 {
                c[i + j] += (a[i] as u128) * (b[j] as u128);
            }
        }

        // Reduce: 2^255 ≡ 19 (mod p), so c[k] for k >= 5 contributes c[k]*19 to c[k-5].
        for k in 5..9 {
            c[k - 5] += c[k] * 19;
        }

        // Carry propagate from u128 down to u64 limbs
        let mask = MASK51 as u128;
        let mut limbs = [0u64; 5];
        for i in 0..4 {
            let carry = c[i] >> 51;
            limbs[i] = (c[i] & mask) as u64;
            c[i + 1] += carry;
        }
        let carry = c[4] >> 51;
        limbs[4] = (c[4] & mask) as u64;
        limbs[0] += (carry * 19) as u64;
        let carry = limbs[0] >> 51;
        limbs[0] &= MASK51;
        limbs[1] += carry;

        FieldElement { limbs }
    }

    // squaring: a^2 mod p
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    // modular inverse: a^(p-2) mod p via Fermat's little theorem
    // Uses the standard addition chain for 2^255 - 21 (= p - 2)
    pub fn invert(&self) -> Self {
        let z1    = *self;
        let z2    = z1.square();
        let z4    = z2.square();
        let z8    = z4.square();
        let z9    = z8.mul(&z1);
        let z11   = z9.mul(&z2);
        let z22   = z11.square();
        let z_5_0 = z22.mul(&z9);                                          // z^(2^5  - 1)

        let z_10_5  = (0..5).fold(z_5_0,  |a, _| a.square());
        let z_10_0  = z_10_5.mul(&z_5_0);                                  // z^(2^10 - 1)

        let z_20_10 = (0..10).fold(z_10_0, |a, _| a.square());
        let z_20_0  = z_20_10.mul(&z_10_0);                                // z^(2^20 - 1)

        let z_40_20 = (0..20).fold(z_20_0, |a, _| a.square());
        let z_40_0  = z_40_20.mul(&z_20_0);                                // z^(2^40 - 1)

        let z_50_10 = (0..10).fold(z_40_0, |a, _| a.square());
        let z_50_0  = z_50_10.mul(&z_10_0);                                // z^(2^50 - 1)

        let z_100_50 = (0..50).fold(z_50_0,  |a, _| a.square());
        let z_100_0  = z_100_50.mul(&z_50_0);                              // z^(2^100 - 1)

        let z_200_100 = (0..100).fold(z_100_0, |a, _| a.square());
        let z_200_0   = z_200_100.mul(&z_100_0);                           // z^(2^200 - 1)

        let z_250_50 = (0..50).fold(z_200_0, |a, _| a.square());
        let z_250_0  = z_250_50.mul(&z_50_0);                              // z^(2^250 - 1)

        // z^(2^255-32) then *z^11 = z^(2^255-21) = z^(p-2)
        let z_255_5 = (0..5).fold(z_250_0, |a, _| a.square());
        z_255_5.mul(&z11)
    }

    // Reduce to canonical form in [0, p)
    fn reduce(&self) -> Self {
        let mut limbs = self.limbs;

        for i in 0..4 {
            let carry = limbs[i] >> 51;
            limbs[i] &= MASK51;
            limbs[i + 1] += carry;
        }
        let carry = limbs[4] >> 51;
        limbs[4] &= MASK51;
        limbs[0] += carry * 19;
        let carry = limbs[0] >> 51;
        limbs[0] &= MASK51;
        limbs[1] += carry;

        // After carry propagation the value is in [0, 2p).
        // Add 19: if the result overflows limb[4], the original was >= p.
        let mut t = limbs;
        t[0] += 19;
        for i in 0..4 {
            let carry = t[i] >> 51;
            t[i] &= MASK51;
            t[i + 1] += carry;
        }
        let overflow = t[4] >> 51;
        t[4] &= MASK51;

        if overflow == 1 { FieldElement { limbs: t } } else { FieldElement { limbs } }
    }
}
