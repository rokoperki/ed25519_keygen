use crate::field_element::FieldElement;
use crate::sha512::sha512;

// d = -121665/121666 mod p (little-endian)
const D_BYTES: [u8; 32] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

// Base point G x-coordinate (little-endian)
const GX_BYTES: [u8; 32] = [
    0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
    0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
];

// Base point G y-coordinate = 4/5 mod p (little-endian)
const GY_BYTES: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

// A point on the twisted Edwards curve -x² + y² = 1 + d·x²·y²
// Using extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, T=XY/Z
#[derive(Clone, Copy)]
pub struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    // Identity element: (0, 1)
    pub fn identity() -> Self {
        Point {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::one(),
            t: FieldElement::zero(),
        }
    }

    // Base point G
    pub fn base_point() -> Self {
        let x = FieldElement::from_bytes(&GX_BYTES);
        let y = FieldElement::from_bytes(&GY_BYTES);
        let z = FieldElement::one();
        let t = x.mul(&y);
        Point { x, y, z, t }
    }

    // Unified point addition using add-2008-hwcd formulas
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#addition-add-2008-hwcd
    pub fn add(&self, other: &Self) -> Self {
        let d = FieldElement::from_bytes(&D_BYTES);
        let two = FieldElement::from_bytes(&{
            let mut b = [0u8; 32];
            b[0] = 2;
            b
        });

        let a = (self.y.sub(&self.x)).mul(&(other.y.sub(&other.x)));
        let b = (self.y.add(&self.x)).mul(&(other.y.add(&other.x)));
        let c = self.t.mul(&two.mul(&d)).mul(&other.t);
        let dd = self.z.mul(&two).mul(&other.z);
        let e = b.sub(&a);
        let f = dd.sub(&c);
        let g = dd.add(&c);
        let h = b.add(&a);

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    // Dedicated point doubling using dbl-2008-hwcd formulas (a = -1)
    // https://hyperelliptic.org/EFD/g1p/auto-twisted-extended.html#doubling-dbl-2008-hwcd
    pub fn double(&self) -> Self {
        let aa = self.x.square(); // A = X^2
        let b = self.y.square(); // B = Y^2
        let c = self.z.square().add(&self.z.square()); // C = 2*Z^2
        let d = aa.neg(); // D = a*A = -A  (a = -1)
        let e = self.x.add(&self.y).square().sub(&aa).sub(&b); // E = (X+Y)^2 - A - B
        let g = d.add(&b); // G = D + B
        let f = g.sub(&c); // F = G - C
        let h = d.sub(&b); // H = D - B

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    // Scalar multiplication: scalar × self using double-and-add
    // scalar is a 32-byte little-endian integer
    pub fn scalar_mul(&self, scalar: &[u8; 32]) -> Self {
        let mut result = Point::identity();
        let mut addend = *self;

        for byte in scalar.iter() {
            for bit in 0..8 {
                if (byte >> bit) & 1 == 1 {
                    result = result.add(&addend);
                }
                addend = addend.double();
            }
        }

        result
    }

    // Encode point as 32 bytes: y coordinate (LE) with the sign of x in the top bit
    pub fn encode(&self) -> [u8; 32] {
        // Convert from projective to affine: x = X/Z, y = Y/Z
        let z_inv = self.z.invert();
        let x = self.x.mul(&z_inv);
        let y = self.y.mul(&z_inv);

        let mut bytes = y.to_bytes();
        // Set top bit to the low bit (sign) of x
        let x_bytes = x.to_bytes();
        bytes[31] |= (x_bytes[0] & 1) << 7;

        bytes
    }
}

// Derive Ed25519 public key from a 32-byte private seed
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    // 1. Hash the seed with SHA-512
    let h = sha512(seed);

    // 2. Take the first 32 bytes as the scalar and clamp it
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&h[..32]);
    scalar[0] &= 248; // clear lowest 3 bits  (ensure scalar is multiple of cofactor 8)
    scalar[31] &= 127; // clear bit 255
    scalar[31] |= 64; // set bit 254          (ensure scalar is in safe range)

    // 3. Multiply base point G by the scalar
    Point::base_point().scalar_mul(&scalar).encode()
}

// Base58 encoding (no checksum — Solana addresses are raw 32-byte public keys)
pub fn base58_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    let mut n = bytes.to_vec();
    let mut result = Vec::new();

    // Count leading zero bytes (map to '1')
    let leading_zeros = n.iter().take_while(|&&b| b == 0).count();

    // Repeated division by 58
    while n.iter().any(|&b| b != 0) {
        let mut carry = 0u32;
        for byte in n.iter_mut() {
            let val = carry * 256 + *byte as u32;
            *byte = (val / 58) as u8;
            carry = val % 58;
        }
        result.push(ALPHABET[carry as usize]);
    }

    // Add '1' for each leading zero byte
    for _ in 0..leading_zeros {
        result.push(b'1');
    }

    result.reverse();
    String::from_utf8(result).unwrap()
}
