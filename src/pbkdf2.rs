use crate::sha512;


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

pub fn pbkdf2_hmac_sha512(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(output_len);
    let mut block_num: u32 = 1;
    
    while output.len() < output_len {
        // U1 = HMAC(password, salt || block_number_as_big_endian_u32)
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block_num.to_be_bytes());
        
        let mut u = hmac_sha512(password, &salt_block);
        let mut result = u;
        
        // U2, U3, ..., U_iterations
        for _ in 1..iterations {
            u = hmac_sha512(password, &u);
            // XOR into result
            for (r, ui) in result.iter_mut().zip(u.iter()) {
                *r ^= ui;
            }
        }
        
        output.extend_from_slice(&result);
        block_num += 1;
    }
    
    output.truncate(output_len);
    output
}