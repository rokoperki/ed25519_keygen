// What you need to implement:
#[derive(Debug)]
pub struct Entropy {
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum EntropyError {
    GenerationError,
    WrongSize,
}

impl Entropy {
    pub fn generate(num_bytes: usize) -> Self {
        match num_bytes {
            16 | 20 | 24 | 28 | 32 => {
                let mut bytes = vec![0u8; num_bytes];
                getrandom::getrandom(&mut bytes).expect("Failed to generate entropy");
                Entropy { bytes }
            }
            _ => Err(EntropyError::WrongSize).unwrap(),
        }
    }

    pub fn display_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}