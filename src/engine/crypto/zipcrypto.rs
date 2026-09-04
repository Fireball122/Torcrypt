// src/engine/crypto/zipcrypto.rs — PKWARE Traditional ZipCrypto Stream Cipher
// Standard implementation for ZIP password recovery and verification.

use super::crc32::crc32_update;

#[derive(Debug, Clone, Copy)]
pub struct ZipCryptoState {
    pub key0: u32,
    pub key1: u32,
    pub key2: u32,
}

impl ZipCryptoState {
    pub fn new(password: &[u8]) -> Self {
        let mut state = Self {
            key0: 0x12345678,
            key1: 0x23456789,
            key2: 0x34567890,
        };
        for &b in password {
            state.update(b);
        }
        state
    }

    #[inline(always)]
    pub fn update(&mut self, plaintext_byte: u8) {
        self.key0 = crc32_update(self.key0, plaintext_byte);
        self.key1 = self.key1.wrapping_add(self.key0 & 0xFF).wrapping_mul(134775813).wrapping_add(1);
        self.key2 = crc32_update(self.key2, (self.key1 >> 24) as u8);
    }

    #[inline(always)]
    pub fn decrypt_byte(&mut self, cipher_byte: u8) -> u8 {
        let temp = (self.key2 | 2) as u16;
        let keystream = ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
        let plain_byte = cipher_byte ^ keystream;
        self.update(plain_byte);
        plain_byte
    }

    /// Tests a candidate password against the 12-byte encryption header.
    /// Returns true if the 12th byte matches the check byte.
    pub fn verify_header(password: &[u8], header: &[u8; 12], check_byte: u8) -> bool {
        let mut state = Self::new(password);
        let mut last_decrypted = 0u8;
        for &b in header {
            last_decrypted = state.decrypt_byte(b);
        }
        last_decrypted == check_byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zipcrypto_roundtrip() {
        let password = b"testpassword";
        let mut enc_state = ZipCryptoState::new(password);
        let plaintext = b"Hello, World!";
        let mut ciphertext = Vec::new();

        // Encrypt
        for &b in plaintext {
            let temp = (enc_state.key2 | 2) as u16;
            let keystream = ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
            let c = b ^ keystream;
            enc_state.update(b);
            ciphertext.push(c);
        }

        // Decrypt
        let mut dec_state = ZipCryptoState::new(password);
        let mut decrypted = Vec::new();
        for &c in &ciphertext {
            decrypted.push(dec_state.decrypt_byte(c));
        }

        assert_eq!(&decrypted, plaintext);
    }
}
