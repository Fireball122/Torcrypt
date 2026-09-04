// src/engine/crypto/rc4.rs — Rivest Cipher 4 (RC4 / ARC4) Stream Cipher
// Pure-Rust implementation with zero dependencies, used for PDF Standard Encryption Handler.

#[derive(Debug, Clone)]
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        assert!(!key.is_empty() && key.len() <= 256, "RC4 key length must be 1..=256 bytes");
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    #[inline(always)]
    pub fn next_byte(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.s[self.i as usize]);
        self.s.swap(self.i as usize, self.j as usize);
        let t = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
        self.s[t as usize]
    }

    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b ^= self.next_byte();
        }
    }
}

pub fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut rc4 = Rc4::new(key);
    let mut out = data.to_vec();
    rc4.apply_keystream(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_rfc6229() {
        // Test vector from RFC 6229: Key = "Key", Plaintext = "Plaintext"
        let key = b"Key";
        let plaintext = b"Plaintext";
        let ciphertext = rc4_crypt(key, plaintext);
        assert_eq!(ciphertext, vec![0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);

        // Symmetric round-trip
        let roundtrip = rc4_crypt(key, &ciphertext);
        assert_eq!(roundtrip, plaintext);
    }
}
