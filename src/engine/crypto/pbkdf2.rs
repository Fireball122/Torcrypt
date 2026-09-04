// src/engine/crypto/pbkdf2.rs — RFC 2898 / PKCS #5 Password-Based Key Derivation Function 2
// Pure-Rust implementation with zero dependencies, supporting HMAC-SHA1 and HMAC-SHA256.

use super::hmac::{hmac_sha1, hmac_sha256};

/// Derives key material using PBKDF2-HMAC-SHA1 into `output`.
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
    let mut block_idx = 1u32;
    let mut offset = 0;

    while offset < output.len() {
        // U_1 = HMAC(password, salt || INT_32_BE(block_idx))
        let mut salt_and_idx = Vec::with_capacity(salt.len() + 4);
        salt_and_idx.extend_from_slice(salt);
        salt_and_idx.extend_from_slice(&block_idx.to_be_bytes());

        let mut u = hmac_sha1(password, &salt_and_idx);
        let mut t = u;

        // U_2..U_c = HMAC(password, U_{k-1})
        for _ in 1..rounds {
            u = hmac_sha1(password, &u);
            for k in 0..20 {
                t[k] ^= u[k];
            }
        }

        let copy_len = (output.len() - offset).min(20);
        output[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
        block_idx += 1;
    }
}

/// Derives key material using PBKDF2-HMAC-SHA256 into `output`.
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], rounds: u32, output: &mut [u8]) {
    let mut block_idx = 1u32;
    let mut offset = 0;

    while offset < output.len() {
        let mut salt_and_idx = Vec::with_capacity(salt.len() + 4);
        salt_and_idx.extend_from_slice(salt);
        salt_and_idx.extend_from_slice(&block_idx.to_be_bytes());

        let mut u = hmac_sha256(password, &salt_and_idx);
        let mut t = u;

        for _ in 1..rounds {
            u = hmac_sha256(password, &u);
            for k in 0..32 {
                t[k] ^= u[k];
            }
        }

        let copy_len = (output.len() - offset).min(32);
        output[offset..offset + copy_len].copy_from_slice(&t[..copy_len]);
        offset += copy_len;
        block_idx += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_sha1_rfc6070() {
        // RFC 6070 Test Vector 2:
        // P = "password", S = "salt", c = 2, dkLen = 20
        let mut dk = [0u8; 20];
        pbkdf2_hmac_sha1(b"password", b"salt", 2, &mut dk);
        let expected = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e,
            0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        assert_eq!(dk, expected);
    }
}
