// src/engine/crypto/hmac.rs — RFC 2104 Hash-based Message Authentication Code (HMAC)
// Pure-Rust implementation with zero dependencies for SHA-1 and SHA-256.

use super::sha1::sha1;
use super::sha256::sha256;

const BLOCK_SIZE: usize = 64;

/// Computes HMAC-SHA1(key, data) -> [u8; 20]
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = sha1(key);
        key_block[..20].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut k_ipad = [0u8; BLOCK_SIZE];
    let mut k_opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5C;
    }

    // Inner hash: H(k_ipad || data)
    let mut inner_msg = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_msg.extend_from_slice(&k_ipad);
    inner_msg.extend_from_slice(data);
    let inner_hash = sha1(&inner_msg);

    // Outer hash: H(k_opad || inner_hash)
    let mut outer_msg = [0u8; BLOCK_SIZE + 20];
    outer_msg[..BLOCK_SIZE].copy_from_slice(&k_opad);
    outer_msg[BLOCK_SIZE..].copy_from_slice(&inner_hash);
    sha1(&outer_msg)
}

/// Computes HMAC-SHA256(key, data) -> [u8; 32]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hash = sha256(key);
        key_block[..32].copy_from_slice(&hash);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut k_ipad = [0u8; BLOCK_SIZE];
    let mut k_opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        k_ipad[i] = key_block[i] ^ 0x36;
        k_opad[i] = key_block[i] ^ 0x5C;
    }

    let mut inner_msg = Vec::with_capacity(BLOCK_SIZE + data.len());
    inner_msg.extend_from_slice(&k_ipad);
    inner_msg.extend_from_slice(data);
    let inner_hash = sha256(&inner_msg);

    let mut outer_msg = [0u8; BLOCK_SIZE + 32];
    outer_msg[..BLOCK_SIZE].copy_from_slice(&k_opad);
    outer_msg[BLOCK_SIZE..].copy_from_slice(&inner_hash);
    sha256(&outer_msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha1_rfc2202() {
        // RFC 2202 Test Case 1:
        // Key: 0x0b repeated 20 times
        // Data: "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha1(&key, data);
        let expected = [
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
            0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231() {
        // RFC 4231 Test Case 1:
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = hmac_sha256(&key, data);
        let hex_mac: String = mac.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex_mac, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
}
