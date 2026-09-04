// src/engine/crackers/seven_zip.rs — Native In-Process 7-Zip AES-256 Password Cracker
// Authenticates candidates using 7z SHA-256 KDF (2^cycles rounds) + AES-256-CBC header decryption.

use crate::engine::crypto::{aes_cbc_decrypt, sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SevenZipTarget {
    pub file_path:         String,
    pub num_cycles_power:  u8,
    pub salt:              Vec<u8>,
    pub iv:                [u8; 16],
    pub encrypted_sample:  Vec<u8>,
}

impl SevenZipTarget {
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 32 {
            return None;
        }

        let mut sig_hdr = [0u8; 32];
        file.read_exact(&mut sig_hdr).ok()?;
        if sig_hdr[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return None;
        }

        let next_header_offset = u64::from_le_bytes([
            sig_hdr[12], sig_hdr[13], sig_hdr[14], sig_hdr[15],
            sig_hdr[16], sig_hdr[17], sig_hdr[18], sig_hdr[19],
        ]);
        let next_header_size = u64::from_le_bytes([
            sig_hdr[20], sig_hdr[21], sig_hdr[22], sig_hdr[23],
            sig_hdr[24], sig_hdr[25], sig_hdr[26], sig_hdr[27],
        ]);

        if next_header_offset == 0 || (32 + next_header_offset) >= file_len {
            return None;
        }

        let actual_pos = 32 + next_header_offset;
        file.seek(SeekFrom::Start(actual_pos)).ok()?;

        let sample_len = (next_header_size.min(64)) as usize;
        let mut sample_buf = vec![0u8; sample_len];
        file.read_exact(&mut sample_buf).ok()?;

        let mut salt = vec![0u8; 16];
        let mut iv = [0u8; 16];

        if sample_buf.len() >= 32 {
            salt.copy_from_slice(&sample_buf[0..16]);
            iv.copy_from_slice(&sample_buf[16..32]);
        }

        Some(Self {
            file_path: path.to_string_lossy().to_string(),
            num_cycles_power: 19, // 7z standard default: 2^19 = 524,288 cycles
            salt,
            iv,
            encrypted_sample: sample_buf,
        })
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        if self.encrypted_sample.len() < 16 {
            return false;
        }

        // 1. Build UTF-16LE password bytes + salt
        let mut key_buf = Vec::with_capacity(self.salt.len() + candidate.len() * 2);
        key_buf.extend_from_slice(&self.salt);
        for c in candidate.encode_utf16() {
            key_buf.extend_from_slice(&c.to_le_bytes());
        }

        // 2. Run 7z SHA-256 KDF loop
        // 7z SHA-256 KDF: 2^num_cycles_power rounds (typical archives: 2^19 = 524288)
        let rounds = 1u64 << (self.num_cycles_power.min(30)); // respect the archive KDF; cap at 2^30 to avoid overflow
        let mut hash = sha256(&key_buf);
        for _ in 1..rounds {
            let mut round_buf = [0u8; 40];
            round_buf[..32].copy_from_slice(&hash);
            hash = sha256(&round_buf[..32]);
        }

        // 3. Decrypt first 16 bytes of encrypted header
        let dec = aes_cbc_decrypt(&hash, &self.iv, &self.encrypted_sample[..16]);
        if let Some(&first_byte) = dec.first() {
            // Standard 7-Zip header markers:
            // 0x17 = kEncodedHeader
            // 0x01 = kHeader
            first_byte == 0x17 || first_byte == 0x01
        } else {
            false
        }
    }

    pub fn test_batch(&self, candidates: &[String]) -> Option<String> {
        for cand in candidates {
            if self.verify(cand) {
                return Some(cand.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seven_zip_target_structure() {
        let target = SevenZipTarget {
            file_path: "test.7z".into(),
            num_cycles_power: 8,
            salt: vec![0u8; 16],
            iv: [0u8; 16],
            encrypted_sample: vec![0x17; 32],
        };
        // Verify method executes safely
        let _ = target.verify("testpassword");
    }
}
