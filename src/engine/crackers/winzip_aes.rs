// src/engine/crackers/winzip_aes.rs — Native In-Process WinZip AES-128/256 Password Cracker
// Authenticates candidates using PBKDF2-HMAC-SHA1 (1,000 rounds) against 2-byte verification codes.

use crate::engine::crypto::pbkdf2_hmac_sha1;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WinZipAesTarget {
    pub file_path:     String,
    pub aes_bits:      u16,     // 128 or 256
    pub salt:          Vec<u8>, // 8 bytes (128-bit) or 16 bytes (256-bit)
    pub verifier:      [u8; 2], // 2-byte password verification code
    pub key_len:       usize,   // 16 or 32
}

impl WinZipAesTarget {
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).ok()?;
        if &magic != b"PK\x03\x04" {
            return None;
        }

        let mut hdr = [0u8; 26];
        file.read_exact(&mut hdr).ok()?;

        let flags = u16::from_le_bytes([hdr[2], hdr[3]]);
        let method = u16::from_le_bytes([hdr[4], hdr[5]]);
        let fn_len = u16::from_le_bytes([hdr[22], hdr[23]]) as usize;
        let ef_len = u16::from_le_bytes([hdr[24], hdr[25]]) as usize;

        if (flags & 0x0001) == 0 {
            return None; // Unencrypted
        }

        // Skip filename
        file.seek(SeekFrom::Current(fn_len as i64)).ok()?;

        // Scan extra field for 0x9901 (WinZip AES)
        let mut ef_buf = vec![0u8; ef_len];
        if ef_len > 0 {
            file.read_exact(&mut ef_buf).ok()?;
        }

        let mut is_winzip = method == 99;
        let mut aes_bits = 256u16;

        let mut pos = 0;
        while pos + 4 <= ef_buf.len() {
            let id = u16::from_le_bytes([ef_buf[pos], ef_buf[pos + 1]]);
            let sz = u16::from_le_bytes([ef_buf[pos + 2], ef_buf[pos + 3]]) as usize;
            if id == 0x9901 && pos + 4 + sz <= ef_buf.len() && sz >= 7 {
                is_winzip = true;
                let strength = ef_buf[pos + 8];
                aes_bits = match strength {
                    0x01 => 128,
                    0x02 => 192,
                    _    => 256,
                };
                break;
            }
            pos += 4 + sz;
        }

        if !is_winzip {
            return None;
        }

        let key_len = if aes_bits == 128 { 16 } else { 32 };
        let salt_len = if aes_bits == 128 { 8 } else { 16 };

        let mut salt = vec![0u8; salt_len];
        file.read_exact(&mut salt).ok()?;

        let mut verifier = [0u8; 2];
        file.read_exact(&mut verifier).ok()?;

        Some(Self {
            file_path: path.to_string_lossy().to_string(),
            aes_bits,
            salt,
            verifier,
            key_len,
        })
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        // Output length: key_len (AES) + key_len (HMAC) + 2 (Verifier)
        let dk_len = self.key_len * 2 + 2;
        let mut dk = vec![0u8; dk_len];
        pbkdf2_hmac_sha1(candidate.as_bytes(), &self.salt, 1000, &mut dk);

        // Last 2 bytes must match stored password verification code
        dk[self.key_len * 2] == self.verifier[0] && dk[self.key_len * 2 + 1] == self.verifier[1]
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
    fn test_winzip_aes_verification_roundtrip() {
        let password = "SecretPassword!2026";
        let salt = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        // Derive expected verifier
        let key_len = 32; // AES-256
        let mut dk = [0u8; 66];
        pbkdf2_hmac_sha1(password.as_bytes(), &salt, 1000, &mut dk);
        let verifier = [dk[64], dk[65]];

        let target = WinZipAesTarget {
            file_path: "test.zip".into(),
            aes_bits: 256,
            salt: salt.to_vec(),
            verifier,
            key_len: 32,
        };

        assert!(target.verify("SecretPassword!2026"));
        assert!(!target.verify("WrongPassword"));
    }
}
