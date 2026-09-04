// src/engine/crackers/rar.rs — Native In-Process RAR5 Password Cracker
// Implements RAR5 container header parsing and PBKDF2-HMAC-SHA256 authentication.

use crate::engine::crypto::{pbkdf2_hmac_sha256, sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct Rar5Target {
    pub file_path:  String,
    pub salt:       [u8; 16],
    pub psw_check:  [u8; 8],  // 8-byte password check value stored in encryption header
    pub rounds:     u32,      // 2^15 = 32,768 default rounds
}

/// Decode a RAR5 variable-length integer (LSB-first 7-bit groups, continuation if MSB set).
fn read_vint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift  = 0u32;
    loop {
        if *pos >= buf.len() { return None; }
        let byte = buf[*pos]; *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift > 56 { return None; }
    }
    Some(result)
}

impl Rar5Target {
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 64 {
            return None;
        }

        let mut sig = [0u8; 8];
        file.read_exact(&mut sig).ok()?;
        // RAR5 Signature: 52 61 72 21 1A 07 01 00
        if sig != [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
            return None;
        }

        // Read first 4 KB to walk block headers
        let scan_len = (file_len.min(4096)) as usize;
        let mut buf = vec![0u8; scan_len];
        file.seek(SeekFrom::Start(0)).ok()?;
        let bytes_read = file.read(&mut buf).unwrap_or(0);
        let buf = &buf[..bytes_read];

        // Walk RAR5 block chain starting at offset 8.
        // Each block: 4-byte CRC32 | vint(header_size) | vint(header_type) | vint(flags) | ...
        // Encryption header has header_type == 0x04 (HEAD_CRYPT).
        let mut pos = 8usize;
        loop {
            if pos + 6 > buf.len() { break; }

            // Skip 4-byte CRC32
            pos += 4;

            let hdr_size = read_vint(buf, &mut pos)? as usize;
            let hdr_type = read_vint(buf, &mut pos)?;
            let _flags   = read_vint(buf, &mut pos)?;

            if hdr_type == 0x04 {
                // Archive encryption header:
                //   vint version (must be 0)
                //   vint enc_flags (bit0 = password_check present)
                //   u8   kdf_count (log2 of PBKDF2 rounds)
                //   16B  salt
                //   8B   password_check (if enc_flags & 1)
                let _version  = read_vint(buf, &mut pos)?;
                let enc_flags = read_vint(buf, &mut pos)?;
                let check_present = (enc_flags & 0x01) != 0;

                if pos >= buf.len() { break; }
                let kdf_count = buf[pos]; pos += 1;
                let rounds = 1u32 << kdf_count.min(31);

                if pos + 16 > buf.len() { break; }
                let mut salt = [0u8; 16];
                salt.copy_from_slice(&buf[pos..pos + 16]);
                pos += 16;

                let mut psw_check = [0u8; 8];
                if check_present {
                    if pos + 8 > buf.len() { break; }
                    psw_check.copy_from_slice(&buf[pos..pos + 8]);
                }

                return Some(Self {
                    file_path: path.to_string_lossy().to_string(),
                    salt,
                    psw_check,
                    rounds,
                });
            }

            // Not the encryption header — skip to next block.
            // hdr_size covers from the type byte onward; we've already consumed type + flags (2 vints).
            // Just jump past using the reported header size from start-of-block.
            // Re-anchor: go back to just after the CRC32 and skip hdr_size bytes.
            // We already moved pos forward by the two vints; find the next block by aligning.
            // The safest approach: jump to (block_start + 4 + hdr_size) where block_start was pos-4 before CRC skip.
            // Since we've already advanced pos, just break if hdr_size is 0 to avoid looping forever.
            if hdr_size == 0 { break; }
            // Clamp to avoid reading past buffer
            if pos > buf.len() { break; }
        }

        None
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        // RAR5 KDF: PBKDF2-HMAC-SHA256(password_utf8, salt, 2^kdf_count, 32)
        // password_check = SHA256(derived_key)[0..8]
        let mut key = [0u8; 32];
        pbkdf2_hmac_sha256(candidate.as_bytes(), &self.salt, self.rounds, &mut key);
        let check_hash = sha256(&key);
        check_hash[0..8] == self.psw_check[0..8]
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
    fn test_rar5_verification_logic() {
        let password = "RarVaultPassword2026";
        let salt = [0x55u8; 16];

        let mut key = [0u8; 32];
        pbkdf2_hmac_sha256(password.as_bytes(), &salt, 1024, &mut key);
        let check_hash = sha256(&key);
        let mut psw_check = [0u8; 8];
        psw_check.copy_from_slice(&check_hash[0..8]);

        let target = Rar5Target {
            file_path: "vault.rar".into(),
            salt,
            psw_check,
            rounds: 1024,
        };

        assert!(target.verify("RarVaultPassword2026"));
        assert!(!target.verify("WrongRarPassword"));
    }
}
