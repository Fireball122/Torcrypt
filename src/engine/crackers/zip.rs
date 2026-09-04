// src/engine/crackers/zip.rs — Real In-Process ZipCrypto Password Cracker
// Extracts PKWARE 12-byte encryption headers and validates candidate passwords.

use crate::engine::crypto::ZipCryptoState;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ZipTarget {
    pub file_path:   String,
    pub header:      [u8; 12],
    pub check_byte:  u8,
    pub check_byte2: Option<u8>,
    pub sample_data: Vec<u8>,
}

impl ZipTarget {
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).ok()?;
        if &magic != b"PK\x03\x04" {
            return None;
        }

        // Read Local File Header (30 bytes total)
        let mut hdr = [0u8; 26]; // remaining 26 bytes after signature
        file.read_exact(&mut hdr).ok()?;

        let flags = u16::from_le_bytes([hdr[2], hdr[3]]);
        let is_encrypted = (flags & 0x0001) != 0;
        if !is_encrypted {
            return None;
        }

        let mod_time = u16::from_le_bytes([hdr[6], hdr[7]]);
        let crc32 = u32::from_le_bytes([hdr[10], hdr[11], hdr[12], hdr[13]]);
        let fn_len = u16::from_le_bytes([hdr[22], hdr[23]]) as usize;
        let ef_len = u16::from_le_bytes([hdr[24], hdr[25]]) as usize;

        // Determine check byte:
        // PKWARE AppNote: If bit 3 of the general purpose bit flag is set,
        // it uses high byte of last modification time. Otherwise, high byte of CRC-32.
        let (check_byte, check_byte2) = if (flags & 0x0008) != 0 {
            ((mod_time >> 8) as u8, None)
        } else {
            ((crc32 >> 24) as u8, Some(((crc32 >> 16) & 0xFF) as u8))
        };

        // Skip filename and extra field
        file.seek(SeekFrom::Current((fn_len + ef_len) as i64)).ok()?;

        // Read 12-byte encryption header
        let mut enc_header = [0u8; 12];
        file.read_exact(&mut enc_header).ok()?;

        // Read small payload sample to confirm decompression/validity
        let mut sample = vec![0u8; 32];
        let n = file.read(&mut sample).unwrap_or(0);
        sample.truncate(n);

        Some(Self {
            file_path: path.to_string_lossy().to_string(),
            header: enc_header,
            check_byte,
            check_byte2,
            sample_data: sample,
        })
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        let pass_bytes = candidate.as_bytes();
        let mut state = ZipCryptoState::new(pass_bytes);
        let mut b10 = 0u8;
        let mut b11 = 0u8;
        for (i, &b) in self.header.iter().enumerate() {
            let dec = state.decrypt_byte(b);
            if i == 10 {
                b10 = dec;
            } else if i == 11 {
                b11 = dec;
            }
        }

        if b11 != self.check_byte {
            return false;
        }

        if let Some(expected_b10) = self.check_byte2 {
            if b10 != expected_b10 {
                return false;
            }
        }

        true
    }

    pub fn test_batch(&self, candidates: &[String]) -> Option<String> {
        for candidate in candidates {
            if self.verify(candidate) {
                return Some(candidate.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_target_verification() {
        let password = b"secret123";
        let mut state = ZipCryptoState::new(password);

        // Fabricate 12-byte header where byte 11 matches check byte 0x42
        let check_byte = 0x42u8;
        let mut plain_header = [0u8; 12];
        plain_header[11] = check_byte;

        let mut enc_header = [0u8; 12];
        for i in 0..12 {
            let temp = (state.key2 | 2) as u16;
            let keystream = ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
            enc_header[i] = plain_header[i] ^ keystream;
            state.update(plain_header[i]);
        }

        let target = ZipTarget {
            file_path: "test.zip".into(),
            header: enc_header,
            check_byte,
            check_byte2: None,
            sample_data: vec![],
        };

        assert!(target.verify("secret123"));
        assert!(!target.verify("wrongpass"));
    }
}
