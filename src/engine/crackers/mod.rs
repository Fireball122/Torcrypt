// src/engine/crackers/mod.rs — High-Performance Multi-Target Cracking Engine
// Coordinates candidate streams and cryptographic verification across formats.

pub mod generator;
pub mod hash;
pub mod pdf;
pub mod zip;
pub mod winzip_aes;
pub mod seven_zip;
pub mod rar;
pub mod keepass;
pub mod rules;
pub use rules::{best64_rules, Rule, RuleOp};

pub use generator::{CandidateIterator, CandidateSource};
pub use hash::{HashAlgo, HashTarget};
pub use pdf::PdfTarget;
pub use zip::ZipTarget;
pub use winzip_aes::WinZipAesTarget;
pub use seven_zip::SevenZipTarget;
pub use rar::Rar5Target;
pub use keepass::KeePassTarget;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum ActiveCracker {
    Hash(HashTarget),
    Zip(ZipTarget),
    WinZipAes(WinZipAesTarget),
    Pdf(PdfTarget),
    SevenZip(SevenZipTarget),
    Rar5(Rar5Target),
    KeePass(KeePassTarget),
}

impl ActiveCracker {
    pub fn load_target(path: &Path) -> Option<Self> {
        let path_str = path.to_string_lossy().to_lowercase();

        // 1. Try Hash file or raw hash string
        if path_str.ends_with(".hash") || path_str.ends_with(".hashes") || path_str.ends_with(".txt") {
            if let Some(target) = HashTarget::load_from_file(path) {
                return Some(ActiveCracker::Hash(target));
            }
        }

        // 2. Try ZIP archive (WinZip AES first, then ZipCrypto)
        if path_str.ends_with(".zip") || path_str.ends_with(".jar") || path_str.ends_with(".apk") {
            if let Some(target) = WinZipAesTarget::load_from_file(path) {
                return Some(ActiveCracker::WinZipAes(target));
            }
            if let Some(target) = ZipTarget::load_from_file(path) {
                return Some(ActiveCracker::Zip(target));
            }
        }

        // 3. Try 7-Zip archive
        if path_str.ends_with(".7z") {
            if let Some(target) = SevenZipTarget::load_from_file(path) {
                return Some(ActiveCracker::SevenZip(target));
            }
        }

        // 4. Try RAR archive
        if path_str.ends_with(".rar") {
            if let Some(target) = Rar5Target::load_from_file(path) {
                return Some(ActiveCracker::Rar5(target));
            }
        }

        // 5. Try KeePass database
        if path_str.ends_with(".kdbx") {
            if let Some(target) = KeePassTarget::load_from_file(path) {
                return Some(ActiveCracker::KeePass(target));
            }
        }

        // 6. Try PDF document
        if path_str.ends_with(".pdf") {
            if let Some(target) = PdfTarget::load_from_file(path) {
                return Some(ActiveCracker::Pdf(target));
            }
        }

        // 4. Fallback: try hash target parsing on file content
        if let Some(target) = HashTarget::load_from_file(path) {
            return Some(ActiveCracker::Hash(target));
        }

        None
    }

    pub fn cipher_name(&self) -> &'static str {
        match self {
            ActiveCracker::Hash(h)       => h.algo.display_name(),
            ActiveCracker::Zip(_)        => "ZipCrypto Standard (PKWARE Stream Cipher)",
            ActiveCracker::WinZipAes(w)  => {
                if w.aes_bits == 128 {
                    "WinZip AES-128 (PBKDF2-HMAC-SHA1)"
                } else {
                    "WinZip AES-256 (PBKDF2-HMAC-SHA1)"
                }
            }
            ActiveCracker::Pdf(p)        => {
                if p.revision == 2 {
                    "Adobe PDF Standard Security (40-bit RC4)"
                } else {
                    "Adobe PDF Standard Security (128-bit RC4)"
                }
            }
            ActiveCracker::SevenZip(_)   => "7-Zip AES-256 (SHA-256 KDF)",
            ActiveCracker::Rar5(_)       => "RAR5 (PBKDF2-HMAC-SHA256 + AES-256)",
            ActiveCracker::KeePass(_)    => "KeePass 2.x KDBX (AES-KDF)",
        }
    }

    #[inline(always)]
    pub fn verify_candidate(&self, candidate: &str) -> bool {
        match self {
            ActiveCracker::Hash(h)      => h.verify(candidate),
            ActiveCracker::Zip(z)       => z.verify(candidate),
            ActiveCracker::WinZipAes(w) => w.verify(candidate),
            ActiveCracker::Pdf(p)       => p.verify(candidate),
            ActiveCracker::SevenZip(s)  => s.verify(candidate),
            ActiveCracker::Rar5(r)      => r.verify(candidate),
            ActiveCracker::KeePass(k)   => k.verify(candidate),
        }
    }


    pub fn test_batch(&self, candidates: &[String]) -> Option<String> {
        for candidate in candidates {
            if self.verify_candidate(candidate) {
                return Some(candidate.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_zip(path: &std::path::Path, password: &str) {
        let mut state = crate::engine::crypto::ZipCryptoState::new(password.as_bytes());
        let check_byte = 0xAAu8;
        let check_byte2 = 0x55u8;
        let mut plain_header = [0u8; 12];
        plain_header[10] = check_byte2;
        plain_header[11] = check_byte;

        let mut enc_header = [0u8; 12];
        for i in 0..12 {
            let temp = (state.key2 | 2) as u16;
            let keystream = ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
            enc_header[i] = plain_header[i] ^ keystream;
            state.update(plain_header[i]);
        }

        let mut zip_bytes = Vec::new();
        zip_bytes.extend_from_slice(b"PK\x03\x04");
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, check_byte2, check_byte]);
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(b"test.txt");
        zip_bytes.extend_from_slice(&enc_header);

        let cd_offset = zip_bytes.len() as u32;
        zip_bytes.extend_from_slice(b"PK\x01\x02");
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, check_byte2, check_byte]);
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(b"test.txt");

        let cd_size = (zip_bytes.len() as u32) - cd_offset;
        zip_bytes.extend_from_slice(b"PK\x05\x06");
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes());
        zip_bytes.extend_from_slice(&[0, 0]);

        std::fs::write(path, zip_bytes).unwrap();
    }

    #[test]
    fn test_real_zip_file_recovery() {
        let temp_path = std::env::temp_dir().join("torcrypt_unit_test_real.zip");
        create_test_zip(&temp_path, "secret123");

        let cracker = ActiveCracker::load_target(&temp_path).expect("Should load real zip");
        assert!(cracker.verify_candidate("secret123"));
        assert!(!cracker.verify_candidate("wrongpass"));

        let mut gen = CandidateIterator::new_common();
        let batch = gen.next_batch(200);
        let found = cracker.test_batch(&batch);
        assert_eq!(found, Some("secret123".to_string()));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_real_md5_file_recovery() {
        let temp_path = std::env::temp_dir().join("torcrypt_unit_test_md5.hash");
        std::fs::write(&temp_path, "0192023a7bbd73250516f069df18b500").unwrap(); // md5("admin123")

        let cracker = ActiveCracker::load_target(&temp_path).expect("Should load real md5 hash");
        assert!(cracker.verify_candidate("admin123"));
        assert!(!cracker.verify_candidate("wrong"));

        let mut gen = CandidateIterator::new_common();
        let batch = gen.next_batch(200);
        let found = cracker.test_batch(&batch);
        assert_eq!(found, Some("admin123".to_string()));

        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn test_real_sha256_file_recovery() {
        let temp_path = std::env::temp_dir().join("torcrypt_unit_test_sha256.hash");
        // sha256("welcome1") = fcc3a23fc7232cc89c7cb0f23d8774fefb73d7dc2ab22e6a1b6b8b202b4dcc91
        std::fs::write(&temp_path, "fcc3a23fc7232cc89c7cb0f23d8774fefb73d7dc2ab22e6a1b6b8b202b4dcc91").unwrap();

        let cracker = ActiveCracker::load_target(&temp_path).expect("Should load real sha256");
        assert!(cracker.verify_candidate("welcome1"));
        assert!(!cracker.verify_candidate("wrong"));

        let mut gen = CandidateIterator::new_common();
        let batch = gen.next_batch(200);
        let found = cracker.test_batch(&batch);
        assert_eq!(found, Some("welcome1".to_string()));

        let _ = std::fs::remove_file(temp_path);
    }
}
