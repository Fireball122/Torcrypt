// src/engine/crackers/hash.rs — Real In-Process Cryptographic Hash Cracker
// Evaluates candidate passwords against MD5, SHA-1, SHA-256, and NTLM targets.

use crate::engine::crypto::{md5_hex, ntlm_hex, sha1_hex, sha256_hex};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgo {
    Md5,
    Sha1,
    Sha256,
    Ntlm,
}

impl HashAlgo {
    pub fn display_name(&self) -> &'static str {
        match self {
            HashAlgo::Md5    => "MD5 (RFC 1321)",
            HashAlgo::Sha1   => "SHA-1 (FIPS 180-1)",
            HashAlgo::Sha256 => "SHA-256 (FIPS 180-4)",
            HashAlgo::Ntlm   => "NTLM (Windows SAM)",
        }
    }

    pub fn compute(&self, candidate: &str) -> String {
        match self {
            HashAlgo::Md5    => md5_hex(candidate.as_bytes()),
            HashAlgo::Sha1   => sha1_hex(candidate.as_bytes()),
            HashAlgo::Sha256 => sha256_hex(candidate.as_bytes()),
            HashAlgo::Ntlm   => ntlm_hex(candidate),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HashTarget {
    pub target_hex:   String,
    pub target_bytes: Vec<u8>,
    pub algo:         HashAlgo,
    pub multi_targets: Vec<Vec<u8>>,
}

impl HashTarget {
    pub fn parse(input: &str) -> Option<Self> {
        let trimmed = input.trim().to_lowercase();
        // Remove username prefix if in format "user:hash" or "user:uid:lm:ntlm:::"
        let hash_str = if trimmed.contains(':') {
            let parts: Vec<&str> = trimmed.split(':').collect();
            if parts.len() >= 4 && parts[3].len() == 32 {
                let hex = parts[3];
                let mut bytes = Vec::with_capacity(16);
                for i in 0..16 {
                    bytes.push(u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?);
                }
                return Some(Self {
                    target_hex: hex.to_string(),
                    target_bytes: bytes,
                    algo: HashAlgo::Ntlm,
                    multi_targets: Vec::new(),
                });
            } else if let Some(last) = parts.last() {
                last.trim()
            } else {
                &trimmed
            }
        } else {
            &trimmed
        };

        let is_hex = !hash_str.is_empty() && hash_str.chars().all(|c| c.is_ascii_hexdigit());
        if !is_hex {
            return None;
        }

        let algo = match hash_str.len() {
            32  => HashAlgo::Md5, // Default 32-char hex to MD5 (can be NTLM if specified)
            40  => HashAlgo::Sha1,
            64  => HashAlgo::Sha256,
            _   => return None,
        };
        let mut target_bytes = Vec::with_capacity(hash_str.len() / 2);
        for i in 0..hash_str.len() / 2 {
            target_bytes.push(u8::from_str_radix(&hash_str[i * 2..i * 2 + 2], 16).ok()?);
        }

        Some(Self {
            target_hex: hash_str.to_string(),
            target_bytes,
            algo,
            multi_targets: Vec::new(),
        })
    }
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        let mut first_target: Option<Self> = None;
        let mut all_bytes: Vec<Vec<u8>> = Vec::new();

        for line in content.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                if let Some(target) = Self::parse(t) {
                    all_bytes.push(target.target_bytes.clone());
                    if first_target.is_none() {
                        first_target = Some(target);
                    }
                }
            }
        }

        let mut primary = first_target?;
        primary.multi_targets = all_bytes;
        Some(primary)
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        let b = candidate.as_bytes();
        match self.algo {
            HashAlgo::Md5 => {
                let digest = crate::engine::crypto::md5(b);
                if self.multi_targets.len() > 1 {
                    return self.multi_targets.iter().any(|t| t.as_slice() == &digest[..]);
                }
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Ntlm => {
                let digest = crate::engine::crypto::ntlm_hash(candidate);
                if self.multi_targets.len() > 1 {
                    return self.multi_targets.iter().any(|t| t.as_slice() == &digest[..]);
                }
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Sha1 => {
                let digest = crate::engine::crypto::sha1(b);
                if self.multi_targets.len() > 1 {
                    return self.multi_targets.iter().any(|t| t.as_slice() == &digest[..]);
                }
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Sha256 => {
                let digest = crate::engine::crypto::sha256(b);
                if self.multi_targets.len() > 1 {
                    return self.multi_targets.iter().any(|t| t.as_slice() == &digest[..]);
                }
                digest == self.target_bytes.as_slice()
            }
        }
    }
    pub fn test_batch(&self, candidates: &[String]) -> Option<String> {
        #[cfg(target_arch = "x86_64")]
        {
            use crate::engine::crypto::simd::{active_simd_backend, parse_hex_words_32, SimdBackend};

            if active_simd_backend() == SimdBackend::Avx2_8Way {
                if let Some(target_words) = parse_hex_words_32(&self.target_hex) {
                    match self.algo {
                        HashAlgo::Md5 => {
                            for chunk in candidates.chunks(8) {
                                let mut byte_refs = [&b""[..]; 8];
                                for (i, s) in chunk.iter().enumerate() {
                                    byte_refs[i] = s.as_bytes();
                                }
                                unsafe {
                                    if let Some(idx) = crate::engine::crypto::simd::avx2::test_md5_8way(&byte_refs[..chunk.len()], target_words) {
                                        return Some(chunk[idx].clone());
                                    }
                                }
                            }
                        }
                        HashAlgo::Ntlm => {
                            for chunk in candidates.chunks(8) {
                                let mut str_refs = [""; 8];
                                for (i, s) in chunk.iter().enumerate() {
                                    str_refs[i] = s.as_str();
                                }
                                unsafe {
                                    if let Some(idx) = crate::engine::crypto::simd::avx2::test_ntlm_8way(&str_refs[..chunk.len()], target_words) {
                                        return Some(chunk[idx].clone());
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
        }

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
    fn test_hash_target_md5() {
        // "secret123" MD5 = 5d7845ac6ee7cfffafc5fe5f35cf666d
        let target = HashTarget::parse("5d7845ac6ee7cfffafc5fe5f35cf666d").unwrap();
        assert_eq!(target.algo, HashAlgo::Md5);
        assert!(target.verify("secret123"));
        assert!(!target.verify("wrongpass"));
    }

    #[test]
    fn test_hash_target_sha256() {
        // "admin2026" SHA-256
        let hex = sha256_hex(b"admin2026");
        let target = HashTarget::parse(&hex).unwrap();
        assert_eq!(target.algo, HashAlgo::Sha256);
        assert!(target.verify("admin2026"));
    }

    #[test]
    fn test_hash_target_ntlm() {
        // PWDUMP format
        let target = HashTarget::parse("Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::").unwrap();
        assert_eq!(target.algo, HashAlgo::Ntlm);
        assert!(target.verify("password"));
    }

    #[test]
    fn test_multi_hash_loading_and_verification() {
        let temp_dir = std::env::temp_dir();
        let hash_file = temp_dir.join("torcrypt_multihash_test.txt");

        // MD5 of "password" = 5f4dcc3b5aa765d61d8327deb882cf99
        // MD5 of "admin"    = 21232f297a57a5a743894a0e4a801fc3
        let content = "# Header comment\n5f4dcc3b5aa765d61d8327deb882cf99\n21232f297a57a5a743894a0e4a801fc3\n";
        std::fs::write(&hash_file, content).unwrap();

        let target = HashTarget::load_from_file(&hash_file).expect("Should load multi-hash file");
        assert_eq!(target.multi_targets.len(), 2);
        assert!(target.verify("password"));
        assert!(target.verify("admin"));
        assert!(!target.verify("wrongpass"));

        let _ = std::fs::remove_file(hash_file);
    }
}
