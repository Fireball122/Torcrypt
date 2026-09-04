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
        })
    }
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        for line in content.lines() {
            let t = line.trim();
            if !t.is_empty() && !t.starts_with('#') {
                if let Some(target) = Self::parse(t) {
                    return Some(target);
                }
            }
        }
        None
    }

    #[inline(always)]
    pub fn verify(&self, candidate: &str) -> bool {
        let b = candidate.as_bytes();
        match self.algo {
            HashAlgo::Md5 => {
                let digest = crate::engine::crypto::md5(b);
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Ntlm => {
                let digest = crate::engine::crypto::ntlm_hash(candidate);
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Sha1 => {
                let digest = crate::engine::crypto::sha1(b);
                digest == self.target_bytes.as_slice()
            }
            HashAlgo::Sha256 => {
                let digest = crate::engine::crypto::sha256(b);
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
                                let byte_refs: Vec<&[u8]> = chunk.iter().map(|s| s.as_bytes()).collect();
                                unsafe {
                                    if let Some(idx) = crate::engine::crypto::simd::avx2::test_md5_8way(&byte_refs, target_words) {
                                        return Some(chunk[idx].clone());
                                    }
                                }
                            }
                        }
                        HashAlgo::Ntlm => {
                            for chunk in candidates.chunks(8) {
                                let str_refs: Vec<&str> = chunk.iter().map(|s| s.as_str()).collect();
                                unsafe {
                                    if let Some(idx) = crate::engine::crypto::simd::avx2::test_ntlm_8way(&str_refs, target_words) {
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
}
