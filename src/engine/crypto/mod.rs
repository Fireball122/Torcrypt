// src/engine/crypto/mod.rs — Cryptographic Primitives for Torcrypt Real Decryption Engine
// Pure-Rust, zero-dependency implementations of hashing, symmetric stream ciphers, and key derivation.

pub mod crc32;
pub mod md4;
pub mod md5;
pub mod rc4;
pub mod sha1;
pub mod sha256;
pub mod zipcrypto;
pub mod simd;
pub mod hmac;
pub mod pbkdf2;
pub mod aes;

pub use hmac::{hmac_sha1, hmac_sha256};
pub use pbkdf2::{pbkdf2_hmac_sha1, pbkdf2_hmac_sha256};
pub use aes::{aes_cbc_decrypt, AesKey};
pub use simd::{active_simd_backend, parse_hex_words_32, SimdBackend};

pub use crc32::{crc32, crc32_update};
pub use md4::{md4, md4_hex, ntlm_hash, ntlm_hex};
pub use md5::{md5, md5_hex};
pub use rc4::{rc4_crypt, Rc4};
pub use sha1::{sha1, sha1_hex};
pub use sha256::{sha256, sha256_hex};
pub use zipcrypto::ZipCryptoState;
