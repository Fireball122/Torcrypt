// src/engine/extractors/keepass.rs — In-Process KeePass Password Database Inspector
// Parses KDBX 3.x/4.x headers, extracting cipher UUIDs (AES-256, ChaCha20, Twofish), master seeds, and KDF parameters.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct KeePassInspection {
    pub is_keepass:     bool,
    pub format_version: String,
    pub cipher_name:    String,
    pub kdf_name:       String,
    pub rounds_or_iter: Option<u64>,
    pub master_seed_hex:Option<String>,
    pub summary:        String,
}

impl KeePassInspection {
    pub fn inspect(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 12 {
            return None;
        }

        let mut sig_hdr = [0u8; 12];
        file.read_exact(&mut sig_hdr).ok()?;

        let sig1 = u32::from_le_bytes([sig_hdr[0], sig_hdr[1], sig_hdr[2], sig_hdr[3]]);
        let sig2 = u32::from_le_bytes([sig_hdr[4], sig_hdr[5], sig_hdr[6], sig_hdr[7]]);

        // KeePass base signature: 0x9AA2D903
        if sig1 != 0x9AA2D903 {
            return None;
        }

        let is_kdb1 = sig2 == 0xB54BFB65;
        let is_kdbx = sig2 == 0xB54BFB67 || sig2 == 0xB54BFB66;

        if !is_kdb1 && !is_kdbx {
            return None;
        }

        if is_kdb1 {
            return Some(KeePassInspection {
                is_keepass: true,
                format_version: "KeePass 1.x (Classic KDB)".into(),
                cipher_name: "AES-256 / Twofish (CBC Mode)".into(),
                kdf_name: "AES-KDF (Transform Rounds)".into(),
                rounds_or_iter: None,
                master_seed_hex: None,
                summary: "KeePass 1.x Database (Classic KDB, AES-256/Twofish)".into(),
            });
        }

        let ver_minor = u16::from_le_bytes([sig_hdr[8], sig_hdr[9]]);
        let ver_major = u16::from_le_bytes([sig_hdr[10], sig_hdr[11]]);

        // Parse outer header fields (KDBX 3.x / 4.x)
        let mut cipher_name = "AES-256 (Rijndael)".to_string();
        let mut kdf_name = "AES-KDF (PBKDF2 Derivative)".to_string();
        let mut rounds = None;
        let mut master_seed = None;

        let scan_len = (file_len.min(8192)) as usize;
        let mut buf = vec![0u8; scan_len];
        let _ = file.seek(SeekFrom::Start(12));
        let bytes_read = file.read(&mut buf).unwrap_or(0);
        let slice = &buf[..bytes_read];

        let mut pos = 0;
        while pos + 3 <= slice.len() {
            let field_id = slice[pos];
            if field_id == 0 {
                // End of header
                break;
            }

            let field_len = if ver_major >= 4 {
                if pos + 5 > slice.len() { break; }
                let l = u32::from_le_bytes([slice[pos + 1], slice[pos + 2], slice[pos + 3], slice[pos + 4]]) as usize;
                pos += 5;
                l
            } else {
                let l = u16::from_le_bytes([slice[pos + 1], slice[pos + 2]]) as usize;
                pos += 3;
                l
            };

            if pos + field_len > slice.len() {
                break;
            }

            let field_data = &slice[pos..pos + field_len];
            match field_id {
                2 => {
                    // Cipher UUID (16 bytes)
                    if field_len == 16 {
                        let uuid = field_data.iter().map(|b| format!("{:02X}", b)).collect::<String>();
                        if uuid == "31C1F2E6BF714350BE5805216AFC5AFF" {
                            cipher_name = "AES-256 (CBC Mode)".into();
                        } else if uuid == "D6038A2B3B6F415CA229E1044A1F6E52" {
                            cipher_name = "ChaCha20 (256-bit Stream)".into();
                        } else if uuid == "AD68F29F16EB4B2CB64CE837248FF5E0" {
                            cipher_name = "Twofish (256-bit Block)".into();
                        }
                    }
                }
                4 => {
                    // Master Seed
                    if field_len >= 16 {
                        master_seed = Some(field_data.iter().take(16).map(|b| format!("{:02X}", b)).collect());
                    }
                }
                6 => {
                    // Transform Rounds
                    if field_len == 8 {
                        let r = u64::from_le_bytes([
                            field_data[0], field_data[1], field_data[2], field_data[3],
                            field_data[4], field_data[5], field_data[6], field_data[7],
                        ]);
                        rounds = Some(r);
                    }
                }
                11 => {
                    // KDF Parameters (KDBX 4)
                    if field_data.windows(8).any(|w| w == b"$Argon2d") || field_data.windows(7).any(|w| w == b"Argon2d") {
                        kdf_name = "Argon2d (RFC 9106 Memory-Hard KDF)".into();
                    } else if field_data.windows(9).any(|w| w == b"$Argon2id") || field_data.windows(8).any(|w| w == b"Argon2id") {
                        kdf_name = "Argon2id (Hybrid Memory-Hard KDF)".into();
                    }
                }
                _ => {}
            }

            pos += field_len;
        }

        let rounds_str = rounds.map(|r| format!(" │ {} rounds", r)).unwrap_or_default();
        let summary = format!(
            "KeePass {}.{} Database: {} │ {}{}",
            ver_major, ver_minor, cipher_name, kdf_name, rounds_str
        );

        Some(KeePassInspection {
            is_keepass: true,
            format_version: format!("KeePass {}.{}", ver_major, ver_minor),
            cipher_name,
            kdf_name,
            rounds_or_iter: rounds,
            master_seed_hex: master_seed,
            summary,
        })
    }
}
