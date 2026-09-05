// src/engine/extractors/seven_zip.rs — In-Process 7-Zip Archive Container Inspector
// Detects 7-Zip signature (37 7A BC AF 27 1C), parses header properties, and determines AES-256 KDF encryption.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct SevenZipInspection {
    pub is_7z:         bool,
    pub is_encrypted:  bool,
    pub version_major: u8,
    pub version_minor: u8,
    pub has_enc_header:bool,
    pub kdf_info:      String,
    pub summary:       String,
}

impl SevenZipInspection {
    pub fn inspect(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 32 {
            return None; // 32 bytes minimum 7z header
        }

        let mut sig_hdr = [0u8; 32];
        file.read_exact(&mut sig_hdr).ok()?;

        // 7z signature: 37 7A BC AF 27 1C
        if sig_hdr[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
            return None;
        }

        let ver_major = sig_hdr[6];
        let ver_minor = sig_hdr[7];

        let next_header_offset = u64::from_le_bytes([
            sig_hdr[12], sig_hdr[13], sig_hdr[14], sig_hdr[15],
            sig_hdr[16], sig_hdr[17], sig_hdr[18], sig_hdr[19],
        ]);
        let next_header_size = u64::from_le_bytes([
            sig_hdr[20], sig_hdr[21], sig_hdr[22], sig_hdr[23],
            sig_hdr[24], sig_hdr[25], sig_hdr[26], sig_hdr[27],
        ]);

        // Scan for 7zAES Method ID: [0x06, 0xF1, 0x07, 0x01] in header or tail
        let mut is_encrypted = false;
        let mut enc_header = false;
        let mut is_heuristic = false;
        if next_header_offset > 0 && next_header_size > 0 && (32 + next_header_offset) < file_len {
            let actual_hdr_pos = 32 + next_header_offset;
            if file.seek(SeekFrom::Start(actual_hdr_pos)).is_ok() {
                let check_len = (next_header_size.min(4096)) as usize;
                let mut check_buf = vec![0u8; check_len];
                if file.read_exact(&mut check_buf).is_ok() {
                    // Encoded header marker in 7z is 0x17 (kEncodedHeader)
                    if check_buf.first() == Some(&0x17) {
                        enc_header = true;
                        is_encrypted = true;
                    }
                    if check_buf.windows(4).any(|w| w == [0x06, 0xF1, 0x07, 0x01]) {
                        is_encrypted = true;
                    }
                }
            }
        }

        // Fallback: check last 4KB
        if !is_encrypted && file_len > 64 {
            let tail_len = (file_len.min(4096)) as usize;
            let mut tail = vec![0u8; tail_len];
            let _ = file.seek(SeekFrom::Start(file_len - tail_len as u64));
            if file.read_exact(&mut tail).is_ok() && tail.windows(4).any(|w| w == [0x06, 0xF1, 0x07, 0x01]) {
                is_encrypted = true;
                is_heuristic = true;
            }
        }

        let (kdf_info, summary) = if is_encrypted {
            let hdr_note = if enc_header {
                " (Encrypted File List)"
            } else if is_heuristic {
                " (Probable / Tail Signature)"
            } else {
                ""
            };
            (
                "SHA-256 KDF (524,288 rounds, 2^19) + AES-256-CBC".into(),
                format!("7-Zip AES-256 Encrypted Archive{} (v{}.{})", hdr_note, ver_major, ver_minor),
            )
        } else {
            (
                "None".into(),
                format!("Plaintext 7-Zip Archive (v{}.{}) — No Encryption", ver_major, ver_minor),
            )
        };

        Some(SevenZipInspection {
            is_7z: true,
            is_encrypted,
            version_major: ver_major,
            version_minor: ver_minor,
            has_enc_header: enc_header,
            kdf_info,
            summary,
        })
    }
}
