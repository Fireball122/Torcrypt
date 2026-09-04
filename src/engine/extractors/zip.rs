// src/engine/extractors/zip.rs — In-Process ZIP Archive Container Inspector
// Parses ZIP Central Directory and Local File Headers to detect encryption schemes (ZipCrypto vs WinZip AES).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZipEncryption {
    None,
    ZipCrypto {
        crc32: u32,
    },
    WinZipAes {
        strength_bits: u16,
        salt_len:      usize,
        salt_hex:      Option<String>,
        verifier_hex:  Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ZipInspection {
    pub is_zip:            bool,
    pub encryption:        ZipEncryption,
    pub total_files:       usize,
    pub encrypted_files:   usize,
    pub target_filename:   Option<String>,
    pub summary:           String,
}

impl ZipInspection {
    pub fn inspect(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 22 {
            return None; // Minimum valid ZIP size (empty archive with EOCD)
        }

        // 1. Try to read from Central Directory via EOCD
        if let Some(inspection) = inspect_central_directory(&mut file, file_len) {
            return Some(inspection);
        }

        // 2. Fallback: inspect first local file header
        inspect_first_local_header(&mut file)
    }
}

fn inspect_central_directory(file: &mut File, file_len: u64) -> Option<ZipInspection> {
    // EOCD record signature is 0x06054B50 (PK\x05\x06)
    // Minimum EOCD size is 22 bytes, max comment is 65535 bytes
    let scan_len = (file_len.min(65557)) as usize;
    let mut buf = vec![0u8; scan_len];
    let start_offset = file_len - scan_len as u64;

    file.seek(SeekFrom::Start(start_offset)).ok()?;
    file.read_exact(&mut buf).ok()?;

    // Search backwards for PK\x05\x06
    let mut eocd_pos = None;
    for i in (0..=scan_len.saturating_sub(22)).rev() {
        if buf[i..i + 4] == [0x50, 0x4B, 0x05, 0x06] {
            eocd_pos = Some(i);
            break;
        }
    }

    let eocd_idx = eocd_pos?;
    let eocd = &buf[eocd_idx..];
    if eocd.len() < 22 {
        return None;
    }

    let total_entries = u16::from_le_bytes([eocd[10], eocd[11]]) as usize;
    let cd_size = u32::from_le_bytes([eocd[12], eocd[13], eocd[14], eocd[15]]) as u64;
    let cd_offset = u32::from_le_bytes([eocd[16], eocd[17], eocd[18], eocd[19]]) as u64;

    if cd_offset + cd_size > file_len {
        return None;
    }

    file.seek(SeekFrom::Start(cd_offset)).ok()?;
    let mut cd_buf = vec![0u8; cd_size as usize];
    file.read_exact(&mut cd_buf).ok()?;

    let mut pos = 0;
    let mut encrypted_count = 0;
    let mut detected_enc = ZipEncryption::None;
    let mut target_name = None;
    let mut entries_parsed = 0;

    while pos + 46 <= cd_buf.len() && entries_parsed < total_entries {
        // Central directory header signature is 0x02014B50 (PK\x01\x02)
        if cd_buf[pos..pos + 4] != [0x50, 0x4B, 0x01, 0x02] {
            break;
        }

        let flag = u16::from_le_bytes([cd_buf[pos + 8], cd_buf[pos + 9]]);
        let method = u16::from_le_bytes([cd_buf[pos + 10], cd_buf[pos + 11]]);
        let crc = u32::from_le_bytes([cd_buf[pos + 16], cd_buf[pos + 17], cd_buf[pos + 18], cd_buf[pos + 19]]);
        let fn_len = u16::from_le_bytes([cd_buf[pos + 28], cd_buf[pos + 29]]) as usize;
        let ef_len = u16::from_le_bytes([cd_buf[pos + 30], cd_buf[pos + 31]]) as usize;
        let comment_len = u16::from_le_bytes([cd_buf[pos + 32], cd_buf[pos + 33]]) as usize;
        let local_hdr_offset = u32::from_le_bytes([cd_buf[pos + 42], cd_buf[pos + 43], cd_buf[pos + 44], cd_buf[pos + 45]]) as u64;

        let name_start = pos + 46;
        let name_end = name_start + fn_len;
        let filename = if name_end <= cd_buf.len() {
            String::from_utf8_lossy(&cd_buf[name_start..name_end]).to_string()
        } else {
            String::new()
        };

        let ef_start = name_end;
        let ef_end = ef_start + ef_len;
        let is_encrypted = (flag & 0x0001) != 0;

        if is_encrypted {
            encrypted_count += 1;
            if target_name.is_none() {
                target_name = Some(filename.clone());
            }

            // Check if WinZip AES (method 99 or extra field 0x9901)
            let mut is_winzip = method == 99;
            let mut aes_bits = 256;

            if ef_end <= cd_buf.len() {
                let ef = &cd_buf[ef_start..ef_end];
                let mut ef_pos = 0;
                while ef_pos + 4 <= ef.len() {
                    let header_id = u16::from_le_bytes([ef[ef_pos], ef[ef_pos + 1]]);
                    let data_size = u16::from_le_bytes([ef[ef_pos + 2], ef[ef_pos + 3]]) as usize;
                    if header_id == 0x9901 && ef_pos + 4 + data_size <= ef.len() && data_size >= 7 {
                        is_winzip = true;
                        let strength = ef[ef_pos + 8];
                        aes_bits = match strength {
                            0x01 => 128,
                            0x02 => 192,
                            _    => 256,
                        };
                        break;
                    }
                    ef_pos += 4 + data_size;
                }
            }

            if is_winzip {
                let salt_len = if aes_bits == 128 { 8 } else { 16 };
                let (salt_hex, verifier_hex) = extract_winzip_salt_and_verifier(file, local_hdr_offset, salt_len);
                detected_enc = ZipEncryption::WinZipAes {
                    strength_bits: aes_bits,
                    salt_len,
                    salt_hex,
                    verifier_hex,
                };
            } else if matches!(detected_enc, ZipEncryption::None) {
                detected_enc = ZipEncryption::ZipCrypto { crc32: crc };
            }
        }

        entries_parsed += 1;
        pos = ef_end + comment_len;
    }

    let summary = match detected_enc {
        ZipEncryption::None => "Plaintext ZIP Archive (Unencrypted)".into(),
        ZipEncryption::ZipCrypto { crc32 } => {
            format!("ZipCrypto Traditional (PKWARE 96-bit, CRC-32: {:08X})", crc32)
        }
        ZipEncryption::WinZipAes { strength_bits, .. } => {
            format!("WinZip AES-{} (PBKDF2-HMAC-SHA1 + AES-CTR)", strength_bits)
        }
    };

    Some(ZipInspection {
        is_zip: true,
        encryption: detected_enc,
        total_files: total_entries,
        encrypted_files: encrypted_count,
        target_filename: target_name,
        summary,
    })
}

fn extract_winzip_salt_and_verifier(file: &mut File, local_hdr_offset: u64, salt_len: usize) -> (Option<String>, Option<String>) {
    // Seek to local header
    if file.seek(SeekFrom::Start(local_hdr_offset)).is_err() {
        return (None, None);
    }

    let mut hdr = [0u8; 30];
    if file.read_exact(&mut hdr).is_err() || hdr[0..4] != [0x50, 0x4B, 0x03, 0x04] {
        return (None, None);
    }

    let fn_len = u16::from_le_bytes([hdr[26], hdr[27]]) as u64;
    let ef_len = u16::from_le_bytes([hdr[28], hdr[29]]) as u64;

    // Encrypted payload follows header + filename + extra field
    let payload_offset = local_hdr_offset + 30 + fn_len + ef_len;
    if file.seek(SeekFrom::Start(payload_offset)).is_err() {
        return (None, None);
    }

    let needed_bytes = salt_len + 2; // salt + 2-byte verification tag
    let mut enc_header = vec![0u8; needed_bytes];
    if file.read_exact(&mut enc_header).is_err() {
        return (None, None);
    }

    let salt_bytes = &enc_header[0..salt_len];
    let verifier_bytes = &enc_header[salt_len..salt_len + 2];

    let salt_hex = salt_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();
    let verifier_hex = verifier_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();

    (Some(salt_hex), Some(verifier_hex))
}

fn inspect_first_local_header(file: &mut File) -> Option<ZipInspection> {
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut hdr = [0u8; 30];
    file.read_exact(&mut hdr).ok()?;

    if hdr[0..4] != [0x50, 0x4B, 0x03, 0x04] {
        return None;
    }

    let flag = u16::from_le_bytes([hdr[6], hdr[7]]);
    let method = u16::from_le_bytes([hdr[8], hdr[9]]);
    let crc = u32::from_le_bytes([hdr[14], hdr[15], hdr[16], hdr[17]]);
    let fn_len = u16::from_le_bytes([hdr[26], hdr[27]]) as usize;
    let ef_len = u16::from_le_bytes([hdr[28], hdr[29]]) as usize;

    let is_encrypted = (flag & 0x0001) != 0;
    if !is_encrypted {
        return Some(ZipInspection {
            is_zip: true,
            encryption: ZipEncryption::None,
            total_files: 1,
            encrypted_files: 0,
            target_filename: None,
            summary: "Plaintext ZIP Archive (Unencrypted)".into(),
        });
    }

    let mut name_buf = vec![0u8; fn_len];
    let _ = file.read_exact(&mut name_buf);
    let target_name = String::from_utf8_lossy(&name_buf).to_string();

    let mut ef_buf = vec![0u8; ef_len];
    let _ = file.read_exact(&mut ef_buf);

    let mut is_winzip = method == 99;
    let mut aes_bits = 256;

    let mut ef_pos = 0;
    while ef_pos + 4 <= ef_buf.len() {
        let header_id = u16::from_le_bytes([ef_buf[ef_pos], ef_buf[ef_pos + 1]]);
        let data_size = u16::from_le_bytes([ef_buf[ef_pos + 2], ef_buf[ef_pos + 3]]) as usize;
        if header_id == 0x9901 && ef_pos + 4 + data_size <= ef_buf.len() && data_size >= 7 {
            is_winzip = true;
            let strength = ef_buf[ef_pos + 8];
            aes_bits = match strength {
                0x01 => 128,
                0x02 => 192,
                _    => 256,
            };
            break;
        }
        ef_pos += 4 + data_size;
    }

    let enc = if is_winzip {
        let salt_len = if aes_bits == 128 { 8 } else { 16 };
        let mut salt_verif = vec![0u8; salt_len + 2];
        let (salt_hex, verifier_hex) = if file.read_exact(&mut salt_verif).is_ok() {
            (
                Some(salt_verif[..salt_len].iter().map(|b| format!("{:02X}", b)).collect()),
                Some(salt_verif[salt_len..].iter().map(|b| format!("{:02X}", b)).collect()),
            )
        } else {
            (None, None)
        };

        ZipEncryption::WinZipAes {
            strength_bits: aes_bits,
            salt_len,
            salt_hex,
            verifier_hex,
        }
    } else {
        ZipEncryption::ZipCrypto { crc32: crc }
    };

    let summary = match enc {
        ZipEncryption::None => "Plaintext ZIP Archive (Unencrypted)".into(),
        ZipEncryption::ZipCrypto { crc32 } => {
            format!("ZipCrypto Traditional (PKWARE 96-bit, CRC-32: {:08X})", crc32)
        }
        ZipEncryption::WinZipAes { strength_bits, .. } => {
            format!("WinZip AES-{} (PBKDF2-HMAC-SHA1 + AES-CTR)", strength_bits)
        }
    };

    Some(ZipInspection {
        is_zip: true,
        encryption: enc,
        total_files: 1,
        encrypted_files: 1,
        target_filename: Some(target_name),
        summary,
    })
}
