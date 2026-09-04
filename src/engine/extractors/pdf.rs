// src/engine/extractors/pdf.rs — In-Process Adobe PDF Security Handler Inspector
// Inspects PDF documents for /Encrypt security dictionaries, extracting version, revision, key length, and hashes.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct PdfInspection {
    pub is_pdf:          bool,
    pub is_encrypted:    bool,
    pub version_str:     String,
    pub filter:          String,
    pub v_version:       u8,
    pub r_revision:      u8,
    pub key_length_bits: u16,
    pub permissions:     i32,
    pub owner_hash_hex:  Option<String>,
    pub user_hash_hex:   Option<String>,
    pub summary:         String,
}

impl PdfInspection {
    pub fn inspect(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 16 {
            return None;
        }

        // 1. Verify %PDF- magic
        let mut header = [0u8; 10];
        file.read_exact(&mut header).ok()?;
        if !header.starts_with(b"%PDF-") {
            return None;
        }
        let version_str = String::from_utf8_lossy(&header[5..8]).trim().to_string();

        // 2. Scan for /Encrypt dictionary: scan last 32KB (where trailer typically is)
        // or entire file if smaller
        let scan_size = (file_len.min(65536)) as usize;
        let mut scan_buf = vec![0u8; scan_size];
        let scan_start = file_len - scan_size as u64;
        file.seek(SeekFrom::Start(scan_start)).ok()?;
        file.read_exact(&mut scan_buf).ok()?;

        // If not found in tail, also check first 64KB for linearized/fast web view PDFs
        let mut found_encrypt = find_subslice(&scan_buf, b"/Encrypt");
        let mut context_buf = scan_buf;

        if found_encrypt.is_none() && file_len > scan_size as u64 {
            let head_size = (file_len.min(65536)) as usize;
            let mut head_buf = vec![0u8; head_size];
            file.seek(SeekFrom::Start(0)).ok()?;
            if file.read_exact(&mut head_buf).is_ok() {
                found_encrypt = find_subslice(&head_buf, b"/Encrypt");
                if found_encrypt.is_some() {
                    context_buf = head_buf;
                }
            }
        }

        let is_encrypted = found_encrypt.is_some();
        if !is_encrypted {
            return Some(PdfInspection {
                is_pdf: true,
                is_encrypted: false,
                version_str: format!("PDF-{}", version_str),
                filter: "None".into(),
                v_version: 0,
                r_revision: 0,
                key_length_bits: 0,
                permissions: 0,
                owner_hash_hex: None,
                user_hash_hex: None,
                summary: format!("Plaintext PDF Document (Version {}) — No Password Protection", version_str),
            });
        }

        // Parse encryption parameters from the context surrounding /Encrypt
        let enc_idx = found_encrypt.unwrap();
        let enc_slice = &context_buf[enc_idx..];

        let v_val = extract_int_param(enc_slice, b"/V").unwrap_or(1) as u8;
        let r_val = extract_int_param(enc_slice, b"/R").unwrap_or(2) as u8;
        let length_val = extract_int_param(enc_slice, b"/Length").unwrap_or(if v_val == 1 { 40 } else if v_val == 5 { 256 } else { 128 }) as u16;
        let p_val = extract_int_param(enc_slice, b"/P").unwrap_or(-1) as i32;

        let o_hex = extract_hex_or_string_param(enc_slice, b"/O");
        let u_hex = extract_hex_or_string_param(enc_slice, b"/U");

        let cipher_desc = match (v_val, r_val) {
            (1, 2) => "RC4 40-bit (Standard Security Handler R2)".into(),
            (2, 3) => format!("RC4 {}-bit (Standard Security Handler R3)", length_val),
            (4, 4) => "AES-128 / CBC (Acrobat 7+ / PDF 1.6)".into(),
            (5, 5) => "AES-256 / CBC (Acrobat X / ISO 32000-1 R5)".into(),
            (5, 6) => "AES-256 / Hardened KDF (Acrobat XI / ISO 32000-2 R6)".into(),
            _      => format!("Standard Security Handler (V={} R={} Length={}-bit)", v_val, r_val, length_val),
        };

        Some(PdfInspection {
            is_pdf: true,
            is_encrypted: true,
            version_str: format!("PDF-{}", version_str),
            filter: "Standard".into(),
            v_version: v_val,
            r_revision: r_val,
            key_length_bits: length_val,
            permissions: p_val,
            owner_hash_hex: o_hex,
            user_hash_hex: u_hex,
            summary: format!("PDF Encrypted: {} │ Permissions: 0x{:08X}", cipher_desc, p_val as u32),
        })
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_int_param(buf: &[u8], key: &[u8]) -> Option<i64> {
    let key_pos = find_subslice(buf, key)?;
    let mut i = key_pos + key.len();

    // Skip whitespace
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n') {
        i += 1;
    }

    let mut is_neg = false;
    if i < buf.len() && buf[i] == b'-' {
        is_neg = true;
        i += 1;
    }

    let start = i;
    while i < buf.len() && buf[i].is_ascii_digit() {
        i += 1;
    }

    if i > start {
        let s = std::str::from_utf8(&buf[start..i]).ok()?;
        let val: i64 = s.parse().ok()?;
        Some(if is_neg { -val } else { val })
    } else {
        None
    }
}

fn extract_hex_or_string_param(buf: &[u8], key: &[u8]) -> Option<String> {
    let key_pos = find_subslice(buf, key)?;
    let mut i = key_pos + key.len();

    // Skip whitespace
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n') {
        i += 1;
    }

    if i >= buf.len() {
        return None;
    }

    // Hex format: <4A3F...>
    if buf[i] == b'<' {
        i += 1;
        let start = i;
        while i < buf.len() && buf[i] != b'>' {
            i += 1;
        }
        let hex_slice = &buf[start..i];
        let hex_str = hex_slice.iter().filter(|b| b.is_ascii_hexdigit()).map(|&b| b as char).collect::<String>();
        if !hex_str.is_empty() {
            return Some(hex_str);
        }
    }
    // Literal string format: (binary...)
    else if buf[i] == b'(' {
        i += 1;
        let mut depth = 1;
        let start = i;
        while i < buf.len() && depth > 0 {
            if buf[i] == b'\\' {
                i += 2; // skip escaped char
                continue;
            }
            if buf[i] == b'(' {
                depth += 1;
            } else if buf[i] == b')' {
                depth -= 1;
            }
            i += 1;
        }
        let raw_bytes = &buf[start..i.saturating_sub(1)];
        let hex = raw_bytes.iter().map(|b| format!("{:02X}", b)).collect::<String>();
        if !hex.is_empty() {
            return Some(hex);
        }
    }

    None
}
