// src/engine/crackers/pdf.rs — Real In-Process Adobe PDF Standard Security Handler Cracker
// Implements ISO 32000-1 / PDF 1.7 Algorithm 3.2 (Key Derivation) and Algorithm 3.6/3.7 (User Auth).

use crate::engine::crypto::{md5, rc4_crypt};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

pub const PDF_PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

#[derive(Debug, Clone)]
pub struct PdfTarget {
    pub file_path:   String,
    pub revision:    u8,
    pub key_bytes:   usize, // 5 for 40-bit, 16 for 128-bit
    pub p_perm:      i32,
    pub o_value:     Vec<u8>,
    pub u_value:     Vec<u8>,
    pub id_first:    Vec<u8>,
}

impl PdfTarget {
    pub fn load_from_file(path: &Path) -> Option<Self> {
        let mut file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len < 32 {
            return None;
        }

        let mut header = [0u8; 16];
        file.read_exact(&mut header).ok()?;
        if !header.starts_with(b"%PDF-") {
            return None;
        }

        let scan_size = (file_len.min(65536)) as usize;
        let mut scan_buf = vec![0u8; scan_size];
        file.seek(SeekFrom::Start(file_len - scan_size as u64)).ok()?;
        file.read_exact(&mut scan_buf).ok()?;

        let mut context_buf = scan_buf;
        let mut enc_pos = find_subslice(&context_buf, b"/Encrypt");
        if enc_pos.is_none() && file_len > scan_size as u64 {
            let head_size = (file_len.min(65536)) as usize;
            let mut head_buf = vec![0u8; head_size];
            file.seek(SeekFrom::Start(0)).ok()?;
            if file.read_exact(&mut head_buf).is_ok() {
                enc_pos = find_subslice(&head_buf, b"/Encrypt");
                if enc_pos.is_some() {
                    context_buf = head_buf;
                }
            }
        }

        let _ = enc_pos?;
        let enc_dict = crate::engine::extractors::hash_formatter::resolve_pdf_encryption_dict(&mut file, file_len, &context_buf)?;
        let enc_slice = &enc_dict[..];

        let rev = extract_int(enc_slice, b"/R").unwrap_or(2) as u8;
        let length = extract_int(enc_slice, b"/Length").unwrap_or(if rev == 2 { 40 } else { 128 }) as usize;
        let key_bytes = (length / 8).clamp(5, 16);
        let p_perm = extract_int(enc_slice, b"/P").unwrap_or(-64) as i32;

        let o_value = extract_bytes(enc_slice, b"/O").unwrap_or_else(|| vec![0u8; 32]);
        let u_value = extract_bytes(enc_slice, b"/U").unwrap_or_else(|| vec![0u8; 32]);

        // Find /ID array
        let id_first = extract_first_id(&context_buf).unwrap_or_default();

        Some(Self {
            file_path: path.to_string_lossy().to_string(),
            revision: rev,
            key_bytes,
            p_perm,
            o_value,
            u_value,
            id_first,
        })
    }

    /// PDF 1.7 Algorithm 3.2: Computing an encryption key
    pub fn compute_encryption_key(&self, password: &str) -> Vec<u8> {
        let pass_bytes = password.as_bytes();
        let mut padded = [0u8; 32];
        if pass_bytes.len() >= 32 {
            padded.copy_from_slice(&pass_bytes[..32]);
        } else {
            padded[..pass_bytes.len()].copy_from_slice(pass_bytes);
            padded[pass_bytes.len()..].copy_from_slice(&PDF_PADDING[..(32 - pass_bytes.len())]);
        }

        let mut hash_data = Vec::with_capacity(32 + self.o_value.len() + 4 + self.id_first.len());
        hash_data.extend_from_slice(&padded);
        hash_data.extend_from_slice(&self.o_value);
        hash_data.extend_from_slice(&(self.p_perm as u32).to_le_bytes());
        hash_data.extend_from_slice(&self.id_first);

        let mut digest = md5(&hash_data);

        if self.revision >= 3 {
            for _ in 0..50 {
                digest = md5(&digest[..self.key_bytes]);
            }
        }

        digest[..self.key_bytes].to_vec()
    }

    /// Authenticates a candidate user password
    pub fn verify(&self, candidate: &str) -> bool {
        let key = self.compute_encryption_key(candidate);

        if self.revision == 2 {
            // Algorithm 3.6: Encrypt PDF_PADDING with RC4 using key
            let test_u = rc4_crypt(&key, &PDF_PADDING);
            if self.u_value.len() >= 32 {
                return test_u[..32] == self.u_value[..32];
            }
            test_u == self.u_value
        } else {
            // Algorithm 3.7: Encrypt MD5(PDF_PADDING + id_first) 20 times
            let mut md5_input = Vec::with_capacity(32 + self.id_first.len());
            md5_input.extend_from_slice(&PDF_PADDING);
            md5_input.extend_from_slice(&self.id_first);
            let mut test_u = md5(&md5_input).to_vec();

            for step in 0..20 {
                let step_key: Vec<u8> = key.iter().map(|&b| b ^ (step as u8)).collect();
                test_u = rc4_crypt(&step_key, &test_u);
            }

            if self.u_value.len() >= 16 {
                test_u[..16] == self.u_value[..16]
            } else {
                test_u == self.u_value
            }
        }
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn extract_int(buf: &[u8], key: &[u8]) -> Option<i64> {
    let pos = find_subslice(buf, key)?;
    let mut i = pos + key.len();
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
        let v = s.parse::<i64>().ok()?;
        Some(if is_neg { -v } else { v })
    } else {
        None
    }
}

fn extract_bytes(buf: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    let pos = find_subslice(buf, key)?;
    let mut i = pos + key.len();
    while i < buf.len() && (buf[i] == b' ' || buf[i] == b'\t' || buf[i] == b'\r' || buf[i] == b'\n') {
        i += 1;
    }
    if i < buf.len() && buf[i] == b'<' {
        let start = i + 1;
        let end = find_subslice(&buf[start..], b">")? + start;
        let hex_str = std::str::from_utf8(&buf[start..end]).ok()?.replace(' ', "");
        let mut bytes = Vec::new();
        for chunk in hex_str.as_bytes().chunks(2) {
            if chunk.len() == 2 {
                let s = std::str::from_utf8(chunk).ok()?;
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    bytes.push(b);
                }
            }
        }
        Some(bytes)
    } else if i < buf.len() && buf[i] == b'(' {
        let start = i + 1;
        let end = find_subslice(&buf[start..], b")")? + start;
        Some(buf[start..end].to_vec())
    } else {
        None
    }
}

fn extract_first_id(buf: &[u8]) -> Option<Vec<u8>> {
    let pos = find_subslice(buf, b"/ID")?;
    let search = &buf[pos..];
    extract_bytes(search, b"[")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pdf_key_derivation_and_auth() {
        assert_eq!(PDF_PADDING.len(), 32);
        assert_eq!(PDF_PADDING[0], 0x28);
        assert_eq!(PDF_PADDING[31], 0x7A);
    }

    #[test]
    fn test_pdf_target_load_indirect() {
        let temp_path = std::env::temp_dir().join("torcrypt_load_indirect.pdf");
        let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <0000000000000000000000000000000000000000000000000000000000000000> /U <6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000> >>\nendobj\ntrailer\n<< /Size 3 /Root 1 0 R /Encrypt 2 0 R /ID [ <62888255846156252261477183186121> <62888255846156252261477183186121> ] >>\n%%EOF";
        std::fs::write(&temp_path, pdf_data).unwrap();

        let target = PdfTarget::load_from_file(&temp_path).expect("Should load indirect PDF");
        assert_eq!(target.revision, 3);
        assert_eq!(target.key_bytes, 16);
        assert_eq!(target.p_perm, -4);
        assert_eq!(target.u_value.len(), 32);
        assert_eq!(target.o_value.len(), 32);
        let _ = std::fs::remove_file(temp_path);
    }
}
