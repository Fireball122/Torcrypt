// src/engine/extractors/hash_formatter.rs — In-Process Hash String Formatter
// Formats binary archive headers into standard Hashcat and John the Ripper hash formats ($zip2$, $pdf$, $7z$, $rar5$)
// eliminating dependencies on external Perl/Python helper scripts (*2john).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Generate an authentic Hashcat/John the Ripper hash string directly from an encrypted archive.
pub fn format_archive_hash(target_path: &Path) -> Option<String> {
    let ext = target_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_lowercase();

    match ext.as_str() {
        "zip" | "jar" => format_zip_hash(target_path),
        "pdf"         => format_pdf_hash(target_path),
        "7z"          => format_7z_hash(target_path),
        "rar"         => format_rar5_hash(target_path),
        _             => None,
    }
}

// ─── ZIP Format ($zip2$) ───────────────────────────────────────────────────────

fn format_zip_hash(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    if &magic != b"PK\x03\x04" {
        return None;
    }

    let mut hdr = [0u8; 26];
    file.read_exact(&mut hdr).ok()?;

    let flags = u16::from_le_bytes([hdr[2], hdr[3]]);
    let method = u16::from_le_bytes([hdr[4], hdr[5]]);
    let mod_time = u16::from_le_bytes([hdr[6], hdr[7]]);
    let crc32 = u32::from_le_bytes([hdr[10], hdr[11], hdr[12], hdr[13]]);
    let fn_len = u16::from_le_bytes([hdr[22], hdr[23]]) as usize;
    let ef_len = u16::from_le_bytes([hdr[24], hdr[25]]) as usize;

    let is_encrypted = (flags & 0x0001) != 0;
    if !is_encrypted {
        return None;
    }

    file.seek(SeekFrom::Current(fn_len as i64)).ok()?;

    let mut ef_buf = vec![0u8; ef_len];
    if ef_len > 0 {
        file.read_exact(&mut ef_buf).ok()?;
    }

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

    if is_winzip {
        let salt_len = if aes_bits == 128 { 8 } else { 16 };
        let mut salt = vec![0u8; salt_len];
        file.read_exact(&mut salt).ok()?;
        let mut verifier = [0u8; 2];
        file.read_exact(&mut verifier).ok()?;

        let mut sample = vec![0u8; 32];
        let n = file.read(&mut sample).unwrap_or(0);
        sample.truncate(n);

        let salt_hex = to_hex(&salt);
        let verifier_hex = to_hex(&verifier);
        let data_hex = to_hex(&sample);

        // Standard $zip2$ WinZip AES line (Mode 3)
        Some(format!(
            "$zip2$*0*3*0*{}*{}*{}*{}*{}*{}*{:08x}*$/zip2$",
            verifier_hex,
            salt_len,
            salt_hex,
            verifier_hex,
            sample.len(),
            data_hex,
            crc32
        ))
    } else {
        // ZipCrypto Traditional (Mode 1)
        let mut enc_header = [0u8; 12];
        file.read_exact(&mut enc_header).ok()?;

        let mut sample = vec![0u8; 32];
        let n = file.read(&mut sample).unwrap_or(0);
        sample.truncate(n);

        let check_byte = if (flags & 0x0008) != 0 {
            (mod_time >> 8) as u8
        } else {
            (crc32 >> 24) as u8
        };

        let hdr_hex = to_hex(&enc_header);
        let data_hex = to_hex(&sample);

        // Standard $zip2$ ZipCrypto line (Mode 1)
        Some(format!(
            "$zip2$*0*1*0*{:08x}*{:04x}*{:02x}*{}*{}*{}*$/zip2$",
            crc32,
            mod_time,
            check_byte,
            hdr_hex,
            sample.len(),
            data_hex
        ))
    }
}

// ─── PDF Format ($pdf$) ────────────────────────────────────────────────────────

/// Resolves the encryption dictionary buffer from either a direct dictionary
/// or by following an indirect object reference (`<N> <gen> R` -> `<N> <gen> obj`).
pub fn resolve_pdf_encryption_dict(file: &mut File, file_len: u64, trailer_ctx: &[u8]) -> Option<Vec<u8>> {
    let enc_pos = find_subslice(trailer_ctx, b"/Encrypt")?;
    let after = &trailer_ctx[enc_pos + b"/Encrypt".len()..];

    // Skip whitespace
    let mut i = 0;
    while i < after.len() && (after[i] == b' ' || after[i] == b'\t' || after[i] == b'\r' || after[i] == b'\n') {
        i += 1;
    }

    if i + 1 < after.len() && after[i] == b'<' && after[i + 1] == b'<' {
        // Direct dictionary
        let dict_end = find_subslice(&after[i..], b">>").unwrap_or(after.len().saturating_sub(i));
        return Some(after[i..i + dict_end + 2].to_vec());
    }

    // Indirect reference: "<obj_num> <gen_num> R"
    let slice_str = std::str::from_utf8(&after[i..after.len().min(i + 48)]).ok()?;
    let mut tokens = slice_str.split_whitespace();
    let obj_num_str = tokens.next()?;
    let gen_num_str = tokens.next()?;
    let r_token = tokens.next()?;
    if r_token != "R" {
        return None;
    }
    let obj_num: u32 = obj_num_str.parse().ok()?;
    let gen_num: u32 = gen_num_str.parse().ok()?;

    let target_needle = format!("{} {} obj", obj_num, gen_num);
    let needle_bytes = target_needle.as_bytes();

    // Stream through file in 64KB blocks with 128-byte overlap to find object definition
    let mut buf = vec![0u8; 65536];
    let mut cur_offset = 0u64;
    while cur_offset < file_len {
        if file.seek(SeekFrom::Start(cur_offset)).is_err() { break; }
        let bytes_read = file.read(&mut buf).unwrap_or(0);
        if bytes_read == 0 { break; }

        if let Some(pos) = find_subslice(&buf[..bytes_read], needle_bytes) {
            let obj_offset = cur_offset + pos as u64;
            let read_len = (file_len.saturating_sub(obj_offset)).min(4096) as usize;
            let mut dict_buf = vec![0u8; read_len];
            if file.seek(SeekFrom::Start(obj_offset)).is_ok() && file.read_exact(&mut dict_buf).is_ok() {
                return Some(dict_buf);
            }
        }

        if cur_offset + 65536 >= file_len { break; }
        cur_offset += 65536 - 128;
    }

    None
}

fn format_pdf_hash(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 32 {
        return None;
    }

    let scan_size = (file_len.min(65536)) as usize;
    let mut scan_buf = vec![0u8; scan_size];
    let scan_start = file_len - scan_size as u64;
    file.seek(SeekFrom::Start(scan_start)).ok()?;
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
    let enc_dict = resolve_pdf_encryption_dict(&mut file, file_len, &context_buf)?;
    let enc_slice = &enc_dict[..];

    let v: u8 = parse_pdf_val(enc_slice, b"/V").unwrap_or(1);
    let r: u8 = parse_pdf_val(enc_slice, b"/R").unwrap_or(2);
    let length_bits: u16 = parse_pdf_val(enc_slice, b"/Length").unwrap_or(if v == 1 { 40 } else { 128 });
    let p: i32 = parse_pdf_val(enc_slice, b"/P").unwrap_or(-4);

    let o_hex = parse_pdf_hex_string(enc_slice, b"/O")?;
    let u_hex = parse_pdf_hex_string(enc_slice, b"/U")?;
    let id_hex = parse_pdf_hex_string(&context_buf, b"/ID").unwrap_or_else(|| "00000000000000000000000000000000".into());

    let id_len = id_hex.len() / 2;
    let u_len = u_hex.len() / 2;
    let o_len = o_hex.len() / 2;

    // Standard $pdf$ format for Hashcat Mode 10500/10400 & JtR:
    // $pdf$<V>*<R>*<length_bits>*<P>*<enc_meta>*<id_len>*<id>*<u_len>*<u>*<o_len>*<o>
    Some(format!(
        "$pdf${}*{}*{}*{}*1*{}*{}*{}*{}*{}*{}",
        v,
        r,
        length_bits,
        p,
        id_len,
        id_hex,
        u_len,
        u_hex,
        o_len,
        o_hex
    ))
}

// ─── 7-Zip Format ($7z$) ───────────────────────────────────────────────────────

pub fn read_7z_vint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos >= buf.len() { return None; }
    let first = buf[*pos]; *pos += 1;
    let mask = 0x80u8;
    let mut value = 0u64;
    for i in 0..8 {
        if (first & (mask >> i)) == 0 {
            let high_bits = (first & ((mask >> i) - 1)) as u64;
            value |= high_bits << (8 * i);
            for j in 0..i {
                if *pos >= buf.len() { return None; }
                let b = buf[*pos] as u64; *pos += 1;
                value |= b << (8 * j);
            }
            return Some(value);
        }
    }
    for j in 0..8 {
        if *pos >= buf.len() { return None; }
        let b = buf[*pos] as u64; *pos += 1;
        value |= b << (8 * j);
    }
    Some(value)
}

fn format_7z_hash(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 32 {
        return None;
    }

    let mut sig_hdr = [0u8; 32];
    file.read_exact(&mut sig_hdr).ok()?;
    if sig_hdr[0..6] != [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] {
        return None;
    }

    let next_header_offset = u64::from_le_bytes([
        sig_hdr[12], sig_hdr[13], sig_hdr[14], sig_hdr[15],
        sig_hdr[16], sig_hdr[17], sig_hdr[18], sig_hdr[19],
    ]);
    let next_header_size = u64::from_le_bytes([
        sig_hdr[20], sig_hdr[21], sig_hdr[22], sig_hdr[23],
        sig_hdr[24], sig_hdr[25], sig_hdr[26], sig_hdr[27],
    ]);
    let next_header_crc = u32::from_le_bytes([
        sig_hdr[28], sig_hdr[29], sig_hdr[30], sig_hdr[31],
    ]);

    if next_header_offset == 0 || (32 + next_header_offset) >= file_len {
        return None;
    }

    let actual_pos = 32 + next_header_offset;
    file.seek(SeekFrom::Start(actual_pos)).ok()?;

    let hdr_buf_len = (next_header_size.min(4096)) as usize;
    let mut hdr_buf = vec![0u8; hdr_buf_len];
    file.read_exact(&mut hdr_buf).ok()?;

    // Parse 7zAES coder properties: Coder ID [0x06, 0xF1, 0x07, 0x01]
    let mut num_cycles_power = 19u8;
    let mut salt: Vec<u8> = Vec::new();
    let mut iv: Vec<u8> = vec![0u8; 16];

    if let Some(pos) = find_subslice(&hdr_buf, &[0x06, 0xF1, 0x07, 0x01]) {
        let mut p = pos + 4; // skip method ID
        let _prop_size = read_7z_vint(&hdr_buf, &mut p).unwrap_or(0);
        if p < hdr_buf.len() {
            let b0 = hdr_buf[p]; p += 1;
            num_cycles_power = b0 & 0x3F;
            let has_iv = (b0 & 0x40) != 0;
            let has_salt = (b0 & 0x80) != 0;

            if (has_iv || has_salt) && p < hdr_buf.len() {
                let b1 = hdr_buf[p]; p += 1;
                let salt_size = if has_salt { (((b1 >> 4) & 0x0F) + 1) as usize } else { 0 };
                let iv_size = if has_iv { ((b1 & 0x0F) + 1) as usize } else { 0 };

                if p + salt_size <= hdr_buf.len() {
                    salt = hdr_buf[p..p + salt_size].to_vec();
                    p += salt_size;
                }
                if p + iv_size <= hdr_buf.len() {
                    iv = hdr_buf[p..p + iv_size].to_vec();
                }
            }
        }
    }

    // In 7z archives with encrypted headers, the packed data stream begins at offset 32
    file.seek(SeekFrom::Start(32)).ok()?;
    let sample_len = (next_header_offset.min(64)) as usize;
    let mut sample_buf = vec![0u8; sample_len.max(16)];
    let bytes_read = file.read(&mut sample_buf).unwrap_or(0);
    sample_buf.truncate(bytes_read);

    let salt_hex = to_hex(&salt);
    let iv_hex = to_hex(&iv);
    let data_hex = to_hex(&sample_buf);

    // Standard $7z$ hash format for Hashcat Mode 11600 & JtR:
    // $7z$0$<numCyclesPower>$<salt_len>$<salt_hex>$<iv_len>$<iv_hex>$<crc32>$<unpack_size>$<pack_size>$<data_hex>
    Some(format!(
        "$7z$0${}${}${}${}${}${}${}${}${}",
        num_cycles_power,
        salt.len(),
        salt_hex,
        iv.len(),
        iv_hex,
        next_header_crc,
        next_header_size,
        sample_buf.len(),
        data_hex
    ))
}

// ─── RAR5 Format ($rar5$) ─────────────────────────────────────────────────────

fn format_rar5_hash(path: &Path) -> Option<String> {
    let target = crate::engine::crackers::rar::Rar5Target::load_from_file(path)?;
    let salt_hex = to_hex(&target.salt);
    let check_hex = to_hex(&target.psw_check);
    let log2_rounds = (31 - target.rounds.leading_zeros()).max(1);
    Some(format!(
        "$rar5${}${}${}$00000000000000000000000000000000${}${}",
        target.salt.len(),
        salt_hex,
        log2_rounds,
        target.psw_check.len(),
        check_hex
    ))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

pub fn parse_pdf_val<T: std::str::FromStr>(buf: &[u8], key: &[u8]) -> Option<T> {
    let pos = find_subslice(buf, key)?;
    let after = &buf[pos + key.len()..];
    let text = std::str::from_utf8(after).ok()?;
    let mut tokens = text.split_whitespace();
    let val_str = tokens.next()?;
    val_str.trim_matches(|c: char| !c.is_ascii_digit() && c != '-').parse::<T>().ok()
}

pub fn parse_pdf_hex_string(buf: &[u8], key: &[u8]) -> Option<String> {
    let pos = find_subslice(buf, key)?;
    let after = &buf[pos + key.len()..];
    let start = after.iter().position(|&b| b == b'<' || b == b'(')?;
    let delimiter = after[start];
    let end_delim = if delimiter == b'<' { b'>' } else { b')' };
    let end = after[start + 1..].iter().position(|&b| b == end_delim)?;
    let raw = &after[start + 1..start + 1 + end];

    if delimiter == b'<' {
        let hex_str: String = raw.iter()
            .filter(|&&b| b.is_ascii_hexdigit())
            .map(|&b| b as char)
            .collect();
        if !hex_str.is_empty() {
            return Some(hex_str.to_lowercase());
        }
    } else {
        return Some(to_hex(raw));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_zip_hash_on_real_fixture() {
        let temp_path = std::env::temp_dir().join("torcrypt_fmt_test.zip");
        crate::engine::tests::create_test_zip(&temp_path, "secret123");

        let hash_opt = format_archive_hash(&temp_path);
        assert!(hash_opt.is_some(), "Should format zip hash in-process");
        let hash_str = hash_opt.unwrap();
        assert!(hash_str.starts_with("$zip2$*0*1*0*"), "Must be valid $zip2$ format, got: {}", hash_str);

        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn test_format_pdf_hash_indirect_object() {
        let temp_path = std::env::temp_dir().join("torcrypt_indirect_test.pdf");
        let pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n2 0 obj\n<< /Filter /Standard /V 2 /R 3 /Length 128 /P -4 /O <0000000000000000000000000000000000000000000000000000000000000000> /U <6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000> >>\nendobj\ntrailer\n<< /Size 3 /Root 1 0 R /Encrypt 2 0 R /ID [ <62888255846156252261477183186121> <62888255846156252261477183186121> ] >>\n%%EOF";
        std::fs::write(&temp_path, pdf_data).unwrap();

        let hash_opt = format_archive_hash(&temp_path);
        assert!(hash_opt.is_some(), "Should format PDF with indirect /Encrypt object");
        let hash_str = hash_opt.unwrap();
        assert!(hash_str.starts_with("$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*"), "Must match Hashcat mode 10500 format: {}", hash_str);

        let _ = std::fs::remove_file(&temp_path);
    }
}
