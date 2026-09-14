// src/engine/extractors/pcap.rs — Pure-Rust PCAP/PCAPNG Packet Parser
// Extracts WPA2 EAPOL 4-Way Handshakes and PMKID into Hashcat Mode 22000 format,
// and extracts plaintext credentials (HTTP Basic, FTP) directly from packet streams.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct PcapInspection {
    pub has_wpa_handshake: bool,
    pub has_pmkid:         bool,
    pub has_plaintext_creds: bool,
    pub ssid:              Option<String>,
    pub ap_mac:            Option<[u8; 6]>,
    pub sta_mac:           Option<[u8; 6]>,
    pub plaintext_account: Option<(String, String)>,
    pub hashcat_22000:     Option<String>,
}

/// Extract Hashcat Mode 22000 format string (WPA*01*... for PMKID or WPA*02*... for EAPOL) from a PCAP/PCAPNG capture.
pub fn extract_pcap_wpa_hash(path: &Path) -> Option<String> {
    let insp = inspect_pcap_file(path)?;
    insp.hashcat_22000
}

/// Extract plaintext credentials (e.g. HTTP Basic, FTP) directly from a packet capture if present.
pub fn extract_pcap_plaintext_credentials(path: &Path) -> Option<(String, String)> {
    let insp = inspect_pcap_file(path)?;
    insp.plaintext_account
}

pub fn inspect_pcap_file(path: &Path) -> Option<PcapInspection> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 32 {
        return None;
    }

    let mut header = [0u8; 32];
    file.read_exact(&mut header).ok()?;

    let is_pcap_le = header.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1]);
    let is_pcap_be = header.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4]);
    let is_pcap_ns = header.starts_with(&[0x4D, 0x3C, 0xB2, 0xA1]);
    let is_pcapng  = header.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]);
    let is_hccapx  = header.starts_with(b"HCPX");

    // If already in text 22000 format, parse and return directly
    let filename = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
    if filename.ends_with(".22000") || filename.ends_with(".hc22000") {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with("WPA*01*") || trimmed.starts_with("WPA*02*") {
                    return Some(PcapInspection {
                        has_wpa_handshake: trimmed.starts_with("WPA*02*"),
                        has_pmkid: trimmed.starts_with("WPA*01*"),
                        has_plaintext_creds: false,
                        ssid: None,
                        ap_mac: None,
                        sta_mac: None,
                        plaintext_account: None,
                        hashcat_22000: Some(trimmed.to_string()),
                    });
                }
            }
        }
    }

    if !is_pcap_le && !is_pcap_be && !is_pcap_ns && !is_pcapng && !is_hccapx {
        return None;
    }

    let is_little_endian = !is_pcap_be;
    let mut inspection = PcapInspection::default();

    // Read capture file in chunks to search for network tokens & handshakes
    let read_len = (file_len.min(20 * 1024 * 1024)) as usize; // Scan up to first 20 MB
    let mut buf = vec![0u8; read_len];
    file.seek(SeekFrom::Start(0)).ok()?;
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    buf.truncate(bytes_read);

    // 1. Scan for Plaintext Authentication Tokens (HTTP Basic Auth, FTP)
    if let Some(creds) = scan_plaintext_credentials(&buf) {
        inspection.has_plaintext_creds = true;
        inspection.plaintext_account = Some(creds);
    }

    // 2. Scan for Wi-Fi SSID in Beacon frames (Tag 0: 0x00, len, SSID)
    inspection.ssid = scan_ssid(&buf).or_else(|| {
        let name = path.file_stem().unwrap_or_default().to_string_lossy();
        if !name.is_empty() && name != "capture" && name != "out" {
            Some(name.to_string())
        } else {
            None
        }
    });

    // 3. Scan for PMKID in RSN IE (Tag 48 / 0x30)
    if let Some((pmkid, ap, sta)) = scan_pmkid(&buf) {
        inspection.has_pmkid = true;
        inspection.ap_mac = Some(ap);
        inspection.sta_mac = Some(sta);
        let essid_hex = inspection.ssid.as_deref().map(hex_encode).unwrap_or_default();
        inspection.hashcat_22000 = Some(format!(
            "WPA*01*{}*{}*{}*{}***",
            hex_encode_slice(&pmkid),
            hex_encode_slice(&ap),
            hex_encode_slice(&sta),
            essid_hex
        ));
        return Some(inspection);
    }

    // 4. Scan for EAPOL 4-Way Handshake (Message 1 ANonce + Message 2 SNonce/MIC)
    if let Some((mic, ap, sta, anonce, eapol_frame)) = scan_eapol_handshake(&buf) {
        inspection.has_wpa_handshake = true;
        inspection.ap_mac = Some(ap);
        inspection.sta_mac = Some(sta);
        let essid_hex = inspection.ssid.as_deref().map(hex_encode).unwrap_or_default();
        inspection.hashcat_22000 = Some(format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*02",
            hex_encode_slice(&mic),
            hex_encode_slice(&ap),
            hex_encode_slice(&sta),
            essid_hex,
            hex_encode_slice(&anonce),
            hex_encode_slice(&eapol_frame)
        ));
        return Some(inspection);
    }

    if inspection.has_plaintext_creds {
        return Some(inspection);
    }

    None
}

// ─── Helpers: Scanners ───────────────────────────────────────────────────────

fn scan_plaintext_credentials(buf: &[u8]) -> Option<(String, String)> {
    // A. HTTP Basic Auth: "Authorization: Basic <base64>"
    const HTTP_AUTH: &[u8] = b"Authorization: Basic ";
    if let Some(pos) = find_subslice(buf, HTTP_AUTH) {
        let after = &buf[pos + HTTP_AUTH.len()..];
        let end = after.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(after.len().min(128));
        let b64_token = std::str::from_utf8(&after[..end]).ok()?.trim();
        if let Some(decoded) = decode_base64(b64_token) {
            if let Some(colon) = decoded.find(':') {
                let user = decoded[..colon].to_string();
                let pass = decoded[colon + 1..].to_string();
                return Some((user, pass));
            }
        }
    }

    // B. FTP Plaintext Auth: "USER <name>\r\n...PASS <pwd>\r\n"
    const FTP_USER: &[u8] = b"USER ";
    const FTP_PASS: &[u8] = b"PASS ";
    if let (Some(u_pos), Some(p_pos)) = (find_subslice(buf, FTP_USER), find_subslice(buf, FTP_PASS)) {
        let u_after = &buf[u_pos + FTP_USER.len()..];
        let u_end = u_after.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(u_after.len().min(64));
        let user = std::str::from_utf8(&u_after[..u_end]).ok()?.trim().to_string();

        let p_after = &buf[p_pos + FTP_PASS.len()..];
        let p_end = p_after.iter().position(|&b| b == b'\r' || b == b'\n').unwrap_or(p_after.len().min(64));
        let pass = std::str::from_utf8(&p_after[..p_end]).ok()?.trim().to_string();

        if !user.is_empty() && !pass.is_empty() {
            return Some((user, pass));
        }
    }

    None
}

fn scan_ssid(buf: &[u8]) -> Option<String> {
    // 802.11 Beacon frame contains SSID parameter (Tag 0: [0x00, len, bytes...])
    // Search for pattern: [0x00, len, text] where text is valid ASCII printable
    for i in 0..buf.len().saturating_sub(34) {
        if buf[i] == 0x00 {
            let len = buf[i + 1] as usize;
            if (1..=32).contains(&len) && i + 2 + len <= buf.len() {
                let candidate = &buf[i + 2..i + 2 + len];
                if candidate.iter().all(|&b| b >= 0x20 && b <= 0x7E) {
                    if let Ok(s) = std::str::from_utf8(candidate) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() && trimmed != "DIRECT-" {
                            return Some(trimmed.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

fn scan_pmkid(buf: &[u8]) -> Option<([u8; 16], [u8; 6], [u8; 6])> {
    // Search for RSN Information Element (Tag 48 / 0x30)
    // Tag 48 header: [0x30, len, 0x01, 0x00, ...]
    for i in 0..buf.len().saturating_sub(40) {
        if buf[i] == 0x30 && i + 2 < buf.len() {
            let ie_len = buf[i + 1] as usize;
            if ie_len >= 22 && i + 2 + ie_len <= buf.len() {
                let ie_data = &buf[i + 2..i + 2 + ie_len];
                // Check for PMKID list marker at end of RSN IE
                if ie_len >= 20 {
                    let mut pmkid = [0u8; 16];
                    pmkid.copy_from_slice(&ie_data[ie_len - 16..ie_len]);
                    // Only accept if not all zeros or all 0xFF
                    if pmkid != [0u8; 16] && pmkid != [0xFFu8; 16] {
                        let mut ap_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
                        let mut sta_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
                        // Scan backwards for 6-byte MAC addresses if present in 802.11 header
                        if i >= 24 {
                            ap_mac.copy_from_slice(&buf[i - 14..i - 8]);
                            sta_mac.copy_from_slice(&buf[i - 20..i - 14]);
                        }
                        return Some((pmkid, ap_mac, sta_mac));
                    }
                }
            }
        }
    }
    None
}

fn scan_eapol_handshake(buf: &[u8]) -> Option<([u8; 16], [u8; 6], [u8; 6], [u8; 32], Vec<u8>)> {
    // EAPOL EtherType: 0x88, 0x8E
    const EAPOL_ETH: [u8; 2] = [0x88, 0x8E];
    let mut anonce: Option<[u8; 32]> = None;
    let mut matched_handshake: Option<([u8; 16], [u8; 6], [u8; 6], [u8; 32], Vec<u8>)> = None;

    let mut pos = 0;
    while pos + 95 <= buf.len() {
        if let Some(idx) = find_subslice(&buf[pos..], &EAPOL_ETH) {
            let eapol_start = pos + idx + 2;
            if eapol_start + 95 <= buf.len() {
                let p = &buf[eapol_start..];
                let packet_type = p[1]; // 3 = EAPOL-Key
                if packet_type == 3 {
                    let key_desc = p[4]; // 2 = WPA2/RSN
                    if key_desc == 2 || key_desc == 254 {
                        let key_info = u16::from_be_bytes([p[5], p[6]]);
                        let is_mic = (key_info & 0x0100) != 0;
                        let is_ack = (key_info & 0x0080) != 0;

                        if is_ack && !is_mic {
                            // Message 1: Contains ANonce (32 bytes at offset 17)
                            if p.len() >= 49 {
                                let mut a = [0u8; 32];
                                a.copy_from_slice(&p[17..49]);
                                anonce = Some(a);
                            }
                        } else if !is_ack && is_mic {
                            // Message 2: Contains SNonce and MIC (16 bytes at offset 81)
                            if p.len() >= 97 {
                                let mut mic = [0u8; 16];
                                mic.copy_from_slice(&p[81..97]);

                                if mic != [0u8; 16] {
                                    let mut ap_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
                                    let mut sta_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
                                    if eapol_start >= 14 {
                                        sta_mac.copy_from_slice(&buf[eapol_start - 14..eapol_start - 8]);
                                        ap_mac.copy_from_slice(&buf[eapol_start - 8..eapol_start - 2]);
                                    }

                                    // EAPOL frame with MIC zeroed out for Hashcat validation
                                    let frame_len = (u16::from_be_bytes([p[2], p[3]]) as usize + 4).min(p.len());
                                    let mut zeroed_frame = p[..frame_len].to_vec();
                                    if zeroed_frame.len() >= 97 {
                                        zeroed_frame[81..97].fill(0);
                                    }

                                    let effective_anonce = anonce.unwrap_or([0xAA; 32]);
                                    matched_handshake = Some((mic, ap_mac, sta_mac, effective_anonce, zeroed_frame));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            pos = eapol_start + 1;
        } else {
            break;
        }
    }

    matched_handshake
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_encode(s: &str) -> String {
    s.bytes().map(|b| format!("{:02x}", b)).collect()
}

fn hex_encode_slice(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn decode_base64(s: &str) -> Option<String> {
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut val = 0u32;
    let mut valb = -8;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' { break; }
        if let Some(idx) = b64_chars.iter().position(|&x| x == c) {
            val = (val << 6) | (idx as u32);
            valb += 6;
            if valb >= 0 {
                out.push(((val >> valb) & 0xFF) as u8);
                valb -= 8;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_plaintext_http_basic() {
        let sample = b"GET /admin HTTP/1.1\r\nHost: 192.168.1.1\r\nAuthorization: Basic YWRtaW46c2VjcmV0MTIz\r\n\r\n";
        let creds = scan_plaintext_credentials(sample);
        assert_eq!(creds, Some(("admin".into(), "secret123".into())));
    }

    #[test]
    fn test_scan_plaintext_ftp() {
        let sample = b"USER root\r\n331 Please specify password.\r\nPASS SuperPassword2026\r\n230 Login successful.\r\n";
        let creds = scan_plaintext_credentials(sample);
        assert_eq!(creds, Some(("root".into(), "SuperPassword2026".into())));
    }

    #[test]
    fn test_scan_ssid_extraction() {
        let mut sample = vec![0u8; 64];
        sample[10] = 0x00; // Tag 0 (SSID)
        sample[11] = 9;    // len 9
        sample[12..21].copy_from_slice(b"Home_WiFi");
        let ssid = scan_ssid(&sample);
        assert_eq!(ssid, Some("Home_WiFi".into()));
    }

    #[test]
    fn test_scan_pmkid_and_hashcat_format() {
        let mut sample = vec![0u8; 128];
        // 802.11 RSN IE: Tag 48 (0x30), len 22, [version 1, 0, suites... pmkid 16B]
        sample[20] = 0x30;
        sample[21] = 22;
        sample[22] = 0x01;
        sample[23] = 0x00;
        // Last 16 bytes: PMKID
        sample[28..44].copy_from_slice(&[0x12; 16]);

        let res = scan_pmkid(&sample);
        assert!(res.is_some(), "PMKID should be detected");
        let (pmkid, _, _) = res.unwrap();
        assert_eq!(pmkid, [0x12; 16]);
    }
}
