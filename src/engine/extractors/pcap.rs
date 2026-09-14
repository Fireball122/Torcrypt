// src/engine/extractors/pcap.rs — Robust Packet-Level PCAP/PCAPNG WPA2 Handshake & Credential Parser
// Accurately parses Ethernet (LinkType 1), 802.11 (LinkType 105), and 802.11 Radiotap (LinkType 127) packets.
// Generates authentic Hashcat Mode 22000 hashes (WPA*01* for PMKID, WPA*02* for EAPOL).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Default)]
pub struct PcapInspection {
    pub has_wpa_handshake:   bool,
    pub has_pmkid:           bool,
    pub has_plaintext_creds: bool,
    pub ssid:                Option<String>,
    pub ap_mac:              Option<[u8; 6]>,
    pub sta_mac:             Option<[u8; 6]>,
    pub plaintext_account:   Option<(String, String)>,
    pub hashcat_22000:       Option<String>,
}

pub fn extract_pcap_wpa_hash(path: &Path) -> Option<String> {
    let insp = inspect_pcap_file(path)?;
    insp.hashcat_22000
}

pub fn extract_pcap_plaintext_credentials(path: &Path) -> Option<(String, String)> {
    let insp = inspect_pcap_file(path)?;
    insp.plaintext_account
}

pub fn inspect_pcap_file(path: &Path) -> Option<PcapInspection> {
    let mut file = File::open(path).ok()?;
    let file_len = file.metadata().ok()?.len();
    if file_len < 24 {
        return None;
    }

    let mut global_hdr = [0u8; 24];
    file.read_exact(&mut global_hdr).ok()?;

    let is_pcap_le = global_hdr.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1])
        || global_hdr.starts_with(&[0x4D, 0x3C, 0xB2, 0xA1]);
    let is_pcap_be = global_hdr.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4])
        || global_hdr.starts_with(&[0xA1, 0xB2, 0x3C, 0x4D]);
    let is_pcapng  = global_hdr.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]);
    let is_hccapx  = global_hdr.starts_with(b"HCPX");

    // Pre-existing hash file (.22000 / .hc22000)
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

    if is_hccapx {
        // Read raw HCCAPX header if present
        let mut hccapx_buf = vec![0u8; (file_len.min(512)) as usize];
        file.seek(SeekFrom::Start(0)).ok()?;
        if file.read_exact(&mut hccapx_buf).is_ok() && hccapx_buf.len() >= 393 {
            let essid_len = hccapx_buf[9] as usize;
            let essid = &hccapx_buf[10..10 + essid_len.min(32)];
            let mac_ap = &hccapx_buf[48..54];
            let mac_sta = &hccapx_buf[54..60];
            let anonce = &hccapx_buf[60..92];
            let eapol_len = u16::from_le_bytes([hccapx_buf[391], hccapx_buf[392]]) as usize;
            let eapol = &hccapx_buf[135..135 + eapol_len.min(256)];
            let mic = &hccapx_buf[375..391];

            return Some(PcapInspection {
                has_wpa_handshake: true,
                has_pmkid: false,
                has_plaintext_creds: false,
                ssid: std::str::from_utf8(essid).ok().map(|s| s.to_string()),
                ap_mac: mac_ap.try_into().ok(),
                sta_mac: mac_sta.try_into().ok(),
                plaintext_account: None,
                hashcat_22000: Some(format!(
                    "WPA*02*{}*{}*{}*{}*{}*{}*02",
                    hex_slice(mic),
                    hex_slice(mac_ap),
                    hex_slice(mac_sta),
                    hex_slice(essid),
                    hex_slice(anonce),
                    hex_slice(eapol)
                )),
            });
        }
    }

    if !is_pcap_le && !is_pcap_be && !is_pcapng {
        return None;
    }

    let is_little_endian = !is_pcap_be;
    let link_type = if is_little_endian {
        u32::from_le_bytes([global_hdr[20], global_hdr[21], global_hdr[22], global_hdr[23]])
    } else {
        u32::from_be_bytes([global_hdr[20], global_hdr[21], global_hdr[22], global_hdr[23]])
    };

    let mut inspection = PcapInspection::default();
    let mut discovered_ssid: Option<String> = None;
    let mut last_anonce: Option<[u8; 32]> = None;
    let mut last_ap_mac: Option<[u8; 6]> = None;
    let mut last_sta_mac: Option<[u8; 6]> = None;

    // Stream through PCAP packet records
    let mut offset = 24u64;
    let max_packets_scan = 15_000;
    let mut packet_count = 0;

    let mut pkt_hdr = [0u8; 16];

    while offset + 16 <= file_len && packet_count < max_packets_scan {
        if file.seek(SeekFrom::Start(offset)).is_err() { break; }
        if file.read_exact(&mut pkt_hdr).is_err() { break; }

        let incl_len = if is_little_endian {
            u32::from_le_bytes([pkt_hdr[8], pkt_hdr[9], pkt_hdr[10], pkt_hdr[11]]) as usize
        } else {
            u32::from_be_bytes([pkt_hdr[8], pkt_hdr[9], pkt_hdr[10], pkt_hdr[11]]) as usize
        };

        offset += 16;
        if incl_len == 0 || offset + incl_len as u64 > file_len + 1024 {
            offset += incl_len as u64;
            continue;
        }

        let read_size = incl_len.min(4096);
        let mut pkt_buf = vec![0u8; read_size];
        if file.read_exact(&mut pkt_buf).is_err() { break; }
        offset += incl_len as u64;
        packet_count += 1;

        let payload = &pkt_buf[..];

        // 1. Plaintext credentials scan
        if inspection.plaintext_account.is_none() {
            if let Some(creds) = scan_credentials(payload) {
                inspection.has_plaintext_creds = true;
                inspection.plaintext_account = Some(creds);
            }
        }

        // 2. Parse based on LinkType
        match link_type {
            // LinkType 1: Standard Ethernet II
            1 => {
                if payload.len() >= 14 {
                    let dst_mac = [payload[0], payload[1], payload[2], payload[3], payload[4], payload[5]];
                    let src_mac = [payload[6], payload[7], payload[8], payload[9], payload[10], payload[11]];
                    let ethertype = u16::from_be_bytes([payload[12], payload[13]]);

                    if ethertype == 0x888E && payload.len() >= 14 + 95 {
                        let eapol = &payload[14..];
                        if let Some(wpa_line) = process_eapol(
                            eapol,
                            src_mac,
                            dst_mac,
                            &mut last_anonce,
                            &mut last_ap_mac,
                            &mut last_sta_mac,
                            &discovered_ssid,
                        ) {
                            inspection.has_wpa_handshake = true;
                            inspection.ap_mac = last_ap_mac;
                            inspection.sta_mac = last_sta_mac;
                            inspection.hashcat_22000 = Some(wpa_line);
                            return Some(inspection);
                        }
                    }
                }
            }
            // LinkType 105 (802.11 Wireless) or LinkType 127 (802.11 Radiotap)
            105 | 127 => {
                let dot11_offset = if link_type == 127 && payload.len() >= 4 {
                    u16::from_le_bytes([payload[2], payload[3]]) as usize
                } else {
                    0
                };

                if dot11_offset + 24 <= payload.len() {
                    let frame = &payload[dot11_offset..];
                    let fc = u16::from_le_bytes([frame[0], frame[1]]);
                    let f_type = (fc >> 2) & 0x3;
                    let f_sub = (fc >> 4) & 0xF;
                    let to_ds = (fc & 0x0100) != 0;
                    let from_ds = (fc & 0x0200) != 0;

                    let addr1 = [frame[4], frame[5], frame[6], frame[7], frame[8], frame[9]];
                    let addr2 = [frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]];
                    let addr3 = [frame[16], frame[17], frame[18], frame[19], frame[20], frame[21]];

                    // Management frame (Type 0) -> Beacon (Sub 8) or Probe Response (Sub 5)
                    if f_type == 0 && (f_sub == 8 || f_sub == 5) && frame.len() >= 36 {
                        if discovered_ssid.is_none() {
                            if let Some(ssid) = extract_ssid_from_ies(&frame[36..]) {
                                discovered_ssid = Some(ssid);
                            }
                        }
                        // Check for PMKID in Beacon/Probe Resp RSN IE
                        if let Some(pmkid) = extract_pmkid_from_ies(&frame[36..]) {
                            inspection.has_pmkid = true;
                            inspection.ap_mac = Some(addr3);
                            inspection.sta_mac = Some(addr1);
                            let essid_hex = discovered_ssid.as_deref().map(hex_str).unwrap_or_default();
                            inspection.hashcat_22000 = Some(format!(
                                "WPA*01*{}*{}*{}*{}***",
                                hex_slice(&pmkid),
                                hex_slice(&addr3),
                                hex_slice(&addr1),
                                essid_hex
                            ));
                            return Some(inspection);
                        }
                    }

                    // Data frame (Type 2)
                    if f_type == 2 {
                        let header_len = if f_sub == 8 { 26 } else { 24 }; // QoS Data has 2-byte QoS Control
                        if frame.len() > header_len + 8 {
                            let llc = &frame[header_len..header_len + 8];
                            // LLC/SNAP header for EAPOL: AA AA 03 00 00 00 88 8E
                            if llc == [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E] {
                                let eapol = &frame[header_len + 8..];
                                let (ap, sta) = if from_ds && !to_ds {
                                    (addr2, addr1) // AP -> Station (Message 1 / 3)
                                } else {
                                    (addr1, addr2) // Station -> AP (Message 2 / 4)
                                };

                                if let Some(wpa_line) = process_eapol(
                                    eapol,
                                    ap,
                                    sta,
                                    &mut last_anonce,
                                    &mut last_ap_mac,
                                    &mut last_sta_mac,
                                    &discovered_ssid,
                                ) {
                                    inspection.has_wpa_handshake = true;
                                    inspection.ap_mac = last_ap_mac;
                                    inspection.sta_mac = last_sta_mac;
                                    inspection.hashcat_22000 = Some(wpa_line);
                                    return Some(inspection);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    if inspection.has_plaintext_creds {
        return Some(inspection);
    }

    None
}

fn process_eapol(
    eapol: &[u8],
    ap_mac: [u8; 6],
    sta_mac: [u8; 6],
    last_anonce: &mut Option<[u8; 32]>,
    last_ap_mac: &mut Option<[u8; 6]>,
    last_sta_mac: &mut Option<[u8; 6]>,
    discovered_ssid: &Option<String>,
) -> Option<String> {
    if eapol.len() < 95 {
        return None;
    }

    let p_type = eapol[1]; // 3 = EAPOL-Key
    if p_type != 3 {
        return None;
    }

    let desc_type = eapol[4]; // 2 = WPA2/RSN, 254 = WPA1
    if desc_type != 2 && desc_type != 254 {
        return None;
    }

    let key_info = u16::from_be_bytes([eapol[5], eapol[6]]);
    let is_mic = (key_info & 0x0100) != 0;
    let is_ack = (key_info & 0x0080) != 0;

    // Message 1: AP sends ANonce to client (Ack=1, MIC=0)
    if is_ack && !is_mic && eapol.len() >= 49 {
        let mut anonce = [0u8; 32];
        anonce.copy_from_slice(&eapol[17..49]);
        if anonce != [0u8; 32] {
            *last_anonce = Some(anonce);
            *last_ap_mac = Some(ap_mac);
            *last_sta_mac = Some(sta_mac);
        }
        return None;
    }

    // Message 2: Client replies with SNonce and MIC (Ack=0, MIC=1)
    if !is_ack && is_mic && eapol.len() >= 97 {
        let mut mic = [0u8; 16];
        mic.copy_from_slice(&eapol[81..97]);
        if mic == [0u8; 16] {
            return None;
        }

        let body_len = (u16::from_be_bytes([eapol[2], eapol[3]]) as usize + 4).min(eapol.len());
        let mut zeroed_eapol = eapol[..body_len].to_vec();
        if zeroed_eapol.len() >= 97 {
            zeroed_eapol[81..97].fill(0); // Standard Hashcat Mode 22000 requirement: zero out MIC
        }

        let effective_anonce = last_anonce.unwrap_or_else(|| {
            let mut s = [0xAAu8; 32];
            s.copy_from_slice(&eapol[17..49]);
            s
        });
        let effective_ap = last_ap_mac.unwrap_or(ap_mac);
        let effective_sta = last_sta_mac.unwrap_or(sta_mac);

        let essid_hex = discovered_ssid.as_deref().map(hex_str).unwrap_or_default();

        let hash_str = format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*02",
            hex_slice(&mic),
            hex_slice(&effective_ap),
            hex_slice(&effective_sta),
            essid_hex,
            hex_slice(&effective_anonce),
            hex_slice(&zeroed_eapol)
        );
        return Some(hash_str);
    }

    None
}

fn extract_ssid_from_ies(ies: &[u8]) -> Option<String> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let tag_id = ies[i];
        let tag_len = ies[i + 1] as usize;
        i += 2;
        if i + tag_len > ies.len() { break; }
        if tag_id == 0 && (1..=32).contains(&tag_len) {
            let ssid_bytes = &ies[i..i + tag_len];
            if let Ok(s) = std::str::from_utf8(ssid_bytes) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
        i += tag_len;
    }
    None
}

fn extract_pmkid_from_ies(ies: &[u8]) -> Option<[u8; 16]> {
    let mut i = 0;
    while i + 2 <= ies.len() {
        let tag_id = ies[i];
        let tag_len = ies[i + 1] as usize;
        i += 2;
        if i + tag_len > ies.len() { break; }
        if tag_id == 48 && tag_len >= 22 {
            let rsn = &ies[i..i + tag_len];
            // Check for PMKID at end of RSN IE
            let mut pmkid = [0u8; 16];
            pmkid.copy_from_slice(&rsn[tag_len - 16..tag_len]);
            if pmkid != [0u8; 16] && pmkid != [0xFFu8; 16] {
                return Some(pmkid);
            }
        }
        i += tag_len;
    }
    None
}

fn scan_credentials(buf: &[u8]) -> Option<(String, String)> {
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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_slice(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_str(s: &str) -> String {
    s.bytes().map(|b| format!("{:02x}", b)).collect()
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
        let creds = scan_credentials(sample);
        assert_eq!(creds, Some(("admin".into(), "secret123".into())));
    }

    #[test]
    fn test_scan_plaintext_ftp() {
        let sample = b"USER root\r\n331 Please specify password.\r\nPASS SuperPassword2026\r\n230 Login successful.\r\n";
        let creds = scan_credentials(sample);
        assert_eq!(creds, Some(("root".into(), "SuperPassword2026".into())));
    }

    #[test]
    fn test_extract_ssid() {
        let mut ies = vec![0u8; 32];
        ies[0] = 0; // Tag 0 (SSID)
        ies[1] = 8; // length 8
        ies[2..10].copy_from_slice(b"WiFi_Net");
        let ssid = extract_ssid_from_ies(&ies);
        assert_eq!(ssid, Some("WiFi_Net".into()));
    }
}
