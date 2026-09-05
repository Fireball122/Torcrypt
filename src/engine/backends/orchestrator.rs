// src/engine/backends/orchestrator.rs — Subprocess Orchestrator for Hashcat & John the Ripper
// Spawns recovery backends, streams candidate lists or mask configurations,
// parses live stdout/stderr for speed/progress telemetry, and captures recovered plaintext.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use crossbeam_channel::{unbounded, Receiver};

use super::detector::BackendType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendStatus {
    Starting,
    Running,
    Completed(String), // Recovered plaintext password
    Exhausted,         // Keyspace exhausted without finding key
    Failed(String),    // Error message / abnormal exit
}

#[derive(Debug, Clone)]
pub struct BackendTelemetry {
    pub status:         BackendStatus,
    pub speed_hps:      f64,
    pub progress_done:  u64,
    pub progress_total: u64,
    pub eta_secs:       f64,
    pub log_line:       Option<String>,
}

pub struct BackendJob {
    backend_type:   BackendType,
    child:          Option<Child>,
    rx:             Receiver<BackendTelemetry>,
    stop_flag:      Arc<AtomicBool>,
    reader_thr:     Option<JoinHandle<()>>,
    temp_hash_file: Option<PathBuf>,
}

impl BackendJob {
    /// Spawn an external backend job against a target container or hash file.
    pub fn launch(
        backend_type:  BackendType,
        backend_bin:   &Path,
        target_path:   &Path,
        extractor_bin: Option<&Path>,
        wordlist:      Option<&Path>,
        candidates:    Option<Vec<String>>,
        cipher_desc:   Option<&str>,
    ) -> Result<Self, String> {
        // 1. Prioritize in-process extraction to avoid external tool dependencies
        let (actual_target, temp_hash_file) = if let Some(hash_str) = crate::engine::extractors::format_archive_hash(target_path) {
            let temp_hash_path = std::env::temp_dir().join(format!(
                "torcrypt_inproc_{}_{}.hash",
                std::process::id(),
                target_path.file_name().unwrap_or_default().to_string_lossy()
            ));
            if std::fs::write(&temp_hash_path, hash_str.as_bytes()).is_ok() {
                let p_clone = temp_hash_path.clone();
                (temp_hash_path, Some(p_clone))
            } else {
                (target_path.to_path_buf(), None)
            }
        } else if let Some(ext) = extractor_bin {
            match extract_hash_with_tool(ext, target_path) {
                Ok(temp_p) => {
                    let p_clone = temp_p.clone();
                    (temp_p, Some(p_clone))
                }
                Err(_) => (target_path.to_path_buf(), None),
            }
        } else {
            (target_path.to_path_buf(), None)
        };
        let stop_flag = Arc::new(AtomicBool::new(false));
        let (tx, rx) = unbounded();

        let mut cmd = Command::new(backend_bin);

        match backend_type {
            BackendType::Hashcat => {
                // Configure Hashcat arguments
                cmd.arg("--status")
                    .arg("--status-timer=1")
                    .arg("--machine-readable");

                if let Some(desc) = cipher_desc {
                    if let Some(mode) = super::detector::hashcat_mode_for(desc) {
                        cmd.arg("-m").arg(mode.to_string());
                    }
                }

                cmd.arg(&actual_target);

                if let Some(w) = wordlist {
                    cmd.arg(w);
                } else if candidates.is_some() {
                    cmd.arg("--stdin");
                    cmd.stdin(Stdio::piped());
                } else {
                    // Default mask attack (8 lower-case)
                    cmd.arg("-a").arg("3").arg("?l?l?l?l?l?l?l?l");
                }
            }
            BackendType::John => {
                // Configure John the Ripper arguments
                if let Some(w) = wordlist {
                    cmd.arg(format!("--wordlist={}", w.display()));
                } else if candidates.is_some() {
                    cmd.arg("--stdin");
                    cmd.stdin(Stdio::piped());
                }
                cmd.arg(&actual_target);
            }
            BackendType::None => {
                return Err("No external backend specified".into());
            }
        }

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn {}: {}", backend_bin.display(), e))?;

        // If stdin candidates provided, pipe them in background thread
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(cand_list) = candidates {
                let stop_flag_clone = Arc::clone(&stop_flag);
                thread::spawn(move || {
                    for cand in cand_list {
                        if stop_flag_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        if writeln!(stdin, "{}", cand).is_err() {
                            break;
                        }
                    }
                });
            }
        }

        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let stop_clone = Arc::clone(&stop_flag);
        let tx_clone = tx.clone();
        let btype = backend_type;

        let reader_thr = thread::spawn(move || {
            let mut last_speed = 0.0;
            let mut last_done = 0;
            let mut last_total = 0;
            let mut found_password: Option<String> = None;

            if let Some(out) = stdout {
                let reader = BufReader::new(out);
                for line_res in reader.lines() {
                    if stop_clone.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(line) = line_res {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        // Send informational log event
                        let _ = tx_clone.send(BackendTelemetry {
                            status: BackendStatus::Running,
                            speed_hps: last_speed,
                            progress_done: last_done,
                            progress_total: last_total,
                            eta_secs: 0.0,
                            log_line: Some(trimmed.to_string()),
                        });

                        // Parse backend-specific telemetry
                        match btype {
                            BackendType::Hashcat => {
                                if let Some((speed, done, total)) = parse_hashcat_line(trimmed) {
                                    if speed > 0.0 { last_speed = speed; }
                                    if done > 0 { last_done = done; }
                                    if total > 0 { last_total = total; }
                                }
                                if let Some(recovered) = parse_hashcat_cracked(trimmed) {
                                    found_password = Some(recovered);
                                }
                            }
                            BackendType::John => {
                                if let Some((speed, done, total)) = parse_john_line(trimmed) {
                                    if speed > 0.0 { last_speed = speed; }
                                    if done > 0 { last_done = done; }
                                    if total > 0 { last_total = total; }
                                }
                                if let Some(recovered) = parse_john_cracked(trimmed) {
                                    found_password = Some(recovered);
                                }
                            }
                            BackendType::None => {}
                        }
                    }
                }
            }

            // Also check stderr for diagnostics
            if let Some(err) = stderr {
                let reader = BufReader::new(err);
                for line_res in reader.lines().take(50) {
                    if let Ok(line) = line_res {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() {
                            let _ = tx_clone.send(BackendTelemetry {
                                status: BackendStatus::Running,
                                speed_hps: last_speed,
                                progress_done: last_done,
                                progress_total: last_total,
                                eta_secs: 0.0,
                                log_line: Some(format!("[backend stderr] {}", trimmed)),
                            });
                        }
                    }
                }
            }

            // Final status
            if let Some(pwd) = found_password {
                let _ = tx_clone.send(BackendTelemetry {
                    status: BackendStatus::Completed(pwd),
                    speed_hps: 0.0,
                    progress_done: last_done,
                    progress_total: last_total,
                    eta_secs: 0.0,
                    log_line: Some("Key Recovered by External Backend!".into()),
                });
            } else {
                let _ = tx_clone.send(BackendTelemetry {
                    status: BackendStatus::Exhausted,
                    speed_hps: 0.0,
                    progress_done: last_done,
                    progress_total: last_total,
                    eta_secs: 0.0,
                    log_line: Some("External backend completed: No password found".into()),
                });
            }
        });

        Ok(Self {
            backend_type,
            child: Some(child),
            rx,
            stop_flag,
            reader_thr: Some(reader_thr),
            temp_hash_file,
        })
    }

    /// Poll for telemetry events from the running backend.
    pub fn poll(&self) -> Option<BackendTelemetry> {
        self.rx.try_recv().ok()
    }

    /// Terminate the backend process cleanly.
    pub fn terminate(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(handle) = self.reader_thr.take() {
            let _ = handle.join();
        }
        if let Some(temp_p) = self.temp_hash_file.take() {
            let _ = std::fs::remove_file(temp_p);
        }
    }
}

/// Run an external extractor (zip2john, pdf2john, rar2john, 7z2john) to dump hash
pub fn extract_hash_with_tool(extractor_bin: &Path, target_path: &Path) -> Result<PathBuf, String> {
    let output = Command::new(extractor_bin)
        .arg(target_path)
        .output()
        .map_err(|e| format!("Failed to run extractor {}: {}", extractor_bin.display(), e))?;

    if !output.status.success() {
        return Err(format!("Extractor exited with code {:?}", output.status.code()));
    }

    let hash_content = String::from_utf8_lossy(&output.stdout);
    if hash_content.trim().is_empty() {
        return Err("Extractor produced empty output".into());
    }

    let temp_hash_path = std::env::temp_dir().join(format!(
        "torcrypt_extracted_{}_{}.hash",
        std::process::id(),
        target_path.file_name().unwrap_or_default().to_string_lossy()
    ));

    std::fs::write(&temp_hash_path, hash_content.as_bytes())
        .map_err(|e| format!("Failed to write extracted hash file: {}", e))?;

    Ok(temp_hash_path)
}

impl Drop for BackendJob {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Parse Hashcat machine-readable status output lines:
/// Example: `STATUS\t3\tSPEED\t142500000\tCUR_EXEC\t15000\tTOTAL_EXEC\t100000`
pub fn parse_hashcat_line(line: &str) -> Option<(f64, u64, u64)> {
    let mut speed = 0.0;
    let mut done = 0;
    let mut total = 0;

    let parts: Vec<&str> = line.split('\t').collect();
    for i in 0..parts.len() {
        if parts[i] == "SPEED" && i + 1 < parts.len() {
            speed = parts[i + 1].parse::<f64>().unwrap_or(0.0);
        } else if parts[i] == "CUR_EXEC" && i + 1 < parts.len() {
            done = parts[i + 1].parse::<u64>().unwrap_or(0);
        } else if parts[i] == "TOTAL_EXEC" && i + 1 < parts.len() {
            total = parts[i + 1].parse::<u64>().unwrap_or(0);
        }
    }

    // Also support traditional output: "Speed.#1.........: 125.4 kH/s"
    if line.contains("Speed.#") {
        if let Some(idx) = line.find(':') {
            let val_part = line[idx + 1..].trim();
            if let Some(num_str) = val_part.split_whitespace().next() {
                if let Ok(val) = num_str.parse::<f64>() {
                    if val_part.contains("kH/s") {
                        speed = val * 1_000.0;
                    } else if val_part.contains("MH/s") {
                        speed = val * 1_000_000.0;
                    } else if val_part.contains("GH/s") {
                        speed = val * 1_000_000_000.0;
                    } else {
                        speed = val;
                    }
                }
            }
        }
    }

    if speed > 0.0 || done > 0 || total > 0 {
        Some((speed, done, total))
    } else {
        None
    }
}

pub fn parse_hashcat_cracked(line: &str) -> Option<String> {
    // Hashcat output on crack: "<hash_or_salt>:<plaintext>"
    // Exclude header or informational lines containing colon
    if line.starts_with("Session.")
        || line.starts_with("Status.")
        || line.starts_with("Hash.Name")
        || line.starts_with("Hash.Target")
        || line.starts_with("Time.Started")
        || line.starts_with("Time.Estimated")
        || line.starts_with("Speed.")
        || line.starts_with("Recovered.")
        || line.starts_with("Progress.")
        || line.starts_with("Rejected.")
        || line.starts_with("Restore.Point")
    {
        return None;
    }

    if let Some(idx) = line.rfind(':') {
        let plaintext = line[idx + 1..].trim();
        if !plaintext.is_empty() && !line.contains('\t') {
            return Some(plaintext.to_string());
        }
    }
    None
}

/// Parse John the Ripper status line:
/// Example: `0g 0:00:00:02 12.50% (ETA: 14:02) 12500p/s 12500c/s 12500C/s`
pub fn parse_john_line(line: &str) -> Option<(f64, u64, u64)> {
    let mut speed = 0.0;

    for word in line.split_whitespace() {
        if word.ends_with("p/s") || word.ends_with("c/s") || word.ends_with("C/s") {
            let num_part = word.trim_end_matches("p/s").trim_end_matches("c/s").trim_end_matches("C/s");
            if let Ok(s) = num_part.parse::<f64>() {
                if s > speed {
                    speed = s;
                }
            }
        }
    }

    if speed > 0.0 {
        Some((speed, 0, 0))
    } else {
        None
    }
}

pub fn parse_john_cracked(line: &str) -> Option<String> {
    // John cracked line format: "password123      (target_or_user)"
    if line.contains('(') && line.ends_with(')') {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if !parts.is_empty() && !parts[0].starts_with('(') {
            return Some(parts[0].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hashcat_machine_readable() {
        let line = "STATUS\t3\tSPEED\t142500000\tCUR_EXEC\t15000\tTOTAL_EXEC\t100000";
        let parsed = parse_hashcat_line(line).expect("Should parse");
        assert_eq!(parsed.0, 142500000.0);
        assert_eq!(parsed.1, 15000);
        assert_eq!(parsed.2, 100000);
    }

    #[test]
    fn test_parse_hashcat_speed_text() {
        let line = "Speed.#1.........:   125.4 kH/s (50.22ms) @ Accel:128 Loops:1024 Thr:64 Vec:1";
        let parsed = parse_hashcat_line(line).expect("Should parse speed");
        assert_eq!(parsed.0, 125400.0);
    }

    #[test]
    fn test_parse_hashcat_cracked_plaintext() {
        let line = "5d41402abc4b2a76b9719d911017c592:hello";
        assert_eq!(parse_hashcat_cracked(line), Some("hello".into()));

        let info_line = "Speed.#1.........: 1000 H/s";
        assert_eq!(parse_hashcat_cracked(info_line), None);
    }

    #[test]
    fn test_parse_john_status_and_cracked() {
        let status = "0g 0:00:00:02 12.50% 14500p/s 14500c/s";
        let parsed = parse_john_line(status).expect("Should parse john speed");
        assert_eq!(parsed.0, 14500.0);

        let cracked = "secret123        (archive.zip/secret.txt)";
        assert_eq!(parse_john_cracked(cracked), Some("secret123".into()));
    }
}
