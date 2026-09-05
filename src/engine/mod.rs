// src/engine/mod.rs — Torcrypt Core Decryption Engine Module
// Manages background decryption threads, IPC channels, and telemetry events.

pub mod audit_export;
pub mod extractors;
pub mod feasibility;
pub mod protocol;
pub mod session_db;
pub mod system_info;
pub mod wordlist_profiler;
pub mod worker;
pub mod crypto;
pub mod crackers;
pub mod backends;
pub mod crack_pool;
pub mod benchmark_runner;
pub use benchmark_runner::{benchmark_stage, run_full_benchmark, BenchResult};

pub use audit_export::export_audit_report;
pub use feasibility::{estimate_feasibility, FeasibilityReport, FeasibilityTier};
pub use wordlist_profiler::WordlistProfile;

pub use session_db::{DbSession, PotfileRecord, SessionDatabase};
pub use system_info::SystemMonitor;

pub use protocol::{
    AttackRequest, ComputeEngine, EngineCommand, LogLevel, TelemetryEvent, WorkerState,
};
pub use worker::DecryptionWorker;

use crossbeam_channel::{unbounded, Receiver, Sender};
use std::thread::{self, JoinHandle};

pub struct EngineHandle {
    pub tx: Sender<EngineCommand>,
    pub rx: Receiver<TelemetryEvent>,
    worker_thread: Option<JoinHandle<()>>,
}

impl EngineHandle {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = unbounded::<EngineCommand>();
        let (tel_tx, tel_rx) = unbounded::<TelemetryEvent>();

        let thread_handle = thread::Builder::new()
            .name("torcrypt-worker".into())
            .spawn(move || {
                let mut worker = DecryptionWorker::new(cmd_rx, tel_tx);
                worker.run();
            })
            .expect("Failed to spawn torcrypt background worker thread");

        Self {
            tx: cmd_tx,
            rx: tel_rx,
            worker_thread: Some(thread_handle),
        }
    }
    pub fn send(&self, cmd: EngineCommand) {
        let _ = self.tx.send(cmd);
    }

    pub fn try_recv(&self) -> Result<TelemetryEvent, crossbeam_channel::TryRecvError> {
        self.rx.try_recv()
    }
}

impl Default for EngineHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for EngineHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(EngineCommand::Shutdown);
        if let Some(handle) = self.worker_thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::path::Path;

    pub(crate) fn create_test_zip(path: &Path, password: &str) {
        let mut state = crate::engine::crypto::ZipCryptoState::new(password.as_bytes());
        let check_byte = 0xAAu8;
        let check_byte2 = 0x55u8;
        let mut plain_header = [0u8; 12];
        plain_header[10] = check_byte2;
        plain_header[11] = check_byte;

        let mut enc_header = [0u8; 12];
        for i in 0..12 {
            let temp = (state.key2 | 2) as u16;
            let keystream = ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8;
            enc_header[i] = plain_header[i] ^ keystream;
            state.update(plain_header[i]);
        }

        let mut zip_bytes = Vec::new();
        zip_bytes.extend_from_slice(b"PK\x03\x04");
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, check_byte2, check_byte]);
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(b"test.txt");
        zip_bytes.extend_from_slice(&enc_header);

        let cd_offset = zip_bytes.len() as u32;
        zip_bytes.extend_from_slice(b"PK\x01\x02");
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, check_byte2, check_byte]);
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(b"test.txt");

        let cd_size = (zip_bytes.len() as u32) - cd_offset;
        zip_bytes.extend_from_slice(b"PK\x05\x06");
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes());
        zip_bytes.extend_from_slice(&[0, 0]);

        std::fs::write(path, zip_bytes).unwrap();
    }

    #[test]
    fn test_engine_lifecycle() {
        let engine = EngineHandle::new();
        engine.send(EngineCommand::Shutdown);
    }

    #[test]
    fn test_attack_pipeline_execution() {
        let temp_path = std::env::temp_dir().join("torcrypt_pipeline_test.zip");
        create_test_zip(&temp_path, "secret123");

        let engine = EngineHandle::new();
        let req = AttackRequest {
            target_path:    temp_path.to_string_lossy().to_string(),
            cipher_suite:   "ZipCrypto Standard".into(),
            active_engine:  ComputeEngine::CpuSimd,
            strategy_id:    "wordlist_fast".into(),
            strategy_title: "Fast Dictionary Pass".into(),
            keyspace_name:  "10,000 Candidates".into(),
            items_total:    10_000,
            speed_base:     35_000.0,
            thread_count:   4,
            wordlist_path:  None,
            start_offset:   0,
            cipher_desc:    Some("ZipCrypto Standard".into()),
        };

        engine.send(EngineCommand::StartAttack(req));

        let mut got_started = false;
        let mut got_key = false;

        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Ok(event) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                match event {
                    TelemetryEvent::Started { target_path, .. } => {
                        assert_eq!(target_path, temp_path.to_string_lossy().to_string());
                        got_started = true;
                    }
                    TelemetryEvent::KeyFound { cracked_key, .. } => {
                        assert!(cracked_key.contains("secret123"));
                        got_key = true;
                        break;
                    }
                    _ => {}
                }
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        assert!(got_started, "Engine should have emitted TelemetryEvent::Started");
        assert!(got_key, "Engine should have recovered key for real zipcrypto target");
    }

    #[test]
    fn test_real_engine_end_to_end_recovery() {
        let temp_path = std::env::temp_dir().join("torcrypt_e2e_recovery.zip");
        create_test_zip(&temp_path, "secret123");

        let engine = EngineHandle::new();
        let req = AttackRequest {
            target_path:    temp_path.to_string_lossy().to_string(),
            cipher_suite:   "ZipCrypto Standard".into(),
            active_engine:  ComputeEngine::CpuSimd,
            strategy_id:    "wordlist_fast".into(),
            strategy_title: "Common Dictionary Candidates".into(),
            keyspace_name:  "Common Dictionary".into(),
            items_total:    1_000,
            speed_base:     10_000.0,
            thread_count:   4,
            wordlist_path:  None,
            start_offset:   0,
            cipher_desc:    Some("ZipCrypto Standard".into()),
        };

        engine.send(EngineCommand::StartAttack(req));

        let mut recovered_key = None;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(4) {
            if let Ok(event) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                match event {
                    TelemetryEvent::KeyFound { cracked_key, .. } => {
                        recovered_key = Some(cracked_key);
                        break;
                    }
                    _ => {}
                }
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        assert!(recovered_key.is_some(), "Real engine should have recovered the password from the real zip");
        let key_str = recovered_key.unwrap();
        assert!(key_str.contains("secret123"), "Recovered key must match 'secret123', got: {}", key_str);
    }

    #[test]
    fn test_pause_resume_cancel() {
        let temp_path = std::env::temp_dir().join("torcrypt_pause_resume.hash");
        // MD5 of an unguessable string to ensure worker runs without immediately finishing
        std::fs::write(&temp_path, "ffffffffffffffffffffffffffffffff").unwrap();

        let engine = EngineHandle::new();
        let req = AttackRequest {
            target_path:    temp_path.to_string_lossy().to_string(),
            cipher_suite:   "MD5 Digest".into(),
            active_engine:  ComputeEngine::CpuSimd,
            strategy_id:    "mask_6d".into(),
            strategy_title: "6-Digit Numeric Mask".into(),
            keyspace_name:  "1,000,000 Pins".into(),
            items_total:    1_000_000,
            speed_base:     10_000.0,
            thread_count:   2,
            wordlist_path:  None,
            start_offset:   0,
            cipher_desc:    Some("MD5 Digest".into()),
        };

        engine.send(EngineCommand::StartAttack(req));
        std::thread::sleep(Duration::from_millis(60));

        engine.send(EngineCommand::Pause);
        let mut got_paused = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if let Ok(event) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                if matches!(event, TelemetryEvent::Paused) {
                    got_paused = true;
                    break;
                }
            }
        }
        assert!(got_paused, "Engine should acknowledge pause");

        engine.send(EngineCommand::Resume);
        let mut got_resumed = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if let Ok(event) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                if matches!(event, TelemetryEvent::Resumed) {
                    got_resumed = true;
                    break;
                }
            }
        }
        assert!(got_resumed, "Engine should acknowledge resume");

        engine.send(EngineCommand::Cancel);
        let mut got_cancelled = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(2) {
            if let Ok(event) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                if matches!(event, TelemetryEvent::Cancelled) {
                    got_cancelled = true;
                    break;
                }
            }
        }
        let _ = std::fs::remove_file(&temp_path);
        assert!(got_cancelled, "Engine should acknowledge cancel");
    }

    #[test]
    fn test_search_exhaustion() {
        let temp_path = std::env::temp_dir().join("torcrypt_exhaust.hash");
        // MD5 of an unguessable string
        std::fs::write(&temp_path, "00000000000000000000000000000000").unwrap();

        let engine = EngineHandle::new();
        let req = AttackRequest {
            target_path:    temp_path.to_string_lossy().to_string(),
            cipher_suite:   "MD5 Digest".into(),
            active_engine:  ComputeEngine::CpuSimd,
            strategy_id:    "mask_4d".into(),
            strategy_title: "4-Digit PIN".into(),
            keyspace_name:  "10,000 PINs".into(),
            items_total:    10_000,
            speed_base:     50_000.0,
            thread_count:   4,
            wordlist_path:  None,
            start_offset:   0,
            cipher_desc:    Some("MD5 Digest".into()),
        };

        engine.send(EngineCommand::StartAttack(req));

        let mut got_exhausted = false;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            if let Ok(TelemetryEvent::Exhausted { .. }) = engine.rx.recv_timeout(Duration::from_millis(50)) {
                got_exhausted = true;
                break;
            }
        }

        let _ = std::fs::remove_file(&temp_path);
        assert!(got_exhausted, "Engine should have emitted Exhausted event when candidate space finishes");
    }
}
