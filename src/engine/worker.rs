// src/engine/worker.rs — Torcrypt Decryption Engine Background Worker
// Runs on a dedicated OS thread, executing real cryptographic candidate pipelines
// or orchestrating external recovery tools (Hashcat / John) with live telemetry.

use std::path::Path;
use std::time::Duration;
use crossbeam_channel::{Receiver, Sender};

use super::backends::{BackendCatalog, BackendJob, BackendStatus, BackendType};
use super::crackers::{ActiveCracker, CandidateIterator};
use super::crack_pool::CrackPool;
use super::protocol::{AttackRequest, ComputeEngine, EngineCommand, LogLevel, TelemetryEvent, WorkerState};

pub struct DecryptionWorker {
    cmd_rx:          Receiver<EngineCommand>,
    tel_tx:          Sender<TelemetryEvent>,
    worker_state:    WorkerState,

    // Active Job Context
    target_path:     String,
    cipher_suite:    String,
    active_engine:   ComputeEngine,
    active_strategy: String,
    items_done:      u64,
    items_total:     u64,
    elapsed_secs:    f64,
    eta_secs:        f64,
    speed_mbps:      f64,
    base_speed:      f64,
    thread_count:    u8,
    thread_active:   u8,
    tick:            u64,
    current_batch_size: usize,

    // Real In-Process Cryptographic Pipeline
    active_cracker:  Option<ActiveCracker>,
    candidate_iter:  Option<CandidateIterator>,
    crack_pool:      Option<CrackPool>,

    // External Subprocess Backend Pipeline (Hashcat / John the Ripper)
    backend_catalog: BackendCatalog,
    active_backend:  Option<BackendJob>,
}

impl DecryptionWorker {
    pub fn new(cmd_rx: Receiver<EngineCommand>, tel_tx: Sender<TelemetryEvent>) -> Self {
        Self {
            cmd_rx,
            tel_tx,
            worker_state:    WorkerState::Idle,
            target_path:     String::new(),
            cipher_suite:    String::new(),
            active_engine:   ComputeEngine::CpuSimd,
            active_strategy: String::new(),
            items_done:      0,
            items_total:     0,
            elapsed_secs:    0.0,
            eta_secs:        0.0,
            speed_mbps:      0.0,
            base_speed:      0.0,
            thread_count:    1,
            thread_active:   0,
            tick:            0,
            current_batch_size: 250,
            active_cracker:  None,
            candidate_iter:  None,
            crack_pool:      None,
            backend_catalog: BackendCatalog::probe(),
            active_backend:  None,
        }
    }

    pub fn run(&mut self) {
        loop {
            match self.worker_state {
                WorkerState::Running => {
                    match self.cmd_rx.recv_timeout(Duration::from_millis(33)) {
                        Ok(cmd) => {
                            if !self.handle_command(cmd) {
                                break; // Shutdown
                            }
                        }
                        Err(_) => {
                            self.step_running_tick();
                        }
                    }
                }
                WorkerState::Paused => {
                    match self.cmd_rx.recv_timeout(Duration::from_millis(66)) {
                        Ok(cmd) => {
                            if !self.handle_command(cmd) {
                                break; // Shutdown
                            }
                        }
                        Err(_) => {
                            self.tick = self.tick.wrapping_add(1);
                            if self.tick % 2 == 0 {
                                let _ = self.tel_tx.send(TelemetryEvent::ProgressUpdate {
                                    items_done:    self.items_done,
                                    items_total:   self.items_total,
                                    speed_mbps:    0.0,
                                    elapsed_secs:  self.elapsed_secs,
                                    eta_secs:      self.eta_secs,
                                    thread_active: 0,
                                    throughput_mb: 0,
                                });
                            }
                        }
                    }
                }
                _ => {
                    // Idle, Stopped, Completed, Exhausted — wait for command
                    match self.cmd_rx.recv() {
                        Ok(cmd) => {
                            if !self.handle_command(cmd) {
                                break; // Shutdown
                            }
                        }
                        Err(_) => {
                            break; // Channel disconnected
                        }
                    }
                }
            }
        }

        // Cleanup on exit
        if let Some(mut backend) = self.active_backend.take() {
            backend.terminate();
        }
    }

    fn handle_command(&mut self, cmd: EngineCommand) -> bool {
        match cmd {
            EngineCommand::StartAttack(req) => {
                self.start_attack(req);
                true
            }
            EngineCommand::Pause => {
                if self.worker_state == WorkerState::Running {
                    self.worker_state  = WorkerState::Paused;
                    self.speed_mbps    = 0.0;
                    self.thread_active = 0;
                    let _ = self.tel_tx.send(TelemetryEvent::Paused);
                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Warn,
                        path:    String::new(),
                        message: "Worker pipeline PAUSED by user".into(),
                    });
                }
                true
            }
            EngineCommand::Resume => {
                if self.worker_state == WorkerState::Paused {
                    self.worker_state  = WorkerState::Running;
                    self.thread_active = self.thread_count;
                    let _ = self.tel_tx.send(TelemetryEvent::Resumed);
                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Info,
                        path:    String::new(),
                        message: "Worker pipeline RESUMED".into(),
                    });
                }
                true
            }
            EngineCommand::Cancel => {
                if self.worker_state == WorkerState::Running || self.worker_state == WorkerState::Paused {
                    self.worker_state  = WorkerState::Stopped;
                    self.speed_mbps    = 0.0;
                    self.thread_active = 0;
                    if let Some(mut backend) = self.active_backend.take() {
                        backend.terminate();
                    }
                    self.crack_pool.take(); // shutdown worker threads
                    self.active_cracker.take();
                    self.candidate_iter.take();
                    if let Ok(db) = crate::engine::SessionDatabase::init() {
                        let _ = db.update_checkpoint(&self.target_path, self.items_done, "CANCELLED");
                    }
                    let _ = self.tel_tx.send(TelemetryEvent::Cancelled);
                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Err,
                        path:    String::new(),
                        message: "Active session cancelled by user".into(),
                    });
                }
                true
            }
            EngineCommand::Shutdown => {
                if let Some(mut backend) = self.active_backend.take() {
                    backend.terminate();
                }
                self.crack_pool.take();
                false
            }
        }
    }

    fn start_attack(&mut self, req: AttackRequest) {
        self.target_path     = req.target_path;
        self.cipher_suite    = req.cipher_suite;
        self.active_engine   = req.active_engine;
        self.active_strategy = req.strategy_title;
        self.items_done      = 0;
        self.items_total     = req.items_total;
        self.elapsed_secs    = 0.0;
        self.thread_count    = req.thread_count;
        self.thread_active   = req.thread_count;
        self.speed_mbps      = req.speed_base;
        self.base_speed      = req.speed_base;
        self.worker_state    = WorkerState::Running;
        self.tick            = 0;

        // Clean up previous backend if any
        if let Some(mut b) = self.active_backend.take() {
            b.terminate();
        }

        let target_p = Path::new(&self.target_path);

        // 1. Attempt to load native pure-Rust cracker
        let real_cracker = ActiveCracker::load_target(target_p);

        if let Some(cracker) = real_cracker {
            let cipher = cracker.cipher_name();

            // Configure candidate generator
            let generator = if let Some(custom_wl) = &req.wordlist_path {
                let p = Path::new(custom_wl);
                if p.is_file() {
                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Lock,
                        path:    custom_wl.clone(),
                        message: format!("Custom Operator Wordlist Engaged: {}", custom_wl),
                    });
                    CandidateIterator::new_wordlist(p.to_path_buf())
                        .unwrap_or_else(CandidateIterator::new_common)
                } else {
                    CandidateIterator::new_common()
                }
            } else if req.strategy_id.starts_with("mask_pattern:") {
                let pat = &req.strategy_id["mask_pattern:".len()..];
                CandidateIterator::new_mask(pat)
            } else if req.strategy_id.contains("hybrid_mask") {
                CandidateIterator::new_mask("?u?l?l?l?d?d")
            } else if req.strategy_id.contains("mask") || req.strategy_id.contains("pin") {
                let digits = if req.strategy_id.contains("10d") {
                    10
                } else if req.strategy_id.contains("8d") {
                    8
                } else if req.strategy_id.contains("7d") {
                    7
                } else if req.strategy_id.contains("6d") {
                    6
                } else if req.strategy_id.contains("5d") {
                    5
                } else if req.strategy_id.contains("4d") {
                    4
                } else {
                    6
                };
                CandidateIterator::new_numeric_mask(digits)
            } else if req.strategy_id.contains("rules") || req.strategy_id.contains("mut") || req.strategy_id.contains("best64") {
                let words: Vec<String> = crate::engine::crackers::generator::COMMON_PASSWORDS
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                CandidateIterator::new_best64(words)
            } else if req.strategy_id.contains("combinator") {
                let words: Vec<String> = crate::engine::crackers::generator::COMMON_PASSWORDS[..50]
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                let suffixes: Vec<String> = (0..100).map(|i| format!("{:02}", i)).collect();
                CandidateIterator::new_combinator(words, suffixes)
            } else if req.strategy_id.contains("prod") || req.strategy_id.contains("full") {
                let wordlist_candidates = [
                    "/home/ultaria/wordlists/rockyou.txt",
                    "/home/ultaria/wordlists/xato-top100k.txt",
                    "/home/ultaria/wordlists/100k-most-used-ncsc.txt",
                    "rockyou.txt",
                    "wordlist.txt",
                    "passwords.txt",
                    "/usr/share/wordlists/rockyou.txt",
                ];
                let mut found_wl = None;
                for &wl in &wordlist_candidates {
                    let p = Path::new(wl);
                    if p.is_file() {
                        found_wl = CandidateIterator::new_wordlist(p.to_path_buf());
                        if found_wl.is_some() {
                            let _ = self.tel_tx.send(TelemetryEvent::Log {
                                level:   LogLevel::Info,
                                path:    wl.to_string(),
                                message: format!("External Wordlist Loaded: {}", wl),
                            });
                            break;
                        }
                    }
                }

                found_wl.unwrap_or_else(CandidateIterator::new_common)
            } else {
                CandidateIterator::new_common()
            };
            let mut generator = generator;
            if req.start_offset > 0 {
                generator.skip_candidates(req.start_offset);
                self.items_done = req.start_offset;
            }
            if let Some(total) = generator.total_candidates() {
                self.items_total = total;
            }
            let initial_per_thread = match &cracker {
                ActiveCracker::SevenZip(_) => 1,
                ActiveCracker::Rar5(_) => 1,
                ActiveCracker::KeePass(_) => 2,
                ActiveCracker::WinZipAes(_) => 5,
                ActiveCracker::Pdf(_) => 50,
                _ => 250,
            };
            self.current_batch_size = (initial_per_thread * self.thread_count as usize).max(1);
            self.candidate_iter = Some(generator);
            // Spawn persistent thread pool for this cracker — replaces per-tick thread::scope.
            self.crack_pool     = Some(CrackPool::spawn(&cracker, self.thread_count as usize));
            self.active_cracker = Some(cracker);
            self.active_backend = None;
            let _ = self.tel_tx.send(TelemetryEvent::Log {
                level:   LogLevel::Lock,
                path:    self.target_path.clone(),
                message: format!("Native In-Process Verification Engine Engaged: {}", cipher),
            });
        } else {
            // 2. Target not supported natively. Check for external backend (Hashcat / John)
            self.active_cracker = None;
            self.candidate_iter = None;

            if let Some(backend_type) = self.backend_catalog.select_backend(target_p, &self.cipher_suite) {
                let bin_path = match backend_type {
                    BackendType::Hashcat => self.backend_catalog.hashcat.as_deref(),
                    BackendType::John    => self.backend_catalog.john.as_deref(),
                    BackendType::None    => None,
                };

                if let Some(bin) = bin_path {
                    let mut gen = CandidateIterator::new_common();
                    let cand_sample = if req.wordlist_path.is_some() { None } else { Some(gen.next_batch(500)) };
                    let extractor_bin = self.backend_catalog.find_extractor_for(target_p);
                    let wl_arg = req.wordlist_path.as_deref().map(Path::new);

                    match BackendJob::launch(backend_type, bin, target_p, extractor_bin, wl_arg, cand_sample) {
                        Ok(job) => {
                            self.active_backend = Some(job);
                            let _ = self.tel_tx.send(TelemetryEvent::Log {
                                level:   LogLevel::Info,
                                path:    self.target_path.clone(),
                                message: format!(
                                    "External Backend Orchestrator Dispatched: {} ({})",
                                    backend_type.display_name(),
                                    bin.display()
                                ),
                            });
                        }
                        Err(err) => {
                            let _ = self.tel_tx.send(TelemetryEvent::Log {
                                level:   LogLevel::Err,
                                path:    self.target_path.clone(),
                                message: format!("Failed to spawn external backend: {}", err),
                            });
                            self.mark_unsupported();
                            return;
                        }
                    }
                } else {
                    self.mark_unsupported();
                    return;
                }
            } else {
                self.mark_unsupported();
                return;
            }
        }

        self.eta_secs = (self.items_total as f64 / 45_000.0).max(0.5);

        // Notify UI of started state
        let _ = self.tel_tx.send(TelemetryEvent::Started {
            target_path:     self.target_path.clone(),
            cipher_suite:    self.cipher_suite.clone(),
            active_strategy: self.active_strategy.clone(),
            active_engine:   self.active_engine,
            items_total:     self.items_total,
            speed_mbps:      self.speed_mbps,
            thread_count:    self.thread_count,
            eta_secs:        self.eta_secs,
        });

        // Instant potfile cache lookup
        if let Ok(db) = crate::engine::SessionDatabase::init() {
            if let Some(cached_pwd) = db.potfile_lookup(&self.target_path) {
                let formatted_key = format!("Password: {}", cached_pwd);
                let _ = self.tel_tx.send(TelemetryEvent::KeyFound {
                    cracked_key:  formatted_key.clone(),
                    kdf_info:     "Potfile Cache Instant Hit".into(),
                    items_done:   1,
                    elapsed_secs: 0.001,
                    base_speed:   1_000_000_000.0,
                    target_path:  self.target_path.clone(),
                    cipher_suite: self.cipher_suite.clone(),
                    thread_count: self.thread_count,
                });
                let _ = self.tel_tx.send(TelemetryEvent::Log {
                    level:   LogLevel::Lock,
                    path:    self.target_path.clone(),
                    message: format!("✨ INSTANT POTFILE HIT: \"{}\"", formatted_key),
                });
                self.worker_state = WorkerState::Completed;
                return;
            }
        }
        let _ = self.tel_tx.send(TelemetryEvent::Log {
            level:   LogLevel::Lock,
            path:    self.target_path.clone(),
            message: format!("Target Loaded: {} │ Profile: {}", self.cipher_suite, self.active_strategy),
        });
        if self.tick % 100 == 0 && self.items_done > 0 {
            if let Ok(db) = crate::engine::SessionDatabase::init() {
                let _ = db.update_checkpoint(&self.target_path, self.items_done, "RUNNING");
            }
        }

        let _ = self.tel_tx.send(TelemetryEvent::Log {
            level:   LogLevel::Info,
            path:    String::new(),
            message: format!(
                "Compute Engine Engaged: {} │ Keyspace: {}",
                self.active_engine.display_name(),
                req.keyspace_name
            ),
        });
    }

    fn mark_unsupported(&mut self) {
        self.worker_state  = WorkerState::Exhausted;
        self.speed_mbps    = 0.0;
        self.thread_active = 0;
        self.eta_secs      = 0.0;

        let _ = self.tel_tx.send(TelemetryEvent::Log {
            level:   LogLevel::Err,
            path:    self.target_path.clone(),
            message: format!(
                "❌ FORMAT NOT RECOVERABLE: '{}' ({}) has no native in-process cracker and no external backend (Hashcat / John the Ripper) was found in PATH.",
                self.target_path, self.cipher_suite
            ),
        });

        let _ = self.tel_tx.send(TelemetryEvent::Log {
            level:   LogLevel::Warn,
            path:    String::new(),
            message: "To crack this container format, please install 'hashcat' or 'john' on this host.".into(),
        });

        let _ = self.tel_tx.send(TelemetryEvent::Exhausted {
            items_total:     self.items_total,
            elapsed_secs:    0.0,
            base_speed:      0.0,
            target_path:     self.target_path.clone(),
            cipher_suite:    self.cipher_suite.clone(),
            active_strategy: self.active_strategy.clone(),
            thread_count:    self.thread_count,
        });
    }

    fn step_running_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        self.elapsed_secs += 0.033;

        // ── 1. EXTERNAL SUBPROCESS BACKEND POLLING ────────────────────────────
        if let Some(backend) = &mut self.active_backend {
            let mut got_completed = None;
            let mut got_exhausted = false;

            while let Some(telem) = backend.poll() {
                if telem.speed_hps > 0.0 {
                    self.speed_mbps = telem.speed_hps;
                }
                if telem.progress_done > 0 {
                    self.items_done = telem.progress_done;
                }
                if telem.progress_total > 0 {
                    self.items_total = telem.progress_total;
                }
                if let Some(msg) = telem.log_line {
                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Info,
                        path:    self.target_path.clone(),
                        message: msg,
                    });
                }
                match telem.status {
                    BackendStatus::Completed(key) => {
                        got_completed = Some(key);
                        break;
                    }
                    BackendStatus::Exhausted => {
                        got_exhausted = true;
                        break;
                    }
                    BackendStatus::Failed(err) => {
                        let _ = self.tel_tx.send(TelemetryEvent::Log {
                            level:   LogLevel::Err,
                            path:    self.target_path.clone(),
                            message: format!("External backend failed: {}", err),
                        });
                        got_exhausted = true;
                        break;
                    }
                    _ => {}
                }
            }

            if let Some(cracked_key) = got_completed {
                self.worker_state  = WorkerState::Completed;
                self.speed_mbps    = 0.0;
                self.thread_active = 0;
                self.eta_secs      = 0.0;
                self.active_backend = None;

                let formatted_key = format!("Password: {}", cracked_key);
                let _ = self.tel_tx.send(TelemetryEvent::KeyFound {
                    cracked_key:  formatted_key.clone(),
                    kdf_info:     "External Backend Verified".into(),
                    items_done:   self.items_done,
                    elapsed_secs: self.elapsed_secs,
                    base_speed:   self.base_speed,
                    target_path:  self.target_path.clone(),
                    cipher_suite: self.cipher_suite.clone(),
                    thread_count: self.thread_count,
                });

                let _ = self.tel_tx.send(TelemetryEvent::Log {
                    level:   LogLevel::Lock,
                    path:    self.target_path.clone(),
                    message: format!("✨ KEY RECOVERED BY BACKEND: \"{}\"", formatted_key),
                });
                if let Ok(db) = crate::engine::SessionDatabase::init() {
                    let _ = db.potfile_insert(&self.target_path, &cracked_key, &self.cipher_suite);
                }
                return;
            }

            if got_exhausted {
                self.worker_state  = WorkerState::Exhausted;
                self.speed_mbps    = 0.0;
                self.thread_active = 0;
                self.eta_secs      = 0.0;
                self.active_backend = None;

                let _ = self.tel_tx.send(TelemetryEvent::Exhausted {
                    items_total:     self.items_done,
                    elapsed_secs:    self.elapsed_secs,
                    base_speed:      self.base_speed,
                    target_path:     self.target_path.clone(),
                    cipher_suite:    self.cipher_suite.clone(),
                    active_strategy: self.active_strategy.clone(),
                    thread_count:    self.thread_count,
                });
                return;
            }

            // Backend progress update
            let _ = self.tel_tx.send(TelemetryEvent::ProgressUpdate {
                items_done:    self.items_done,
                items_total:   self.items_total.max(self.items_done),
                speed_mbps:    self.speed_mbps,
                elapsed_secs:  self.elapsed_secs,
                eta_secs:      self.eta_secs,
                thread_active: self.thread_active,
                throughput_mb: (self.speed_mbps as u64).min(100_000),
            });
            return;
        }

        // ── 2. REAL CRYPTOGRAPHIC CANDIDATE EVALUATION ───────────────────────
        if let Some(cracker) = &self.active_cracker {
            if let Some(iter) = &mut self.candidate_iter {
                let batch_size = self.current_batch_size;
                let batch = iter.next_batch(batch_size);
                if batch.is_empty() {
                    // Search exhausted without finding match
                    self.worker_state  = WorkerState::Exhausted;
                    self.speed_mbps    = 0.0;
                    self.thread_active = 0;
                    self.eta_secs      = 0.0;

                    let _ = self.tel_tx.send(TelemetryEvent::Exhausted {
                        items_total:     self.items_done,
                        elapsed_secs:    self.elapsed_secs,
                        base_speed:      self.base_speed,
                        target_path:     self.target_path.clone(),
                        cipher_suite:    self.cipher_suite.clone(),
                        active_strategy: self.active_strategy.clone(),
                        thread_count:    self.thread_count,
                    });

                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Warn,
                        path:    self.target_path.clone(),
                        message: format!(
                            "❌ SEARCH EXHAUSTED: Password not found in {} ({} candidates tested)",
                            self.active_strategy,
                            fmt_num(self.items_done)
                        ),
                    });
                    return;
                }

                self.items_done += batch.len() as u64;
                let tested_count = batch.len();

                // Dispatch batch through the persistent thread pool and measure evaluation latency
                let eval_start = std::time::Instant::now();
                let found_key = if let Some(pool) = &self.crack_pool {
                    pool.evaluate(batch)
                } else {
                    cracker.test_batch(&batch)
                };
                let eval_duration = eval_start.elapsed();
                let eval_sec = eval_duration.as_secs_f64().max(0.0001);
                let eval_ms = eval_sec * 1000.0;

                // Compute real candidates-per-second throughput:
                self.speed_mbps = (tested_count as f64 / eval_sec).max(1.0);

                // Dynamically adapt batch size toward 20ms target to guarantee 30 FPS responsiveness
                let min_batch = (self.thread_count as usize).max(1);
                if eval_ms < 10.0 {
                    self.current_batch_size = (self.current_batch_size * 3 / 2).min(50_000);
                } else if eval_ms > 30.0 {
                    let ratio = (20.0 / eval_ms).clamp(0.2, 0.8);
                    self.current_batch_size = ((self.current_batch_size as f64 * ratio) as usize).max(min_batch);
                }

                if let Some(found_key) = found_key {
                    // Real Key Recovered!
                    self.worker_state  = WorkerState::Completed;
                    self.speed_mbps    = 0.0;
                    self.thread_active = 0;
                    self.eta_secs      = 0.0;

                    let hit_desc = format!(
                        "Candidate #{}/{} ({:.1}%)",
                        fmt_num(self.items_done),
                        fmt_num(self.items_total),
                        (self.items_done as f64 / self.items_total.max(1) as f64) * 100.0
                    );

                    let formatted_key = format!("Password: {}", found_key);
                    let kdf_info = cracker.cipher_name().to_string();

                    if let Ok(db) = crate::engine::SessionDatabase::init() {
                        let _ = db.potfile_insert(&self.target_path, &found_key, &self.cipher_suite);
                    }
                    let _ = self.tel_tx.send(TelemetryEvent::KeyFound {
                        cracked_key:  formatted_key.clone(),
                        kdf_info:     kdf_info.clone(),
                        items_done:   self.items_done,
                        elapsed_secs: self.elapsed_secs,
                        base_speed:   self.base_speed,
                        target_path:  self.target_path.clone(),
                        cipher_suite: self.cipher_suite.clone(),
                        thread_count: self.thread_count,
                    });

                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Lock,
                        path:    self.target_path.clone(),
                        message: format!("✨ KEY RECOVERED: \"{}\" │ {}", formatted_key, hit_desc),
                    });

                    let _ = self.tel_tx.send(TelemetryEvent::Log {
                        level:   LogLevel::Info,
                        path:    String::new(),
                        message: format!(
                            "Task Finished in {:.2}s │ Verified Authentic Against Cryptographic Hash",
                            self.elapsed_secs
                        ),
                    });
                    return;
                }

                // Progress update
                let _ = self.tel_tx.send(TelemetryEvent::ProgressUpdate {
                    items_done:    self.items_done,
                    items_total:   self.items_total.max(self.items_done),
                    speed_mbps:    self.speed_mbps,
                    elapsed_secs:  self.elapsed_secs,
                    eta_secs:      self.eta_secs,
                    thread_active: self.thread_active,
                    throughput_mb: (self.speed_mbps as u64).min(50_000),
                });
                return;
            }
        }

        // ── 3. NO ACTIVE ENGINE OR BACKEND ───────────────────────────────────
        self.worker_state  = WorkerState::Exhausted;
        self.speed_mbps    = 0.0;
        self.thread_active = 0;
        self.eta_secs      = 0.0;

        let _ = self.tel_tx.send(TelemetryEvent::Exhausted {
            items_total:     self.items_total,
            elapsed_secs:    self.elapsed_secs,
            base_speed:      self.base_speed,
            target_path:     self.target_path.clone(),
            cipher_suite:    self.cipher_suite.clone(),
            active_strategy: self.active_strategy.clone(),
            thread_count:    self.thread_count,
        });
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_batch_evaluation() {
        let target = crate::engine::crackers::HashTarget::parse("5d7845ac6ee7cfffafc5fe5f35cf666d").unwrap();
        let cracker = ActiveCracker::Hash(target);

        let candidates: Vec<String> = (0..1000).map(|i| format!("cand_{}", i)).collect();
        let mut cands_with_hit = candidates.clone();
        cands_with_hit[542] = "secret123".to_string();

        let num_threads = 4;
        let chunk_size = (cands_with_hit.len() + num_threads - 1) / num_threads;
        let found = std::sync::atomic::AtomicBool::new(false);
        let mut result: Option<String> = None;

        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for chunk in cands_with_hit.chunks(chunk_size) {
                let found_ref = &found;
                let cracker_ref = &cracker;
                handles.push(s.spawn(move || {
                    if found_ref.load(std::sync::atomic::Ordering::Relaxed) {
                        return None;
                    }
                    let hit = cracker_ref.test_batch(chunk);
                    if hit.is_some() {
                        found_ref.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    hit
                }));
            }
            for h in handles {
                if let Ok(Some(k)) = h.join() {
                    if result.is_none() {
                        result = Some(k);
                    }
                }
            }
        });

        assert_eq!(result, Some("secret123".to_string()));
    }
}
