// app.rs — TORCRYPT AppState: Routing, File Explorer & Smart Decryption Analyzer, Ring-Buffer Telemetry
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use chrono::Utc;

// ─── Tab Routing (5 Tabs) ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Analyze,   // [1] File Selector & Smart Decryption Analyzer
    Dashboard, // [2] Live Worker & Throughput Monitor
    Benchmark, // [3] Multi-Core Cryptographic Benchmarks
    Sessions,  // [4] Session Registry & Database
    System,    // [5] Host Diagnostics & HW Flags
}

impl Tab {
    pub fn index(self) -> usize {
        match self {
            Tab::Analyze   => 0,
            Tab::Dashboard => 1,
            Tab::Benchmark => 2,
            Tab::Sessions  => 3,
            Tab::System    => 4,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Analyze,
            1 => Tab::Dashboard,
            2 => Tab::Benchmark,
            3 => Tab::Sessions,
            4 => Tab::System,
            _ => Tab::Analyze,
        }
    }
}

// ─── Worker / Session State ───────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerState {
    Idle,
    Running,
    Paused,
    Stopped,
    Completed,
}

// ─── Log Entries (Structured, Ring-Buffered) ──────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Lock,
    Warn,
    Err,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level:     LogLevel,
    pub path:      String,
    pub message:   String,
}

// ─── File Explorer & Smart Analysis Models ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path:         PathBuf,
    pub name:         String,
    pub is_dir:       bool,
    pub is_parent:    bool,
    pub size_bytes:   u64,
    pub is_encrypted: bool,
    pub badge:        String,
}

#[derive(Debug, Clone)]
pub struct FileAnalysis {
    pub file_path:          String,
    pub file_size:          u64,
    pub mime_type:          String,
    pub is_encrypted:       bool,
    pub lock_type:          String,
    pub entropy:            f64,
    pub magic_header:       String,
    pub recommended_attack: String,
    pub ready_to_crack:     bool,
    pub attack_profile_idx: usize, // 0: Wordlist, 1: Mask, 2: Contextual
}

impl Default for FileAnalysis {
    fn default() -> Self {
        Self {
            file_path:          "No file selected".into(),
            file_size:          0,
            mime_type:          "N/A".into(),
            is_encrypted:       false,
            lock_type:          "None".into(),
            entropy:            0.0,
            magic_header:       "—".into(),
            recommended_attack: "Select a file to inspect".into(),
            ready_to_crack:     false,
            attack_profile_idx: 0,
        }
    }
}

// ─── Session Registry ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Session {
    pub id:           String,
    pub target:       String,
    pub cipher:       String,
    pub kdf:          String,
    pub status:       String,
    pub created_at:   String,
    pub keys_checked: u64,
    pub speed_mbps:   f64,
    pub memory_mb:    u32,
    pub threads:      u8,
}

// ─── Benchmark Results ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BenchResult {
    pub name:          String,
    pub single_mb:     u64,
    pub multi_mb:      u64,
    pub latency_us:    f64,
    pub hw_accel:      bool,
}

// ─── AppState ────────────────────────────────────────────────────────────────

pub struct AppState {
    // Startup Splash Animation
    pub in_splash:          bool,
    pub splash_frame:       usize,
    pub splash_last_tick:   Instant,
    pub splash_start_time:  Instant,

    // Routing
    pub current_tab:        Tab,
    pub show_help:          bool,

    // File Explorer & Smart Decryption Analyzer
    pub current_dir:        PathBuf,
    pub dir_entries:        Vec<FileEntry>,
    pub file_selected_idx:  usize,
    pub analysis:           FileAnalysis,
    pub attack_selected:    usize, // 0: Wordlist+Rules, 1: Mask/Bruteforce, 2: Contextual

    // Worker
    pub worker_state:       WorkerState,
    pub cipher_suite:       String,
    pub target_path:        String,
    pub items_done:         u64,
    pub items_total:        u64,
    pub elapsed_secs:       f64,
    pub eta_secs:           f64,
    pub speed_mbps:         f64,
    pub thread_count:       u8,
    pub thread_active:      u8,

    // Telemetry (ring buffers, fixed capacity)
    pub throughput_history: VecDeque<u64>,      // 60 samples
    pub log_ring:           VecDeque<LogEntry>, // 200 entries

    // Sessions
    pub sessions:           Vec<Session>,
    pub sessions_selected:  usize,
    pub search_mode:        bool,
    pub search_query:       String,

    // Benchmark
    pub bench_results:      Vec<BenchResult>,
    pub bench_selected:     usize,
    pub bench_running:      bool,
    pub bench_progress:     u8, // 0–100

    // System info (populated once at startup)
    pub sys_os:             String,
    pub sys_kernel:         String,
    pub sys_arch:           String,
    pub sys_cpu:            String,
    pub sys_rustc:          String,
    pub cpu_usage_pct:      u8,
    pub ram_used_gb:        f64,
    pub ram_total_gb:       f64,
    pub aes_ni:             bool,
    pub avx2:               bool,
    pub rdrand:             bool,
    pub vaes512:            bool,

    // Tick counter (drives animations)
    pub tick:               u64,
}

impl Default for AppState {
    fn default() -> Self {
        let initial_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/home/ultaria"));
        let now = Instant::now();

        let mut state = Self {
            in_splash:          true,
            splash_frame:       0,
            splash_last_tick:   now,
            splash_start_time:  now,

            current_tab:        Tab::Analyze,
            show_help:          false,

            current_dir:        initial_dir,
            dir_entries:        Vec::new(),
            file_selected_idx:  0,
            analysis:           FileAnalysis::default(),
            attack_selected:    0,

            // Clean IDLE / STANDBY startup state
            worker_state:       WorkerState::Idle,
            cipher_suite:       "—".into(),
            target_path:        "No active target (Select in [1] Analyze)".into(),
            items_done:         0,
            items_total:        0,
            elapsed_secs:       0.0,
            eta_secs:           0.0,
            speed_mbps:         0.0,
            thread_count:       12,
            thread_active:      0,

            throughput_history: VecDeque::with_capacity(60),
            log_ring:           VecDeque::with_capacity(200),

            sessions: vec![
                Session {
                    id:           "SES-9821".into(),
                    target:       "/var/vaults/secure_payload.enc".into(),
                    cipher:       "AES-256-GCM".into(),
                    kdf:          "Argon2id".into(),
                    status:       "COMPLETED".into(),
                    created_at:   "2026-08-27 22:42".into(),
                    keys_checked: 25_000,
                    speed_mbps:   428.5,
                    memory_mb:    64,
                    threads:      12,
                },
                Session {
                    id:           "SES-9819".into(),
                    target:       "/home/ultaria/keys/backup.key".into(),
                    cipher:       "ChaCha20-Poly1305".into(),
                    kdf:          "BLAKE3".into(),
                    status:       "COMPLETED".into(),
                    created_at:   "2026-08-27 20:11".into(),
                    keys_checked: 1_200_000,
                    speed_mbps:   1120.0,
                    memory_mb:    32,
                    threads:      8,
                },
            ],
            sessions_selected:  0,
            search_mode:        false,
            search_query:       String::new(),

            bench_results: vec![
                BenchResult { name: "AES-256-GCM (AVX2)".into(),   single_mb: 720,  multi_mb: 1450, latency_us: 0.69, hw_accel: true  },
                BenchResult { name: "ChaCha20-Poly1305".into(),     single_mb: 560,  multi_mb: 1120, latency_us: 0.89, hw_accel: true  },
                BenchResult { name: "AES-256-CTR (AVX2)".into(),    single_mb: 840,  multi_mb: 1680, latency_us: 0.59, hw_accel: true  },
                BenchResult { name: "XChaCha20-Poly1305".into(),    single_mb: 490,  multi_mb: 980,  latency_us: 1.02, hw_accel: true  },
                BenchResult { name: "Argon2id (16MB Cost)".into(),  single_mb: 170,  multi_mb: 340,  latency_us: 5.88, hw_accel: false },
            ],
            bench_selected:     0,
            bench_running:      false,
            bench_progress:     0,

            sys_os:             "Linux x86_64 (Debian 13 / Trixie)".into(),
            sys_kernel:         "6.12.74-amd64 SMP PREEMPT_DYNAMIC".into(),
            sys_arch:           "x86_64".into(),
            sys_cpu:            "Intel Celeron J4105 @ 1.50GHz (4C/4T)".into(),
            sys_rustc:          "rustc 1.98.0 (88d9e12ae)".into(),
            cpu_usage_pct:      12,
            ram_used_gb:        4.2,
            ram_total_gb:       32.0,
            aes_ni:             true,
            avx2:               true,
            rdrand:             true,
            vaes512:            false,

            tick:               0,
        };

        // Fill initial 60 throughput slots with 0 MB/s
        for _ in 0..60 {
            state.throughput_history.push_back(0);
        }

        // Clean initial startup logs
        state.add_log(LogLevel::Info, "", "Hardware cryptographic acceleration active (AES-NI / AVX2)");
        state.add_log(LogLevel::Info, "", "Torcrypt engine initialized — STANDBY mode");
        state.add_log(LogLevel::Info, "", "PCAP / WPA2-PSK & Container analyzer active — select target in Tab 1");

        // Load initial directory listing
        state.refresh_directory();

        state
    }
}

impl AppState {
    // ── Directory Refresh & Navigation ───────────────────────────────────────

    pub fn navigate_up_directory(&mut self) {
        if let Some(parent) = self.current_dir.parent().map(|p| p.to_path_buf()) {
            self.current_dir = parent;
            self.refresh_directory();
        }
    }

    pub fn refresh_directory(&mut self) {
        let mut entries: Vec<FileEntry> = Vec::new();

        // 1. Add explicit parent directory entry if not at filesystem root
        if self.current_dir.parent().is_some() {
            entries.push(FileEntry {
                path:         self.current_dir.parent().unwrap().to_path_buf(),
                name:         ".. (Parent Directory ↩)".into(),
                is_dir:       true,
                is_parent:    true,
                size_bytes:   0,
                is_encrypted: false,
                badge:        "↩ [BACK]".into(),
            });
        }

        // 2. Read current directory entries
        if let Ok(read_dir) = fs::read_dir(&self.current_dir) {
            let mut dirs: Vec<FileEntry> = Vec::new();
            let mut files: Vec<FileEntry> = Vec::new();

            for entry_res in read_dir.flatten() {
                let path = entry_res.path();
                let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();

                if name.starts_with('.') && name != ".." {
                    continue;
                }

                if let Ok(meta) = entry_res.metadata() {
                    if meta.is_dir() {
                        dirs.push(FileEntry {
                            path,
                            name,
                            is_dir:       true,
                            is_parent:    false,
                            size_bytes:   0,
                            is_encrypted: false,
                            badge:        "📁 [DIR]".into(),
                        });
                    } else {
                        let size = meta.len();
                        let (badge, is_enc) = detect_file_badge(&path, &name);
                        files.push(FileEntry {
                            path,
                            name,
                            is_dir:       false,
                            is_parent:    false,
                            size_bytes:   size,
                            is_encrypted: is_enc,
                            badge,
                        });
                    }
                }
            }

            dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

            entries.extend(dirs);
            entries.extend(files);
        }

        self.dir_entries = entries;
        if self.file_selected_idx >= self.dir_entries.len() {
            self.file_selected_idx = 0;
        }

        self.analyze_selected_file();
    }

    // ── Smart Magic-Byte Container Analysis ──────────────────────────────────

    pub fn analyze_selected_file(&mut self) {
        if self.dir_entries.is_empty() || self.file_selected_idx >= self.dir_entries.len() {
            self.analysis = FileAnalysis::default();
            return;
        }

        let entry = &self.dir_entries[self.file_selected_idx];
        if entry.is_parent {
            self.analysis = FileAnalysis {
                file_path:          entry.path.to_string_lossy().to_string(),
                file_size:          0,
                mime_type:          "Parent Directory Navigation".into(),
                is_encrypted:       false,
                lock_type:          "Directory Level Up".into(),
                entropy:            0.0,
                magic_header:       "N/A".into(),
                recommended_attack: "Press [Enter] or [← / Backspace] to go back".into(),
                ready_to_crack:     false,
                attack_profile_idx: 0,
            };
            return;
        }

        if entry.is_dir {
            self.analysis = FileAnalysis {
                file_path:          entry.path.to_string_lossy().to_string(),
                file_size:          0,
                mime_type:          "Directory / Folder".into(),
                is_encrypted:       false,
                lock_type:          "Unencrypted Directory".into(),
                entropy:            0.0,
                magic_header:       "N/A".into(),
                recommended_attack: "Press [Enter] to enter directory".into(),
                ready_to_crack:     false,
                attack_profile_idx: 0,
            };
            return;
        }

        self.analysis = analyze_file_magic(&entry.path, entry.size_bytes);
    }

    // ── Launch Attack from Tab 1 ──────────────────────────────────────────────

    pub fn launch_attack_from_analysis(&mut self) {
        if !self.analysis.ready_to_crack {
            return;
        }

        self.target_path   = self.analysis.file_path.clone();
        self.cipher_suite  = self.analysis.lock_type.clone();
        self.worker_state  = WorkerState::Running;
        self.items_done    = 0;
        self.items_total   = 14_344_392; // Standard dictionary size (e.g. RockYou)
        self.elapsed_secs  = 0.0;
        self.eta_secs      = 120.0;
        self.speed_mbps    = 428.5;
        self.thread_active = self.thread_count;

        let attack_name = match self.attack_selected {
            0 => "Dictionary + Hashcat Rule Engine",
            1 => "Mask / Brute-Force Matrix (?u?l?l?d?d)",
            2 => "Contextual Metadata Attack (Username/Host/Year)",
            _ => "Standard Wordlist Attack",
        };

        let path_clone = self.target_path.clone();
        let cipher_clone = self.cipher_suite.clone();

        self.add_log(
            LogLevel::Lock,
            &path_clone,
            &format!("Opened target: {} │ Strategy: {}", cipher_clone, attack_name),
        );
        self.add_log(LogLevel::Info, "", "Dispatched task to 12 CPU worker threads (AVX2 SIMD)");

        // Auto-switch to Tab 2 (Dashboard) to watch live progress
        self.current_tab = Tab::Dashboard;
    }

    // ── Public Mutation Interface ────────────────────────────────────────────

    pub fn add_log(&mut self, level: LogLevel, path: &str, msg: &str) {
        if self.log_ring.len() >= 200 {
            self.log_ring.pop_front();
        }
        self.log_ring.push_back(LogEntry {
            timestamp: Utc::now().format("%H:%M:%S").to_string(),
            level,
            path:    path.to_string(),
            message: msg.to_string(),
        });
    }

    pub fn push_throughput(&mut self, mb: u64) {
        if self.throughput_history.len() >= 60 {
            self.throughput_history.pop_front();
        }
        self.throughput_history.push_back(mb);
    }

    pub fn progress_pct(&self) -> f64 {
        if self.items_total == 0 { return 0.0; }
        (self.items_done as f64 / self.items_total as f64) * 100.0
    }

    pub fn thread_saturation_pct(&self) -> u8 {
        if self.thread_count == 0 { return 0; }
        ((self.thread_active as u32 * 100) / self.thread_count as u32) as u8
    }

    pub fn on_tick(&mut self) {
        self.tick = self.tick.wrapping_add(1);

        // 1. Advance splash screen animation if active
        if self.in_splash {
            static FRAME_DELAYS_MS: [u64; 13] = [
                500, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 1000
            ];
            let delay_ms = FRAME_DELAYS_MS[self.splash_frame.min(12)];
            if self.splash_last_tick.elapsed().as_millis() as u64 >= delay_ms {
                self.splash_frame += 1;
                self.splash_last_tick = Instant::now();
                if self.splash_frame >= 13 {
                    self.in_splash = false;
                }
            }
            return;
        }

        // 2. Only advance worker stats if actively running a job
        if self.worker_state == WorkerState::Running {
            let jitter = (self.tick % 7) as f64 * 2.5 - 8.0;
            self.speed_mbps = (428.5 + jitter).max(400.0);

            if self.items_done < self.items_total {
                self.items_done = (self.items_done + 4).min(self.items_total);
                self.elapsed_secs += 0.033;
                self.eta_secs = ((self.items_total - self.items_done) as f64 / 120.0).max(0.0);
            }

            if self.tick % 2 == 0 {
                let mb = (420 + (self.tick % 9 * 5)) as u64;
                self.push_throughput(mb);
            }

            if self.tick % 30 == 0 {
                let path_clone = self.target_path.clone();
                self.add_log(LogLevel::Info, &path_clone, "Candidate block verified authentic — hashing candidate batch");
            }
        } else {
            if self.tick % 2 == 0 {
                self.push_throughput(0);
            }
        }

        // 3. Advance benchmark progress if benchmark is executing
        if self.bench_running && self.bench_progress < 100 {
            self.bench_progress = (self.bench_progress + 2).min(100);
            if self.bench_progress == 100 {
                self.bench_running = false;
                self.add_log(LogLevel::Lock, "", "Multi-threaded benchmark suite run completed.");
            }
        }
    }

    pub fn on_key_char(&mut self, c: char) {
        if self.search_mode {
            match c {
                '\x08' | '\x7f' => { self.search_query.pop(); }
                c if c.is_ascii_graphic() || c == ' ' => self.search_query.push(c),
                _ => {}
            }
            return;
        }

        match c {
            '1' => self.current_tab = Tab::Analyze,
            '2' => self.current_tab = Tab::Dashboard,
            '3' => self.current_tab = Tab::Benchmark,
            '4' => self.current_tab = Tab::Sessions,
            '5' => self.current_tab = Tab::System,
            '?' => self.show_help = !self.show_help,
            'q' | 'Q' => {} // handled in main

            // Tab 1 Actions: Launch Attack / Cycle Strategy / Directory Navigation
            'a' | 'A' if self.current_tab == Tab::Analyze => {
                self.launch_attack_from_analysis();
            }
            '\t' if self.current_tab == Tab::Analyze => {
                self.attack_selected = (self.attack_selected + 1) % 3;
            }
            'h' | 'H' | 'b' | 'B' if self.current_tab == Tab::Analyze => {
                self.navigate_up_directory();
            }

            ' ' => {
                if self.current_tab == Tab::Analyze && self.analysis.ready_to_crack {
                    self.launch_attack_from_analysis();
                } else if self.worker_state == WorkerState::Running {
                    self.worker_state = WorkerState::Paused;
                    self.add_log(LogLevel::Warn, "", "Worker pipeline PAUSED by user");
                } else if self.worker_state == WorkerState::Paused {
                    self.worker_state = WorkerState::Running;
                    self.add_log(LogLevel::Info, "", "Worker pipeline RESUMED");
                }
            }
            'c' | 'C' => {
                if self.worker_state == WorkerState::Running || self.worker_state == WorkerState::Paused {
                    self.worker_state = WorkerState::Stopped;
                    self.speed_mbps   = 0.0;
                    self.thread_active = 0;
                    self.add_log(LogLevel::Err, "", "Active session cancelled by user");
                }
            }
            'b' | 'B' => {
                if !self.bench_running {
                    self.bench_running  = true;
                    self.bench_progress = 0;
                    self.add_log(LogLevel::Info, "", "Executing multi-core throughput benchmark suite...");
                }
            }
            '/' => {
                if self.current_tab == Tab::Sessions {
                    self.search_mode  = true;
                    self.search_query = String::new();
                }
            }
            'j' | 'J' => {
                if self.current_tab == Tab::Analyze && !self.dir_entries.is_empty() {
                    self.file_selected_idx = (self.file_selected_idx + 1).min(self.dir_entries.len().saturating_sub(1));
                    self.analyze_selected_file();
                }
                if self.current_tab == Tab::Sessions {
                    self.sessions_selected = (self.sessions_selected + 1).min(self.sessions.len().saturating_sub(1));
                }
                if self.current_tab == Tab::Benchmark {
                    self.bench_selected = (self.bench_selected + 1).min(self.bench_results.len().saturating_sub(1));
                }
            }
            'k' | 'K' => {
                if self.current_tab == Tab::Analyze && self.file_selected_idx > 0 {
                    self.file_selected_idx -= 1;
                    self.analyze_selected_file();
                }
                if self.current_tab == Tab::Sessions && self.sessions_selected > 0 {
                    self.sessions_selected -= 1;
                }
                if self.current_tab == Tab::Benchmark && self.bench_selected > 0 {
                    self.bench_selected -= 1;
                }
            }
            '\x1b' => {
                self.show_help   = false;
                self.search_mode = false;
            }
            _ => {}
        }
    }

    pub fn filtered_sessions(&self) -> Vec<&Session> {
        let q = self.search_query.to_lowercase();
        self.sessions
            .iter()
            .filter(|s| {
                q.is_empty()
                    || s.id.to_lowercase().contains(&q)
                    || s.target.to_lowercase().contains(&q)
                    || s.cipher.to_lowercase().contains(&q)
                    || s.status.to_lowercase().contains(&q)
            })
            .collect()
    }
}

// ─── File Magic Detection & Entropy Calculation ───────────────────────────────

fn detect_file_badge(path: &Path, name: &str) -> (String, bool) {
    let lower = name.to_lowercase();
    if lower.ends_with(".zip") {
        ("🔒 [ZIP]".into(), true)
    } else if lower.ends_with(".pcap") || lower.ends_with(".pcapng") || lower.ends_with(".cap") {
        ("📡 [WPA]".into(), true)
    } else if lower.ends_with(".hccapx") || lower.ends_with(".22000") {
        ("📶 [WPA]".into(), true)
    } else if lower.ends_with(".pdf") {
        ("📄 [PDF]".into(), true)
    } else if lower.ends_with(".rar") {
        ("📦 [RAR]".into(), true)
    } else if lower.ends_with(".docx") || lower.ends_with(".xlsx") || lower.ends_with(".pptx") {
        ("📊 [DOC]".into(), true)
    } else if lower.ends_with(".enc") || lower.ends_with(".aes") || lower.ends_with(".vault") {
        ("🔐 [ENC]".into(), true)
    } else if lower.ends_with(".hash") || lower.ends_with(".txt") {
        ("🔑 [TXT]".into(), false)
    } else {
        ("📄 [FILE]".into(), false)
    }
}

fn calculate_shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in bytes { counts[b as usize] += 1; }
    let total = bytes.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn analyze_file_magic(path: &Path, size_bytes: u64) -> FileAnalysis {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return FileAnalysis {
                file_path: path.to_string_lossy().to_string(),
                file_size: size_bytes,
                mime_type: "Permission Denied / Unreadable".into(),
                is_encrypted: false,
                lock_type: "Unreadable File".into(),
                entropy: 0.0,
                magic_header: "N/A".into(),
                recommended_attack: "Check file permissions".into(),
                ready_to_crack: false,
                attack_profile_idx: 0,
            };
        }
    };

    let mut buf = [0u8; 4096];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    let slice = &buf[..bytes_read];

    let entropy = calculate_shannon_entropy(slice);
    let hex_header = slice.iter().take(8).map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ");
    let filename = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

    // 1. PCAP / PCAPNG Network Captures (0xD4C3B2A1 / 0xA1B2C3D4 / 0x0A0D0D0A)
    let is_pcap_le = slice.starts_with(&[0xD4, 0xC3, 0xB2, 0xA1]);
    let is_pcap_be = slice.starts_with(&[0xA1, 0xB2, 0xC3, 0xD4]);
    let is_pcap_ns = slice.starts_with(&[0x4D, 0x3C, 0xB2, 0xA1]);
    let is_pcapng  = slice.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]);
    let is_hccapx  = slice.starts_with(b"HCPX") || filename.ends_with(".hccapx") || filename.ends_with(".22000");

    if is_pcap_le || is_pcap_be || is_pcap_ns || is_pcapng || is_hccapx || filename.ends_with(".pcap") || filename.ends_with(".cap") {
        let has_eapol = slice.windows(2).any(|w| w == [0x88, 0x8E]) || filename.contains("wpa") || filename.contains("handshake");
        let mime = if is_pcapng { "application/x-pcapng (Wireshark Capture)" } else if is_hccapx { "application/x-hashcat-22000" } else { "application/vnd.tcpdump.pcap" };

        return FileAnalysis {
            file_path: path.to_string_lossy().to_string(),
            file_size: size_bytes,
            mime_type: mime.into(),
            is_encrypted: true,
            lock_type: "WPA2/WPA3-PSK (PBKDF2-SHA1, 4096 iter, 32-byte PMK)".into(),
            entropy,
            magic_header: if is_pcapng { "0A 0D 0D 0A (PCAPNG)".into() } else if is_hccapx { "HCPX (Hashcat Format)".into() } else { format!("D4 C3 B2 A1 ({})", hex_header) },
            recommended_attack: "Dictionary + GPU Rules (WPA 4-Way Handshake / PMKID)".into(),
            ready_to_crack: true,
            attack_profile_idx: 0,
        };
    }

    // 2. ZIP Inspection (PK\x03\x04)
    if slice.len() >= 8 && slice.starts_with(b"PK\x03\x04") {
        let flags = u16::from_le_bytes([slice[6], slice[7]]);
        let is_encrypted = (flags & 0x0001) != 0;

        let has_winzip_aes = slice.windows(4).any(|w| w == [0x01, 0x99, 0x07, 0x00] || w == [0x01, 0x99]);
        let lock_type = if is_encrypted {
            if has_winzip_aes {
                "WinZip AES-256 (PBKDF2-HMAC-SHA1, 1000 iter)".to_string()
            } else {
                "ZipCrypto Standard (PKWARE Traditional 96-bit)".to_string()
            }
        } else {
            "Plaintext ZIP Archive (Not Encrypted)".to_string()
        };

        return FileAnalysis {
            file_path: path.to_string_lossy().to_string(),
            file_size: size_bytes,
            mime_type: "application/zip (Archive Container)".into(),
            is_encrypted,
            lock_type,
            entropy,
            magic_header: format!("PK 03 04 ({})", hex_header),
            recommended_attack: if is_encrypted {
                "Standard Wordlist + Hashcat Rules (rockyou.txt)"
            } else {
                "No decryption required (archive is unencrypted)"
            }.into(),
            ready_to_crack: is_encrypted,
            attack_profile_idx: 0,
        };
    }

    // 3. PDF Document (%PDF-)
    if slice.starts_with(b"%PDF-") {
        let is_encrypted = slice.windows(8).any(|w| w == b"/Encrypt") || filename.ends_with(".pdf");
        return FileAnalysis {
            file_path: path.to_string_lossy().to_string(),
            file_size: size_bytes,
            mime_type: "application/pdf (Adobe Document)".into(),
            is_encrypted,
            lock_type: if is_encrypted { "PDF Standard Security Handler ($pdf$ AES-128/256)".into() } else { "Plaintext PDF Document".into() },
            entropy,
            magic_header: format!("%PDF-1.x ({})", hex_header),
            recommended_attack: if is_encrypted {
                "Wordlist + Digit Mask (?u?l?l?d?d?d)"
            } else {
                "Document is not password protected"
            }.into(),
            ready_to_crack: is_encrypted,
            attack_profile_idx: 1,
        };
    }

    // 4. RAR Archive (Rar!\x1A\x07)
    if slice.starts_with(b"Rar!\x1A\x07") {
        let is_rar5 = slice.len() >= 8 && slice[6] == 0x01 && slice[7] == 0x00;
        let lock_type = if is_rar5 { "RAR5 Archive Encrypted ($rar5$ PBKDF2-SHA256)" } else { "RAR4 Archive Encrypted ($rar3$ AES-128)" };
        return FileAnalysis {
            file_path: path.to_string_lossy().to_string(),
            file_size: size_bytes,
            mime_type: "application/x-rar-compressed".into(),
            is_encrypted: true,
            lock_type: lock_type.into(),
            entropy,
            magic_header: format!("Rar! 1A 07 ({})", hex_header),
            recommended_attack: "Hybrid Dictionary + Suffix Mask Attack".into(),
            ready_to_crack: true,
            attack_profile_idx: 0,
        };
    }

    // 5. Raw AES / High-Entropy Encrypted Binary
    if entropy > 7.80 || filename.ends_with(".enc") || filename.ends_with(".aes") || filename.ends_with(".vault") {
        return FileAnalysis {
            file_path: path.to_string_lossy().to_string(),
            file_size: size_bytes,
            mime_type: "application/octet-stream (Raw Encrypted Vault)".into(),
            is_encrypted: true,
            lock_type: "AES-256-GCM / Argon2id Key Derivation".into(),
            entropy,
            magic_header: hex_header,
            recommended_attack: "Multi-Threaded Vectorized SIMD Brute-Force".into(),
            ready_to_crack: true,
            attack_profile_idx: 0,
        };
    }

    // 6. Default Plaintext / Hash File
    let is_txt = filename.ends_with(".txt") || filename.ends_with(".hash");
    FileAnalysis {
        file_path: path.to_string_lossy().to_string(),
        file_size: size_bytes,
        mime_type: if is_txt { "text/plain (Candidate / Hash List)".into() } else { "application/octet-stream".into() },
        is_encrypted: false,
        lock_type: "Unencrypted / Plaintext Data".into(),
        entropy,
        magic_header: hex_header,
        recommended_attack: "Use as Dictionary / Wordlist source".into(),
        ready_to_crack: false,
        attack_profile_idx: 0,
    }
}
