// app.rs — TORCRYPT AppState: all data, routing, and ring-buffer telemetry
use std::collections::VecDeque;
use std::time::Instant;
use chrono::Utc;

// ─── Tab Routing ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Benchmark,
    Sessions,
    System,
}

impl Tab {
    pub fn index(self) -> usize {
        match self {
            Tab::Dashboard => 0,
            Tab::Benchmark => 1,
            Tab::Sessions  => 2,
            Tab::System    => 3,
        }
    }

    pub fn from_index(i: usize) -> Self {
        match i {
            0 => Tab::Dashboard,
            1 => Tab::Benchmark,
            2 => Tab::Sessions,
            3 => Tab::System,
            _ => Tab::Dashboard,
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

    // Routing
    pub current_tab:        Tab,
    pub show_help:          bool,

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
    pub throughput_history: VecDeque<u64>,  // 60 samples
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
        let mut state = Self {
            in_splash:        true,
            splash_frame:     0,
            splash_last_tick: Instant::now(),

            current_tab:      Tab::Dashboard,
            show_help:        false,

            // Clean IDLE / STANDBY startup state
            worker_state:     WorkerState::Idle,
            cipher_suite:     "—".into(),
            target_path:      "No active target (Awaiting job)".into(),
            items_done:       0,
            items_total:      0,
            elapsed_secs:     0.0,
            eta_secs:         0.0,
            speed_mbps:       0.0,
            thread_count:     12,
            thread_active:    0,

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
                Session {
                    id:           "SES-9794".into(),
                    target:       "/opt/db_dump/customer_pii.zst".into(),
                    cipher:       "AES-256-CTR".into(),
                    kdf:          "PBKDF2-SHA512".into(),
                    status:       "PAUSED".into(),
                    created_at:   "2026-08-27 18:55".into(),
                    keys_checked: 450_120,
                    speed_mbps:   0.0,
                    memory_mb:    48,
                    threads:      6,
                },
            ],
            sessions_selected: 0,
            search_mode:       false,
            search_query:      String::new(),

            bench_results: vec![
                BenchResult { name: "AES-256-GCM (AVX2)".into(),   single_mb: 720,  multi_mb: 1450, latency_us: 0.69, hw_accel: true  },
                BenchResult { name: "ChaCha20-Poly1305".into(),     single_mb: 560,  multi_mb: 1120, latency_us: 0.89, hw_accel: true  },
                BenchResult { name: "AES-256-CTR (AVX2)".into(),    single_mb: 840,  multi_mb: 1680, latency_us: 0.59, hw_accel: true  },
                BenchResult { name: "XChaCha20-Poly1305".into(),    single_mb: 490,  multi_mb: 980,  latency_us: 1.02, hw_accel: true  },
                BenchResult { name: "Argon2id (16MB Cost)".into(),  single_mb: 170,  multi_mb: 340,  latency_us: 5.88, hw_accel: false },
            ],
            bench_selected:  0,
            bench_running:   false,
            bench_progress:  0,

            sys_os:        "Linux x86_64 (Debian 13 / Trixie)".into(),
            sys_kernel:    "6.12.74-amd64 SMP PREEMPT_DYNAMIC".into(),
            sys_arch:      "x86_64".into(),
            sys_cpu:       "Intel Celeron J4105 @ 1.50GHz (4C/4T)".into(),
            sys_rustc:     "rustc 1.98.0 (88d9e12ae)".into(),
            cpu_usage_pct: 12,
            ram_used_gb:   4.2,
            ram_total_gb:  32.0,
            aes_ni:        true,
            avx2:          true,
            rdrand:        true,
            vaes512:       false,

            tick: 0,
        };

        // Fill initial 60 throughput slots with 0 MB/s
        for _ in 0..60 {
            state.throughput_history.push_back(0);
        }

        // Clean initial startup logs
        state.add_log(LogLevel::Info, "", "Hardware cryptographic acceleration active (AES-NI / AVX2)");
        state.add_log(LogLevel::Info, "", "Torcrypt engine initialized — STANDBY mode");
        state.add_log(LogLevel::Info, "", "Awaiting job dispatch or benchmark execution ([B] to benchmark)");

        state
    }
}

impl AppState {
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
                self.items_done = (self.items_done + 3).min(self.items_total);
            }

            if self.tick % 2 == 0 {
                let mb = (420 + (self.tick % 9 * 5)) as u64;
                self.push_throughput(mb);
            }

            if self.tick % 15 == 0 {
                self.add_log(LogLevel::Info, "/chunks/part_031.bin", "Block stream verified authentic");
            }
        } else {
            // In Idle / Paused / Stopped state, throughput is 0
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
        if self.in_splash {
            self.in_splash = false;
            return;
        }

        if self.search_mode {
            match c {
                '\x08' | '\x7f' => { self.search_query.pop(); }
                c if c.is_ascii_graphic() || c == ' ' => self.search_query.push(c),
                _ => {}
            }
            return;
        }
        match c {
            '1' => self.current_tab = Tab::Dashboard,
            '2' => self.current_tab = Tab::Benchmark,
            '3' => self.current_tab = Tab::Sessions,
            '4' => self.current_tab = Tab::System,
            '?' => self.show_help = !self.show_help,
            'q' | 'Q' => {} // handled in main
            ' ' => {
                // Toggle between Paused and Running if a job exists
                if self.worker_state == WorkerState::Running {
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
                if self.current_tab == Tab::Sessions {
                    self.sessions_selected =
                        (self.sessions_selected + 1).min(self.sessions.len().saturating_sub(1));
                }
                if self.current_tab == Tab::Benchmark {
                    self.bench_selected =
                        (self.bench_selected + 1).min(self.bench_results.len().saturating_sub(1));
                }
            }
            'k' | 'K' => {
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
