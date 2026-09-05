// src/engine/protocol.rs — Torcrypt Engine Protocol: Commands, Telemetry, and Cryptographic Enums
// Decoupled communication protocol between the Ratatui TUI frontend and Decryption Workers.

// ─── Worker / Session State ───────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    Idle,
    Running,
    Paused,
    Stopped,
    Completed, // ✨ Key Found / Decrypted
    Exhausted, // ❌ Search Exhausted (0 Matches in Tier)
}

// ─── Compute Target Engine Mode ───────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeEngine {
    GpuPrimary,   // Discrete GPU via CUDA / OpenCL (verified at runtime)
    Hybrid,       // 50% GPU + 50% CPU SIMD
    CpuSimd,      // Multi-threaded CPU AVX2/AVX-512 vectorization
    TlsKeylog,    // TLS session paired with SSLKEYLOGFILE (inspection-only)
    PcapInspect,  // Plaintext protocol credential stream (inspection-only)
}

impl ComputeEngine {
    pub fn display_name(&self) -> &'static str {
        match self {
            ComputeEngine::GpuPrimary  => "GPU ACCELERATED (CUDA / OpenCL Primary)",
            ComputeEngine::Hybrid      => "HYBRID PIPELINE (GPU 50% + CPU 50%)",
            ComputeEngine::CpuSimd     => "CPU VECTORIZED (AVX2 / AVX-512 SIMD)",
            ComputeEngine::TlsKeylog   => "TLS 1.3 STREAM INSPECTOR (pair SSLKEYLOGFILE)",
            ComputeEngine::PcapInspect => "PCAP PROTOCOL STREAM INSPECTOR",
        }
    }
}

// ─── Log Levels ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Lock,
    Warn,
    Err,
}

// ─── Commands (TUI -> Engine) ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AttackRequest {
    pub target_path:     String,
    pub cipher_suite:    String,   // maps to lock_type from FileAnalysis
    pub active_engine:   ComputeEngine,
    pub strategy_id:     String,
    pub strategy_title:  String,
    pub keyspace_name:   String,
    pub items_total:     u64,
    pub speed_base:      f64,
    pub thread_count:    u8,
    pub wordlist_path:   Option<String>,
    pub start_offset:    u64,
    /// Passed into BackendJob::launch so hashcat_mode_for() can select -m <mode>
    pub cipher_desc:     Option<String>,
}

#[derive(Debug, Clone)]
pub enum EngineCommand {
    StartAttack(AttackRequest),
    Pause,
    Resume,
    Cancel,
    Shutdown,
}

// ─── Telemetry Events (Engine -> TUI) ─────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum TelemetryEvent {
    Log {
        level:   LogLevel,
        path:    String,
        message: String,
    },
    Started {
        target_path:     String,
        cipher_suite:    String,
        active_strategy: String,
        active_engine:   ComputeEngine,
        items_total:     u64,
        speed_cps:       f64,  // candidates per second (was incorrectly named speed_mbps)
        thread_count:    u8,
        eta_secs:        f64,
    },
    ProgressUpdate {
        items_done:      u64,
        items_total:     u64,
        speed_cps:       f64,  // candidates per second
        elapsed_secs:    f64,
        eta_secs:        f64,
        thread_active:   u8,
        throughput_cps:  u64,  // for sparkline history (was throughput_mb)
    },
    KeyFound {
        cracked_key:     String,
        kdf_info:        String,
        items_done:      u64,
        elapsed_secs:    f64,
        base_speed:      f64,
        target_path:     String,
        cipher_suite:    String,
        thread_count:    u8,
    },
    Exhausted {
        items_total:     u64,
        elapsed_secs:    f64,
        base_speed:      f64,
        target_path:     String,
        cipher_suite:    String,
        active_strategy: String,
        thread_count:    u8,
    },
    Paused,
    Resumed,
    Cancelled,
}
