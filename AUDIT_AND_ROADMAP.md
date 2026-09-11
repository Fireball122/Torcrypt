# TORCRYPT — Architecture Breakdown, Audit & Remediation Roadmap

## 1. Executive Architecture Summary
- **Current Stack**: Standalone Rust application (2021 Edition), Ratatui 0.29 + Crossterm 0.28, SQLite session registry with WAL mode.
- **Legacy C++ Stack**: The repository at `~/decryption-tool` is completely separate and unreferenced by `torcrypt-tui`.
- **Active Repository**: `~/torcrypt-tui` on `server-45` (`git@github.com:Fireball122/torcrypt.git`).

---

## 2. Identified Vulnerabilities & Remediation Status

### 2.1 KeePass False-Positive Bug
- **Location**: `src/engine/crackers/keepass.rs:116-120`
- **Issue**: Previously tested `dec[0..16] != [0u8; 16]` after decrypting `expected_start_bytes`.
- **Status**: **RESOLVED** (`365634e`). Now extracts and decrypts the stream start bytes immediately following the header and performs direct byte comparison against `expected_start_bytes`.

### 2.2 RAR5 Header Traversal Lockup
- **Location**: `src/engine/crackers/rar.rs:102-112`
- **Issue**: Omitted advancing `pos` when skipping non-encryption blocks (e.g. `HEAD_MAIN`).
- **Status**: **RESOLVED** (`365634e`). Re-anchors and advances `pos` to `type_start_pos + hdr_size`.

### 2.3 Tab 1 Key Trapping
- **Location**: `src/app.rs:1157-1180`
- **Issue**: Keys '1'..'6' intercepted tab navigation when a crackable file was selected on Tab 1.
- **Status**: **RESOLVED** (`365634e`). Keys '1'..'5' are dedicated to top-level tab switching; attack tiers cycle via `Tab`.

### 2.4 Terminal Panic Hook
- **Location**: `src/main.rs`
- **Issue**: No panic hook installed.
- **Status**: **RESOLVED** (`365634e`). Configured `std::panic::set_hook` to disable raw mode and mouse capture upon any panic.

### 2.5 Hashcat & John Pipeline Bottlenecks
- **Location**: `src/engine/worker.rs:241` & `src/engine/backends/orchestrator.rs:202-216, 496-501`
- **Issue**: Piped only 500 candidates via `--stdin`; naively parsed any log line with `:` as a cracked password.
- **Status**: **RESOLVED** (`365634e`). Bound host system wordlists (`CandidateIterator::system_wordlist_path()`), expanded stdin fallback to 10,000, and filtered out diagnostic warning lines containing colons.

### 2.6 Container Extractors (7z Coder Properties & PDF Indirect Objects)
- **Location**: `src/engine/extractors/hash_formatter.rs`, `src/engine/crackers/pdf.rs`, `src/engine/crackers/seven_zip.rs`
- **Issue**: PDF failed on indirect `/Encrypt` objects (`/Encrypt N M R`) and had stray `*` in `$pdf$` format; 7z omitted coder property parsing and unpack size.
- **Status**: **RESOLVED** (`a43a6c7`). Implemented `resolve_pdf_encryption_dict` with streaming window search; added 7zAES coder parser for Method ID `[0x06, 0xF1, 0x07, 0x01]` extracting cycles, salt, and IV; standardized Hashcat Mode 10500 and 11600 formats.

### 2.7 Event Loop, Redraw Efficiency & Non-Blocking Benchmarks
- **Location**: `src/main.rs`, `src/app.rs`
- **Issue**: Unconditional 30 FPS redraw spun CPU idle; benchmark suite blocked UI thread for 12+ seconds; Tab 5 CPU/RAM was frozen at launch.
- **Status**: **RESOLVED** (`d970699`). Implemented dirty-state rendering (idle CPU dropped to ~0.1%), background thread benchmark execution over channels, and live host CPU/RAM polling every ~1 second.

### 2.8 SIMD Zero-Allocation & UI TableState Synchronization
- **Location**: `src/engine/crackers/hash.rs`, `src/app.rs`, `src/ui/analyze.rs`, `src/ui/sessions.rs`, `src/ui/dashboard.rs`
- **Issue**: Heap allocation per 8 candidates in hot SIMD loop; mouse click desync on scrolled tables; hardcoded filename truncation; hardcoded sparkline ceiling.
- **Status**: **RESOLVED** (`8289ea4`, `e88f5ed`). Replaced SIMD chunk allocations with stack arrays; stored persistent `TableState` with `offset()`-synchronized click regions; added dynamic filename width scaling, dynamic sparkline autoscaling, realistic compute saturation ratio, and F2 mouse capture toggle.

---

## 3. Verification & Deployment Status
- **Unit Tests**: All 73 unit tests passing (`0.23s`).
- **Release Executable**: Built with `--release` and deployed to `/home/ultaria/.local/bin/torcrypt`.
- **NAS Archives**:
  - Initial State: `tornas:/mnt/vault/projects/Torcrypt/torcrypt-backup-20260909_2348.zip`
  - Remediated State: `tornas:/mnt/vault/projects/Torcrypt/torcrypt-v0.1.22-remediated.zip`
EOF
