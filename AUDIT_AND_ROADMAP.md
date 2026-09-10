# TORCRYPT — Architecture Breakdown, Audit & Remediation Roadmap

## 1. Executive Architecture Summary
- **Current Stack**: Standalone Rust application (2021 Edition), Ratatui 0.29 + Crossterm 0.28, SQLite session registry with WAL mode.
- **Legacy C++ Stack**: The repository at `~/decryption-tool` is completely separate and unreferenced by `torcrypt-tui`.
- **Active Repository**: `~/torcrypt-tui` on `server-45` (`git@github.com:Fireball122/torcrypt.git`).

---

## 2. Identified Vulnerabilities & Critical Bugs

### 2.1 KeePass False-Positive Bug
- **Location**: `src/engine/crackers/keepass.rs:116-120`
- **Issue**: Tests `dec[0..16] != [0u8; 16]` after decrypting `expected_start_bytes`.
- **Consequence**: Decrypting random data almost never produces all zeroes; every candidate password tests as valid on the first attempt.
- **Fix**: Compare decrypted stream start bytes against `expected_start_bytes`.

### 2.2 RAR5 Header Traversal Lockup
- **Location**: `src/engine/crackers/rar.rs:102-112`
- **Issue**: Omits advancing `pos` when skipping non-encryption blocks (e.g. `HEAD_MAIN`).
- **Consequence**: Infinite loop / stream desynchronization; all RAR5 archives fail to parse.
- **Fix**: Re-anchor and increment `pos` to `block_start + 4 + hdr_size`.

### 2.3 Tab 1 Key Trapping
- **Location**: `src/app.rs:1157-1180`
- **Issue**: Keys '1'..'6' intercept tab navigation when a crackable file is selected on Tab 1.
- **Consequence**: Users cannot navigate tabs using number keys.
- **Fix**: Use Tab/Shift-Tab or dedicated keys for attack option selection; keep '1'..'5' reserved for top-level tab switching.

### 2.4 Terminal Panic Hook
- **Location**: `src/main.rs`
- **Issue**: No panic hook installed.
- **Consequence**: Any panic leaves Crossterm raw mode and mouse capture enabled, bricking the user's terminal session.
- **Fix**: Set `std::panic::set_hook` to restore terminal state before printing backtrace.

### 2.5 Hashcat & John Pipeline Bottlenecks
- **Location**: `src/engine/worker.rs:241` & `src/engine/backends/orchestrator.rs:202-216, 496-501`
- **Issue**: Pipes only 500 candidates via `--stdin`; naively parses any log line with `:` as a cracked password.
- **Fix**: Support unbounded streaming or full wordlist file passing; implement strict pattern matching for cracked output.

---

## 3. Prioritized Implementation Roadmap
1. **Safety & Stability**: Panic hook, untracked file commit, Tab 1 keybinding collision fix.
2. **Cryptographic Correctness**: Fix KeePass verification and RAR5 block parsing.
3. **Backend Robustness**: Harden Hashcat and John process orchestration.
4. **Performance Optimization**: Zero-allocation SIMD batching, dirty-state 30 FPS rendering, async file analysis.
