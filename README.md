# 🔐 TORCRYPT

> **High-Performance Cryptographic Analysis & Decryption TUI**  
> Built in Rust with **Ratatui** and **Crossterm**. Features a Cyberpunk dark-mode terminal UI, zero dead space, 30 FPS non-blocking event loops, and container header inspection. Native cross-platform support for **Linux**, **macOS**, and **Windows**.

---

## ⚡ One-Liner Quick Install

### 🐧 Linux & 🍎 macOS (Bash / Zsh)
```bash
curl -fsSL https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.sh | bash
```

### 🪟 Windows (PowerShell)
```powershell
irm https://raw.githubusercontent.com/Fireball122/Torcrypt/main/install.ps1 | iex
```

Once installed, launch the application using:
```bash
torcrypt
# or shorthand alias
dt
```

---

## 🌟 Key Features

- **Tab 1: File Selector & Smart Decryption Analyzer (`[1 Analyze]`):**
  - Interactive file system explorer with instant `[← / Backspace]` back navigation.
  - Automatic magic-header container detection:
    - **ZIP Archives (`PK\x03\x04`):** Differentiates between **WinZip AES-256** and **ZipCrypto Standard**.
    - **Wi-Fi Packet Captures (`.pcap`, `.pcapng`, `.hccapx`, `.22000`):** Detects **WPA2/WPA3 EAPOL 4-Way Handshake** and PMKID frames.
    - **PDF Documents (`%PDF-`):** Detects password-protected `/Encrypt` security handlers.
    - **RAR Archives (`Rar!\x1A\x07`):** Identifies RAR4 (`$rar3$`) and RAR5 (`$rar5$`) headers.
    - **Raw Encrypted Vaults (`.enc`, `.aes`):** Calculates Shannon entropy ($0.0 \to 8.0\,\text{bits/byte}$) to identify encrypted blocks.
  - Attack strategy selector: `[Tab]` to cycle between **Standard Wordlist + Rules**, **Mask / Brute-Force Matrix**, and **Contextual Metadata Attack**.
  - One-click launch (`[A]` / `[Space]`) into live multi-threaded decryption pipeline.

- **Tab 2: Live Worker & Throughput Dashboard (`[2 Dashboard]`):**
  - 40/60 responsive split layout.
  - Real-time 60-second sparkline throughput chart (MB/s).
  - Worker saturation gauge, elapsed/ETA timers, and 200-item activity stream table.

- **Tab 3: Multi-Core Cryptographic Benchmark Suite (`[3 Benchmark]`):**
  - Vertical/horizontal comparison bar charts for AES-256-GCM, ChaCha20-Poly1305, Argon2id, AES-CTR, and XChaCha20.
  - Latency and throughput matrix across 1-Core vs 16-Core configurations.

- **Tab 4: Session Registry (`[4 Sessions]`):**
  - Interactive table (`TableState`) with metadata inspector sidebar.
  - Real-time search filter bar (`[/]` to filter).

- **Tab 5: System Diagnostics & Capabilities (`[5 System]`):**
  - Host OS, Kernel, Rustc version, CPU load monitors, per-core mini bars, and hardware SIMD acceleration flags (`AES-NI`, `AVX2`, `RDRAND`).

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|---|---|
| `1` – `5` | Switch Tabs (Analyze, Dashboard, Benchmark, Sessions, System) |
| `J` / `K` or `↑` / `↓` | Navigate file lists, tables, and algorithms |
| `Enter` | Open directory in explorer / Launch selected task |
| `←` / `Backspace` / `H` | Navigate back / level up to parent directory |
| `Tab` | Cycle attack strategies on selected container |
| `A` / `Space` | Launch multi-threaded decryption recovery pipeline |
| `Space` | Pause / Resume active worker pipeline |
| `C` | Cancel active session |
| `B` | Run multi-threaded benchmark suite |
| `/` | Open search filter in Sessions registry |
| `?` | Toggle shortcut reference modal overlay |
| `Q` / `Ctrl+C` | Safely wipe buffers and exit |

---

## 🛠️ Building from Source

```bash
git clone https://github.com/Fireball122/Torcrypt.git
cd Torcrypt
cargo build --release

# Run
./target/release/torcrypt-tui
```

---

## 📄 License

MIT License.
