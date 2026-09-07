#!/usr/bin/env bash
set -e

# ==============================================================================
#  TORCRYPT — Universal Installer
#  Repository: https://github.com/Fireball122/Torcrypt
# ==============================================================================

REPO="Fireball122/Torcrypt"
BIN_NAME="torcrypt-tui"
ALIAS_NAME="torcrypt"
SHORT_ALIAS="dt"
INSTALL_DIR="${HOME}/.local/bin"

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo "  ╔═══════════════════════════════════════════════════════════════╗"
echo "  ║        🔐  TORCRYPT — UNIVERSAL CLI & TUI INSTALLER           ║"
echo "  ╚═══════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

# 1. Detect Platform
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *) echo -e "${RED}[-] Unsupported architecture: ${ARCH}${RESET}"; exit 1 ;;
esac

case "${OS}" in
    linux)  ASSET_NAME="torcrypt-linux-${ARCH}" ;;
    darwin) ASSET_NAME="torcrypt-macos-${ARCH}" ;;
    *) echo -e "${RED}[-] Unsupported OS: ${OS}${RESET}"; exit 1 ;;
esac

echo -e "${CYAN}[*] Platform detected:${RESET} ${BOLD}${OS} (${ARCH})${RESET}"

mkdir -p "${INSTALL_DIR}"
TARGET_PATH="${INSTALL_DIR}/${BIN_NAME}"
TEMP_BIN="$(mktemp)"

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
INSTALLED=false

# 2. Try Pre-compiled Static Binary
echo -e "${CYAN}[*] Fetching release binary from GitHub...${RESET}"
if curl -fsSL --connect-timeout 8 "${DOWNLOAD_URL}" -o "${TEMP_BIN}" 2>/dev/null; then
    chmod +x "${TEMP_BIN}"
    # Verify the downloaded binary runs on this host without glibc/linker errors
    if "${TEMP_BIN}" --help >/dev/null 2>&1 || [ $? -le 2 ]; then
        mv "${TEMP_BIN}" "${TARGET_PATH}"
        INSTALLED=true
        echo -e "${GREEN}[✔] Verified and installed static release binary.${RESET}"
    fi
fi
rm -f "${TEMP_BIN}"

# 3. Fallback: Native Cargo Build
if [ "${INSTALLED}" = false ]; then
    echo -e "${YELLOW}[!] Building natively from source via Cargo...${RESET}"
    [ -f "${HOME}/.cargo/env" ] && source "${HOME}/.cargo/env"

    if command -v cargo >/dev/null 2>&1 || [ -x "${HOME}/.cargo/bin/cargo" ]; then
        CARGO_BIN="$(command -v cargo || echo "${HOME}/.cargo/bin/cargo")"
        TEMP_DIR="$(mktemp -d)"
        git clone --depth 1 "https://github.com/${REPO}.git" "${TEMP_DIR}/torcrypt"
        cd "${TEMP_DIR}/torcrypt"
        "${CARGO_BIN}" build --release
        install -m755 "target/release/${BIN_NAME}" "${TARGET_PATH}"
        rm -rf "${TEMP_DIR}"
        echo -e "${GREEN}[✔] Successfully compiled and installed native binary.${RESET}"
    else
        echo -e "${RED}[-] Error: Rust/Cargo required for build.${RESET}"
        exit 1
    fi
fi

# 4. Create Shortcuts
ln -sf "${TARGET_PATH}" "${INSTALL_DIR}/${ALIAS_NAME}"
ln -sf "${TARGET_PATH}" "${INSTALL_DIR}/${SHORT_ALIAS}"
echo -e "${GREEN}[✔] Shortcuts created:${RESET} ${BOLD}${INSTALL_DIR}/${ALIAS_NAME}${RESET} and ${BOLD}${INSTALL_DIR}/${SHORT_ALIAS}${RESET}"

# 5. Ensure ~/.local/bin is in PATH
SHELL_CONFIGS=("${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile")
PATH_EXPORT='export PATH="${HOME}/.local/bin:${PATH}"'

for config_file in "${SHELL_CONFIGS[@]}"; do
    if [ -f "${config_file}" ] && ! grep -q "\.local/bin" "${config_file}"; then
        echo -e "\n# Added by Torcrypt installer\n${PATH_EXPORT}" >> "${config_file}"
        echo -e "${CYAN}[*] Added ~/.local/bin to ${config_file}${RESET}"
    fi
done

# 6. Interactive Setup Helper
prompt_user() {
    local message="$1"
    local default_val="$2"
    local reply=""
    if [ -t 0 ] || [ -e /dev/tty ]; then
        read -r -p "$message: " reply </dev/tty || reply="$default_val"
    else
        reply="$default_val"
    fi
    echo "${reply:-$default_val}"
}

# 7. Interactive External Decryption Backends
echo ""
echo -e "${CYAN}  ┌─────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${CYAN}  │ ⚡ STEP 1: EXTERNAL DECRYPTION GUI ENGINES (OPTIONAL)        │${RESET}"
echo -e "${CYAN}  └─────────────────────────────────────────────────────────────┘${RESET}"
echo -e "  TORCRYPT operates as a GUI frontend for high-speed recovery tools:"
echo -e "    ${BOLD}[1] Hashcat${RESET} (GPU / OpenCL / CUDA Acceleration)"
echo -e "    ${BOLD}[2] John the Ripper${RESET} (Multi-Core SIMD & Jumbo Containers)"
echo -e "    ${BOLD}[3] All recommended tools${RESET} (Hashcat, John the Ripper, fcrackzip)"
echo -e "    ${BOLD}[4] Skip${RESET} (Use built-in pure-Rust AVX2 engine only)"
echo ""

tool_choice=$(prompt_user "  Select an option [1-4] (Default: 3)" "3")

if [ "${tool_choice}" = "1" ] || [ "${tool_choice}" = "2" ] || [ "${tool_choice}" = "3" ]; then
    if command -v apt-get >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Installing selected backends via apt...${RESET}"
        case "${tool_choice}" in
            1) sudo apt-get update && sudo apt-get install -y hashcat ;;
            2) sudo apt-get update && sudo apt-get install -y john ;;
            3) sudo apt-get update && sudo apt-get install -y hashcat john fcrackzip ;;
        esac
    elif command -v pacman >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Installing selected backends via pacman...${RESET}"
        case "${tool_choice}" in
            1) sudo pacman -S --noconfirm hashcat ;;
            2) sudo pacman -S --noconfirm john ;;
            3) sudo pacman -S --noconfirm hashcat john fcrackzip ;;
        esac
    elif command -v dnf >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Installing selected backends via dnf...${RESET}"
        case "${tool_choice}" in
            1) sudo dnf install -y hashcat ;;
            2) sudo dnf install -y john ;;
            3) sudo dnf install -y hashcat john fcrackzip ;;
        esac
    elif command -v brew >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Installing selected backends via Homebrew...${RESET}"
        case "${tool_choice}" in
            1) brew install hashcat ;;
            2) brew install john-jumbo ;;
            3) brew install hashcat john-jumbo fcrackzip ;;
        esac
    else
        echo -e "${YELLOW}[!] No supported package manager found. Please install Hashcat/John manually.${RESET}"
    fi
else
    echo -e "${CYAN}[*] Skipped external backends.${RESET}"
fi

# 8. Interactive Wordlists Download
echo ""
echo -e "${CYAN}  ┌─────────────────────────────────────────────────────────────┐${RESET}"
echo -e "${CYAN}  │ 📖 STEP 2: DICTIONARY WORDLISTS                             │${RESET}"
echo -e "${CYAN}  └─────────────────────────────────────────────────────────────┘${RESET}"
echo -e "  TORCRYPT includes a 27K built-in corpus. Real-world wordlists"
echo -e "  enable recovery of millions of complex passwords:"
echo -e "    ${BOLD}[1] Download RockYou.txt${RESET} (14.3M Passwords - ~134 MB, Industry Standard)"
echo -e "    ${BOLD}[2] Download SecLists Top-100k${RESET} (~1 MB - Lightweight Quick Starter)"
echo -e "    ${BOLD}[3] Download Both RockYou & Top-100k${RESET}"
echo -e "    ${BOLD}[4] Skip wordlists${RESET} (use built-in dictionary or custom wordlists with [W])"
echo ""

wl_choice=$(prompt_user "  Select an option [1-4] (Default: 1)" "1")

WORDLISTS_DIR="${HOME}/.local/share/torcrypt/wordlists"
mkdir -p "${WORDLISTS_DIR}"

if [ "${wl_choice}" = "1" ] || [ "${wl_choice}" = "2" ] || [ "${wl_choice}" = "3" ]; then
    if [ "${wl_choice}" = "1" ] || [ "${wl_choice}" = "3" ]; then
        ROCKYOU_PATH="${WORDLISTS_DIR}/rockyou.txt"
        ROCKYOU_URL="https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"
        echo -e "${CYAN}[*] Downloading RockYou.txt (14.3M passwords, ~134 MB)...${RESET}"
        if curl -fSL --progress-bar "${ROCKYOU_URL}" -o "${ROCKYOU_PATH}"; then
            echo -e "${GREEN}[✔] Saved RockYou wordlist to: ${ROCKYOU_PATH}${RESET}"
        fi
    fi
    if [ "${wl_choice}" = "2" ] || [ "${wl_choice}" = "3" ]; then
        TOP100K_PATH="${WORDLISTS_DIR}/top-100000.txt"
        TOP100K_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-100000.txt"
        echo -e "${CYAN}[*] Downloading SecLists Top-100k...${RESET}"
        if curl -fSL --silent "${TOP100K_URL}" -o "${TOP100K_PATH}"; then
            echo -e "${GREEN}[✔] Saved Top-100k wordlist to: ${TOP100K_PATH}${RESET}"
        fi
    fi
else
    echo -e "${CYAN}[*] Skipped wordlists.${RESET}"
fi

echo ""
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✨ TORCRYPT installation complete!${RESET}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "  Executable : ${BOLD}${TARGET_PATH}${RESET}"
echo -e "  Shortcut   : ${BOLD}torcrypt${RESET}  (or shorthand: ${BOLD}dt${RESET})"
if [ -d "${WORDLISTS_DIR}" ] && [ "$(ls -A "${WORDLISTS_DIR}" 2>/dev/null)" ]; then
    echo -e "  Wordlists  : ${CYAN}${WORDLISTS_DIR}${RESET}"
fi
echo ""
echo -e "  Run: ${CYAN}${BOLD}torcrypt${RESET}  (or shorthand: ${BOLD}dt${RESET})"
echo -e "  In [1 Analyze], press [E] to cycle backends (Auto / Hashcat / John / Native)"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo ""
