#!/usr/bin/env bash
set -e

# ==============================================================================
#  TORCRYPT — One-Liner Universal Installer
#  Repository: https://github.com/Fireball122/torcrypt
# ==============================================================================

REPO="Fireball122/torcrypt"
BIN_NAME="torcrypt-tui"
ALIAS_NAME="torcrypt"
SHORT_ALIAS="dt"
INSTALL_DIR="${HOME}/.local/bin"

# Visual styling tokens
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

# 1. Detect Architecture & OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
    x86_64|amd64)  ARCH="x86_64" ;;
    aarch64|arm64) ARCH="aarch64" ;;
    *)
        echo -e "${RED}[-] Unsupported architecture: ${ARCH}${RESET}"
        exit 1
        ;;
esac

case "${OS}" in
    linux)  ASSET_NAME="torcrypt-linux-${ARCH}" ;;
    darwin) ASSET_NAME="torcrypt-macos-${ARCH}" ;;
    *)
        echo -e "${RED}[-] Unsupported operating system: ${OS}${RESET}"
        exit 1
        ;;
esac

echo -e "${CYAN}[*] Platform detected:${RESET} ${BOLD}${OS} (${ARCH})${RESET}"

# 2. Check for latest release binary or fallback to Cargo compilation
mkdir -p "${INSTALL_DIR}"
TARGET_PATH="${INSTALL_DIR}/${BIN_NAME}"

DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"

echo -e "${CYAN}[*] Attempting binary download from GitHub Releases...${RESET}"
if curl -fsSL --connect-timeout 10 "${DOWNLOAD_URL}" -o "${TARGET_PATH}" 2>/dev/null; then
    chmod +x "${TARGET_PATH}"
    echo -e "${GREEN}[✔] Downloaded pre-compiled binary successfully.${RESET}"
else
    echo -e "${YELLOW}[!] Pre-compiled binary not found on release tag. Falling back to Cargo build...${RESET}"
    if command -v cargo >/dev/null 2>&1; then
        echo -e "${CYAN}[*] Compiling latest release with Cargo...${RESET}"
        TEMP_DIR="$(mktemp -d)"
        git clone --depth 1 "https://github.com/${REPO}.git" "${TEMP_DIR}/torcrypt"
        cd "${TEMP_DIR}/torcrypt"
        cargo build --release
        install -m755 "target/release/${BIN_NAME}" "${TARGET_PATH}"
        rm -rf "${TEMP_DIR}"
        echo -e "${GREEN}[✔] Compiled and installed via Cargo.${RESET}"
    else
        echo -e "${RED}[-] Error: Could not download pre-compiled binary and Rust/Cargo is not installed.${RESET}"
        echo -e "${YELLOW}[*] Please install Rust (https://rustup.rs) or check GitHub Releases.${RESET}"
        exit 1
    fi
fi

# 3. Create Symlinks for 'torcrypt' and 'dt'
ln -sf "${TARGET_PATH}" "${INSTALL_DIR}/${ALIAS_NAME}"
ln -sf "${TARGET_PATH}" "${INSTALL_DIR}/${SHORT_ALIAS}"
echo -e "${GREEN}[✔] Created shortcuts:${RESET} ${BOLD}${INSTALL_DIR}/${ALIAS_NAME}${RESET} and ${BOLD}${INSTALL_DIR}/${SHORT_ALIAS}${RESET}"

# 4. Ensure ~/.local/bin is in PATH across all shell profiles
SHELL_CONFIGS=("${HOME}/.bashrc" "${HOME}/.zshrc" "${HOME}/.profile")
PATH_EXPORT='export PATH="${HOME}/.local/bin:${PATH}"'

for config_file in "${SHELL_CONFIGS[@]}"; do
    if [ -f "${config_file}" ]; then
        if ! grep -q "\.local/bin" "${config_file}"; then
            echo -e "\n# Added by Torcrypt installer" >> "${config_file}"
            echo "${PATH_EXPORT}" >> "${config_file}"
            echo -e "${CYAN}[*] Added ~/.local/bin to ${config_file}${RESET}"
        fi
    fi
done

echo ""
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✨ TORCRYPT installation complete!${RESET}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "  To launch the interactive TUI, run:"
echo -e "    ${CYAN}${BOLD}torcrypt${RESET}  ${YELLOW}(or shorthand: ${BOLD}dt${RESET}${YELLOW})${RESET}"
echo ""
