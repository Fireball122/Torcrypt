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

echo ""
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  ✨ TORCRYPT installation complete!${RESET}"
echo -e "${GREEN}${BOLD}═════════════════════════════════════════════════════════════════${RESET}"
echo -e "  Run: ${CYAN}${BOLD}torcrypt${RESET}  (or shorthand: ${BOLD}dt${RESET})"
echo ""
