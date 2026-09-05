// src/engine/backends/detector.rs — External Recovery Tool Detector & Capability Matcher
// Probes system paths for Hashcat, John the Ripper, and *2john extractors.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendType {
    Hashcat,
    John,
    Fcrackzip,
    Native,
    None,
}

impl BackendType {
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendType::Hashcat   => "⚡ Hashcat (GPU/OpenCL Accelerator)",
            BackendType::John      => "🔨 John the Ripper (Multi-Core SIMD)",
            BackendType::Fcrackzip => "📦 fcrackzip (Optimized ZIP Cracker)",
            BackendType::Native    => "🦀 Native In-Process Engine (AVX2 SIMD)",
            BackendType::None      => "✖ Unsupported Format",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            BackendType::Hashcat   => "Hashcat",
            BackendType::John      => "John",
            BackendType::Fcrackzip => "fcrackzip",
            BackendType::Native    => "Native",
            BackendType::None      => "None",
        }
    }

    pub fn is_external(&self) -> bool {
        matches!(self, BackendType::Hashcat | BackendType::John | BackendType::Fcrackzip)
    }
}

/// User preference for backend execution engine
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackendSelection {
    #[default]
    Auto,      // Automatically picks best available: Hashcat (GPU) -> John -> fcrackzip -> Native
    Hashcat,   // Force Hashcat
    John,      // Force John the Ripper
    Fcrackzip, // Force fcrackzip
    Native,    // Force built-in pure-Rust engine
}

impl BackendSelection {
    pub fn display_name(&self) -> &'static str {
        match self {
            BackendSelection::Auto      => "AUTO (Best Detected Tool)",
            BackendSelection::Hashcat   => "HASHCAT (GPU / OpenCL)",
            BackendSelection::John      => "JOHN THE RIPPER (Multi-Core SIMD)",
            BackendSelection::Fcrackzip => "FCRACKZIP (Dedicated ZIP)",
            BackendSelection::Native    => "NATIVE ENGINE (Pure Rust AVX2)",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            BackendSelection::Auto      => "Auto",
            BackendSelection::Hashcat   => "Hashcat",
            BackendSelection::John      => "John",
            BackendSelection::Fcrackzip => "fcrackzip",
            BackendSelection::Native    => "Native",
        }
    }

    pub fn next(&self, catalog: &BackendCatalog) -> Self {
        let options = catalog.available_selections();
        if options.is_empty() {
            return BackendSelection::Native;
        }
        let pos = options.iter().position(|&s| s == *self).unwrap_or(0);
        options[(pos + 1) % options.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalTool {
    Hashcat,
    John,
    Fcrackzip,
    Bkcrack,
    Pdfcrack,
    AircrackNg,
    Zip2John,
    Pdf2John,
    Rar2John,
    SevenZip2John,
}

#[derive(Debug, Clone, Default)]
pub struct BackendCatalog {
    pub hashcat:       Option<PathBuf>,
    pub john:          Option<PathBuf>,
    pub fcrackzip:     Option<PathBuf>,
    pub bkcrack:       Option<PathBuf>,
    pub pdfcrack:      Option<PathBuf>,
    pub aircrack_ng:   Option<PathBuf>,
    pub zip2john:      Option<PathBuf>,
    pub pdf2john:      Option<PathBuf>,
    pub rar2john:      Option<PathBuf>,
    pub sevenzip2john: Option<PathBuf>,
}

impl BackendCatalog {
    /// Probe the system PATH and standard binary directories for installed recovery backends.
    pub fn probe() -> Self {
        Self {
            hashcat:       find_executable("hashcat"),
            john:          find_executable("john"),
            fcrackzip:     find_executable("fcrackzip"),
            bkcrack:       find_executable("bkcrack"),
            pdfcrack:      find_executable("pdfcrack"),
            aircrack_ng:   find_executable("aircrack-ng"),
            zip2john:      find_executable("zip2john"),
            pdf2john:      find_executable("pdf2john"),
            rar2john:      find_executable("rar2john"),
            sevenzip2john: find_executable("7z2john").or_else(|| find_executable("7z2john.pl")),
        }
    }

    pub fn has_any(&self) -> bool {
        self.hashcat.is_some() || self.john.is_some() || self.fcrackzip.is_some()
    }

    pub fn has_hashcat(&self) -> bool {
        self.hashcat.is_some()
    }

    pub fn has_john(&self) -> bool {
        self.john.is_some()
    }

    pub fn has_fcrackzip(&self) -> bool {
        self.fcrackzip.is_some()
    }

    pub fn available_selections(&self) -> Vec<BackendSelection> {
        let mut selections = vec![BackendSelection::Auto];
        if self.hashcat.is_some() {
            selections.push(BackendSelection::Hashcat);
        }
        if self.john.is_some() {
            selections.push(BackendSelection::John);
        }
        if self.fcrackzip.is_some() {
            selections.push(BackendSelection::Fcrackzip);
        }
        selections.push(BackendSelection::Native);
        selections
    }

    /// Resolve effective backend for a target considering user preference and target capabilities.
    pub fn resolve_backend(
        &self,
        preference: BackendSelection,
        target_path: &Path,
        cipher_suite: &str,
        has_native_cracker: bool,
    ) -> BackendType {
        match preference {
            BackendSelection::Hashcat => {
                if self.hashcat.is_some() && self.can_hashcat(target_path, cipher_suite) {
                    BackendType::Hashcat
                } else if has_native_cracker {
                    BackendType::Native
                } else if self.john.is_some() && self.can_john(target_path, cipher_suite) {
                    BackendType::John
                } else {
                    BackendType::None
                }
            }
            BackendSelection::John => {
                if self.john.is_some() && self.can_john(target_path, cipher_suite) {
                    BackendType::John
                } else if has_native_cracker {
                    BackendType::Native
                } else if self.hashcat.is_some() && self.can_hashcat(target_path, cipher_suite) {
                    BackendType::Hashcat
                } else {
                    BackendType::None
                }
            }
            BackendSelection::Fcrackzip => {
                if self.fcrackzip.is_some() && self.can_fcrackzip(target_path, cipher_suite) {
                    BackendType::Fcrackzip
                } else if has_native_cracker {
                    BackendType::Native
                } else {
                    self.select_best_backend(target_path, cipher_suite, has_native_cracker)
                }
            }
            BackendSelection::Native => {
                if has_native_cracker {
                    BackendType::Native
                } else {
                    self.select_best_backend(target_path, cipher_suite, has_native_cracker)
                }
            }
            BackendSelection::Auto => {
                self.select_best_backend(target_path, cipher_suite, has_native_cracker)
            }
        }
    }

    /// Automatically selects the best available tool for the target.
    /// Priority: Hashcat (fastest / GPU) > John (broadest formats) > fcrackzip (for zip) > Native Rust > None
    pub fn select_best_backend(
        &self,
        target_path: &Path,
        cipher_suite: &str,
        has_native_cracker: bool,
    ) -> BackendType {
        // 1. Hashcat is premier for GPU/OpenCL acceleration and raw hashes/containers
        if self.hashcat.is_some() && self.can_hashcat(target_path, cipher_suite) {
            return BackendType::Hashcat;
        }

        // 2. John the Ripper handles massive container formats and CPU SIMD
        if self.john.is_some() && self.can_john(target_path, cipher_suite) {
            return BackendType::John;
        }

        // 3. fcrackzip handles standard ZIP archives
        if self.fcrackzip.is_some() && self.can_fcrackzip(target_path, cipher_suite) {
            return BackendType::Fcrackzip;
        }

        // 4. Built-in Native Rust engine
        if has_native_cracker {
            return BackendType::Native;
        }

        BackendType::None
    }

    pub fn can_hashcat(&self, target_path: &Path, cipher_suite: &str) -> bool {
        let ext = target_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let cipher_lower = cipher_suite.to_lowercase();

        hashcat_mode_for(cipher_suite).is_some()
            || ext == "hash"
            || ext == "txt"
            || ext == "22000"
            || ext == "hccapx"
            || cipher_lower.contains("hash")
            || cipher_lower.contains("md5")
            || cipher_lower.contains("sha")
            || cipher_lower.contains("ntlm")
            || cipher_lower.contains("bcrypt")
            || cipher_lower.contains("argon2")
            || cipher_lower.contains("wpa")
            || cipher_lower.contains("pmkid")
            || cipher_lower.contains("zip")
            || cipher_lower.contains("pdf")
            || cipher_lower.contains("rar")
            || cipher_lower.contains("7z")
            || cipher_lower.contains("keepass")
    }

    pub fn can_john(&self, target_path: &Path, cipher_suite: &str) -> bool {
        let ext = target_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let cipher_lower = cipher_suite.to_lowercase();

        ext == "zip"
            || ext == "pdf"
            || ext == "rar"
            || ext == "7z"
            || ext == "kdbx"
            || ext == "hash"
            || ext == "txt"
            || cipher_lower.contains("zip")
            || cipher_lower.contains("pdf")
            || cipher_lower.contains("rar")
            || cipher_lower.contains("7-zip")
            || cipher_lower.contains("keepass")
            || cipher_lower.contains("md5")
            || cipher_lower.contains("sha")
            || cipher_lower.contains("ntlm")
    }

    pub fn can_fcrackzip(&self, target_path: &Path, cipher_suite: &str) -> bool {
        let ext = target_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let cipher_lower = cipher_suite.to_lowercase();
        ext == "zip" && (cipher_lower.contains("zipcrypto") || cipher_lower.contains("pkware") || !cipher_lower.contains("aes"))
    }

    /// Backwards-compatible legacy selector.
    pub fn select_backend(&self, target_path: &Path, cipher_suite: &str) -> Option<BackendType> {
        let b = self.select_best_backend(target_path, cipher_suite, false);
        if b != BackendType::None {
            Some(b)
        } else {
            None
        }
    }

    /// Determine if an unsupported native target can be delegated to an external backend.
    pub fn can_delegate(&self, target_path: &Path, cipher_suite: &str) -> bool {
        self.select_backend(target_path, cipher_suite).is_some()
    }
    /// Locate a specialized extractor tool (e.g. rar2john, 7z2john) for a container format.
    pub fn find_extractor_for(&self, target_path: &Path) -> Option<&Path> {
        let ext = target_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        match ext.as_str() {
            "zip" => self.zip2john.as_deref(),
            "pdf" => self.pdf2john.as_deref(),
            "rar" => self.rar2john.as_deref(),
            "7z"  => self.sevenzip2john.as_deref(),
            _     => None,
        }
    }

    pub fn summary(&self) -> String {
        let mut tools = Vec::new();
        if let Some(p) = &self.hashcat {
            tools.push(format!("⚡ Hashcat ({})", p.display()));
        }
        if let Some(p) = &self.john {
            tools.push(format!("🔨 John ({})", p.display()));
        }
        if let Some(p) = &self.fcrackzip {
            tools.push(format!("📦 fcrackzip ({})", p.display()));
        }
        if let Some(p) = &self.zip2john {
            tools.push(format!("zip2john ({})", p.display()));
        }
        if let Some(p) = &self.pdf2john {
            tools.push(format!("pdf2john ({})", p.display()));
        }
        if let Some(p) = &self.rar2john {
            tools.push(format!("rar2john ({})", p.display()));
        }
        if let Some(p) = &self.sevenzip2john {
            tools.push(format!("7z2john ({})", p.display()));
        }

        if tools.is_empty() {
            "No external recovery tools detected in PATH".into()
        } else {
            tools.join(", ")
        }
    }
}

/// Return the Hashcat -m mode integer for a given container cipher string.
/// The `cipher_desc` is the `lock_type` string produced by analyze_file_magic.
/// Returns None when no Hashcat mode applies (native-only or unsupported).
pub fn hashcat_mode_for(cipher_desc: &str) -> Option<u32> {
    let d = cipher_desc.to_ascii_lowercase();
    if d.contains("md5") && !d.contains("hmac") && !d.contains("pbkdf") {
        return Some(0);   // Raw MD5
    }
    if d.contains("ntlm") || d.contains("sam") {
        return Some(1000); // NTLM
    }
    if d.contains("sha-1") && !d.contains("pbkdf") && !d.contains("hmac") {
        return Some(100);  // Raw SHA-1
    }
    if d.contains("sha-256") && !d.contains("pbkdf") && !d.contains("hmac") {
        return Some(1400); // Raw SHA-256
    }
    if d.contains("zipcrypto") || d.contains("pkware") {
        return Some(17200); // ZipCrypto CRC32
    }
    if d.contains("winzip") || (d.contains("aes") && d.contains("zip")) {
        return Some(13600); // WinZip AES
    }
    if d.contains("pdf") && (d.contains("rc4") || d.contains("revision 2") || d.contains("revision 3")) {
        return Some(10500); // PDF 1.4
    }
    if d.contains("pdf") && d.contains("aes") {
        return Some(10600); // PDF 1.7 AES
    }
    if d.contains("rar3") || d.contains("rar 3") || (d.contains("rar") && !d.contains("rar5")) {
        return Some(12500); // RAR3
    }
    if d.contains("rar5") {
        return Some(13000); // RAR5
    }
    if d.contains("7z") || d.contains("7-zip") {
        return Some(11600); // 7-Zip
    }
    if d.contains("keepass") && d.contains("aes-kdf") {
        return Some(13400); // KeePass 2.x AES-KDF
    }
    if d.contains("keepass") {
        return Some(13400);
    }
    if d.contains("wpa2") || d.contains("pmkid") || d.contains("eapol") {
        return Some(22000); // WPA2 hcxpcapngtool format
    }
    if d.contains("office 97") || d.contains("$office$") || d.contains("cryptoapi") {
        return Some(9700);  // MS Office 97-2003
    }
    if d.contains("office 2013") || d.contains("2013") {
        return Some(9600);  // MS Office 2013
    }
    if d.contains("bitlocker") {
        return Some(22100); // BitLocker
    }
    if d.contains("luks") {
        return Some(14600); // LUKS
    }
    if d.contains("zip") {
        return Some(17200); // Default to PKZIP
    }
    if d.contains("pdf") {
        return Some(10500); // Default to PDF 1.4-1.6
    }
    if d.contains("rar") {
        return Some(12500); // Default to RAR3
    }
    None
}

fn find_executable(name: &str) -> Option<PathBuf> {
    // 1. Check system PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(candidate);
            }
            // Windows fallback with .exe
            #[cfg(target_os = "windows")]
            {
                let candidate_exe = dir.join(format!("{}.exe", name));
                if is_executable(&candidate_exe) {
                    return Some(candidate_exe);
                }
            }
        }
    }

    // 2. Common non-PATH Unix locations
    let common_dirs = [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/homebrew/bin",
        "/snap/bin",
        "/usr/local/sbin",
        "/usr/sbin",
    ];

    for dir in &common_dirs {
        let candidate = PathBuf::from(dir).join(name);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    // 3. User home bin
    if let Ok(home) = std::env::var("HOME") {
        let home_bin = PathBuf::from(home).join(".local/bin").join(name);
        if is_executable(&home_bin) {
            return Some(home_bin);
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = path.metadata() {
            return meta.permissions().mode() & 0o111 != 0;
        }
    }
    #[cfg(not(unix))]
    {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_executable_builtin() {
        // sh or ls should always be found on unix
        #[cfg(unix)]
        {
            assert!(find_executable("sh").is_some());
        }
    }

    #[test]
    fn test_backend_catalog_probe() {
        let catalog = BackendCatalog::probe();
        // Just verify it doesn't panic and returns a valid summary
        let summary = catalog.summary();
        assert!(!summary.is_empty());
    }
}
