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
            BackendType::Hashcat   => "Hashcat (GPU/OpenCL Accelerator)",
            BackendType::John      => "John the Ripper (Multi-Core SIMD)",
            BackendType::Fcrackzip => "fcrackzip (Optimized ZIP Cracker)",
            BackendType::Native    => "Native Engine (In-Process AVX2)",
            BackendType::None      => "Unsupported Format",
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

#[derive(Debug, Clone)]
pub struct BackendRecommendation {
    pub suggested: BackendType,
    pub reason:    &'static str,
}
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

    /// Auto-suggest the optimal decryption engine and explain why based on file format.
    pub fn suggest_backend(
        &self,
        target_path: &Path,
        cipher_suite: &str,
        has_native_cracker: bool,
    ) -> BackendRecommendation {
        let ext = target_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();
        let c = cipher_suite.to_lowercase();

        // 1. Raw Hashes (MD5, NTLM, SHA-1, SHA-256)
        if ext == "hash" || ext == "txt" || c.contains("md5") || c.contains("ntlm") || c.contains("sha") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: "GPU acceleration kernel delivers fastest candidate throughput",
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "Multi-core CPU SIMD vectorization",
                };
            } else if has_native_cracker {
                return BackendRecommendation {
                    suggested: BackendType::Native,
                    reason: "Built-in AVX2 8-way SIMD hash evaluator",
                };
            }
        }

        // 2. ZIP Archives (WinZip AES or ZipCrypto)
        if ext == "zip" || c.contains("zip") {
            if c.contains("winzip") || c.contains("aes") {
                if self.hashcat.is_some() {
                    return BackendRecommendation {
                        suggested: BackendType::Hashcat,
                        reason: "Hashcat Mode 13600 (WinZip AES-256) GPU OpenCL kernel",
                    };
                } else if self.john.is_some() {
                    return BackendRecommendation {
                        suggested: BackendType::John,
                        reason: "John the Ripper WinZip Jumbo engine",
                    };
                } else if has_native_cracker {
                    return BackendRecommendation {
                        suggested: BackendType::Native,
                        reason: "Built-in PBKDF2-HMAC-SHA1 WinZip AES cracker",
                    };
                }
            } else {
                if self.fcrackzip.is_some() {
                    return BackendRecommendation {
                        suggested: BackendType::Fcrackzip,
                        reason: "fcrackzip dedicated lightweight ZIP engine",
                    };
                } else if self.hashcat.is_some() {
                    return BackendRecommendation {
                        suggested: BackendType::Hashcat,
                        reason: "Hashcat Mode 17200 (ZipCrypto CRC32)",
                    };
                } else if self.john.is_some() {
                    return BackendRecommendation {
                        suggested: BackendType::John,
                        reason: "John the Ripper PKZIP Jumbo engine",
                    };
                } else if has_native_cracker {
                    return BackendRecommendation {
                        suggested: BackendType::Native,
                        reason: "Built-in CRC32 ZipCrypto multi-threaded solver",
                    };
                }
            }
        }

        // 3. 7-Zip Archives (.7z)
        if ext == "7z" || c.contains("7z") || c.contains("7-zip") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: "Hashcat Mode 11600 (7-Zip) GPU AES-CBC engine",
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "John 7z Jumbo recovery engine",
                };
            } else if has_native_cracker {
                return BackendRecommendation {
                    suggested: BackendType::Native,
                    reason: "Built-in SHA256 AES-CBC 7z verification engine",
                };
            }
        }

        // 4. RAR Archives (.rar)
        if ext == "rar" || c.contains("rar") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: if c.contains("rar5") { "Hashcat Mode 13000 (RAR5 PBKDF2-SHA256)" } else { "Hashcat Mode 12500 (RAR3-hp)" },
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "John the Ripper RAR Jumbo format parser",
                };
            } else if has_native_cracker {
                return BackendRecommendation {
                    suggested: BackendType::Native,
                    reason: "Built-in RAR5 PBKDF2 verification engine",
                };
            }
        }

        // 5. PDF Documents (.pdf)
        if ext == "pdf" || c.contains("pdf") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: "Hashcat Mode 10500/10600 (PDF Acrobat security handler)",
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "John PDF Jumbo engine",
                };
            } else if has_native_cracker {
                return BackendRecommendation {
                    suggested: BackendType::Native,
                    reason: "Built-in PDF encryption dictionary verifier",
                };
            }
        }

        // 6. Wi-Fi Captures (.pcap, .22000, .hccapx)
        if ext == "22000" || ext == "hccapx" || ext == "pcap" || ext == "pcapng" || c.contains("wpa") || c.contains("pmkid") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: "Hashcat Mode 22000 (WPA-PBKDF2-PMKID+EAPOL)",
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "John wpapsk recovery format",
                };
            }
        }

        // 7. KeePass (.kdbx)
        if ext == "kdbx" || c.contains("keepass") {
            if self.hashcat.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::Hashcat,
                    reason: "Hashcat Mode 13400 (KeePass 1/2 AES-KDF)",
                };
            } else if self.john.is_some() {
                return BackendRecommendation {
                    suggested: BackendType::John,
                    reason: "John KeePass Jumbo engine",
                };
            } else if has_native_cracker {
                return BackendRecommendation {
                    suggested: BackendType::Native,
                    reason: "Built-in KeePass AES-KDF solver",
                };
            }
        }

        // Default fallback
        if self.hashcat.is_some() && self.can_hashcat(target_path, cipher_suite) {
            BackendRecommendation {
                suggested: BackendType::Hashcat,
                reason: "GPU/OpenCL acceleration preferred",
            }
        } else if self.john.is_some() && self.can_john(target_path, cipher_suite) {
            BackendRecommendation {
                suggested: BackendType::John,
                reason: "Multi-core CPU SIMD engine",
            }
        } else if has_native_cracker {
            BackendRecommendation {
                suggested: BackendType::Native,
                reason: "In-process pure-Rust AVX2 engine",
            }
        } else {
            BackendRecommendation {
                suggested: BackendType::None,
                reason: "Requires external tool (install hashcat or john)",
            }
        }
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
            tools.push(format!("Hashcat ({})", p.display()));
        }
        if let Some(p) = &self.john {
            tools.push(format!("John ({})", p.display()));
        }
        if let Some(p) = &self.fcrackzip {
            tools.push(format!("fcrackzip ({})", p.display()));
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

/// Return the John the Ripper `--format=<fmt>` string for a given cipher description.
pub fn john_format_for(cipher_desc: &str) -> Option<&'static str> {
    let d = cipher_desc.to_ascii_lowercase();
    if d.contains("zipcrypto") || d.contains("pkware") {
        Some("PKZIP")
    } else if d.contains("winzip") || (d.contains("aes") && d.contains("zip")) {
        Some("zip")
    } else if d.contains("pdf") {
        Some("pdf")
    } else if d.contains("7z") || d.contains("7-zip") {
        Some("7z")
    } else if d.contains("rar5") {
        Some("rar5")
    } else if d.contains("rar") {
        Some("rar")
    } else if d.contains("keepass") || d.contains("kdbx") {
        Some("keepass")
    } else if d.contains("ntlm") || d.contains("sam") {
        Some("NT")
    } else if d.contains("md5") && !d.contains("hmac") && !d.contains("pbkdf") {
        Some("raw-md5")
    } else if d.contains("sha-1") && !d.contains("pbkdf") && !d.contains("hmac") {
        Some("raw-sha1")
    } else if d.contains("sha-256") && !d.contains("pbkdf") && !d.contains("hmac") {
        Some("raw-sha256")
    } else if d.contains("wpa") || d.contains("pmkid") || d.contains("eapol") {
        Some("wpapsk")
    } else {
        None
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
            #[cfg(target_os = "windows")]
            {
                let candidate_exe = dir.join(format!("{}.exe", name));
                if is_executable(&candidate_exe) {
                    return Some(candidate_exe);
                }
            }
        }
    }

    // 2. Windows-specific well-known paths (WinGet, Chocolatey, Scoop, standard roots)
    #[cfg(target_os = "windows")]
    {
        let mut win_dirs: Vec<PathBuf> = Vec::new();
        if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
            let lad = PathBuf::from(localappdata);
            win_dirs.push(lad.join("Microsoft\\WinGet\\Links"));
            win_dirs.push(lad.join("Programs\\torcrypt\\bin"));
            win_dirs.push(lad.join(format!("Programs\\{}", name)));
            win_dirs.push(lad.join(name));
        }
        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            let up = PathBuf::from(userprofile);
            win_dirs.push(up.join("scoop\\shims"));
            win_dirs.push(up.join(format!("scoop\\apps\\{}\\current", name)));
            win_dirs.push(up.join(format!("scoop\\apps\\{}\\current\\run", name)));
            win_dirs.push(up.join(name));
            win_dirs.push(up.join(format!("{}\\run", name)));
        }
        if let Ok(programdata) = std::env::var("ProgramData") {
            let pd = PathBuf::from(programdata);
            win_dirs.push(pd.join("chocolatey\\bin"));
        }
        win_dirs.push(PathBuf::from(format!("C:\\tools\\{}", name)));
        win_dirs.push(PathBuf::from(format!("C:\\tools\\{}\\run", name)));
        win_dirs.push(PathBuf::from(format!("C:\\{}", name)));
        win_dirs.push(PathBuf::from(format!("C:\\{}\\run", name)));
        win_dirs.push(PathBuf::from(format!("C:\\Program Files\\{}", name)));
        win_dirs.push(PathBuf::from(format!("C:\\Program Files\\{}\\run", name)));
        win_dirs.push(PathBuf::from(format!("C:\\Program Files (x86)\\{}", name)));

        for dir in &win_dirs {
            let cand = dir.join(name);
            if is_executable(&cand) {
                return Some(cand);
            }
            let cand_exe = dir.join(format!("{}.exe", name));
            if is_executable(&cand_exe) {
                return Some(cand_exe);
            }
        }
    }

    // 3. Common non-PATH Unix locations
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

    #[test]
    fn test_suggest_backend() {
        let catalog = BackendCatalog::probe();

        // 1. Raw MD5 hash suggestion
        let rec_md5 = catalog.suggest_backend(Path::new("test.hash"), "MD5 Digest", true);
        assert!(!rec_md5.reason.is_empty());
        if catalog.has_hashcat() {
            assert_eq!(rec_md5.suggested, BackendType::Hashcat);
            assert!(rec_md5.reason.contains("GPU"));
        }

        // 2. WinZip AES suggestion
        let rec_winzip = catalog.suggest_backend(Path::new("archive.zip"), "WinZip AES-256", true);
        assert!(!rec_winzip.reason.is_empty());
        if catalog.has_hashcat() {
            assert_eq!(rec_winzip.suggested, BackendType::Hashcat);
            assert!(rec_winzip.reason.contains("13600"));
        }

        // 3. RAR5 suggestion
        let rec_rar = catalog.suggest_backend(Path::new("archive.rar"), "RAR5 Archive", true);
        assert!(!rec_rar.reason.is_empty());
    }
}
