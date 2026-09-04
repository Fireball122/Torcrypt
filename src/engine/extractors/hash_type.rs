// src/engine/extractors/hash_type.rs — Cryptographic Hash Format Classifier
// Distinguishes raw digests, modular crypt formats, and ticket hashes by structure, length, and charset.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashCategory {
    RawDigest {
        algorithm: &'static str,
        bit_length: usize,
        candidates: &'static [&'static str],
    },
    ModularCrypt {
        algorithm:   &'static str,
        variant:     String,
        cost_or_iter: Option<u32>,
    },
    NetworkTicket {
        protocol:  &'static str,
        etype:     &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct HashClassification {
    pub is_hash:      bool,
    pub category:     HashCategory,
    pub display_name: String,
    pub recommended_engine_desc: &'static str,
    pub hashcat_mode: Option<u32>,
}

impl HashClassification {
    pub fn classify(input: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(input).ok()?.trim();
        if text.is_empty() {
            return None;
        }

        // 1. Modular Crypt Format & KDFs
        if text.starts_with("$2a$") || text.starts_with("$2b$") || text.starts_with("$2y$") {
            let cost = text.get(4..6).and_then(|c| c.parse::<u32>().ok());
            let variant = text.get(1..3).unwrap_or("2b").to_string();
            let cost_str = cost.map(|c| format!("Cost {}", c)).unwrap_or_else(|| "Cost 12".into());
            return Some(Self {
                is_hash: true,
                category: HashCategory::ModularCrypt {
                    algorithm: "Bcrypt",
                    variant,
                    cost_or_iter: cost,
                },
                display_name: format!("Bcrypt ($2b$ Blowfish KDF, {})", cost_str),
                recommended_engine_desc: "Hybrid CPU+GPU (Memory Hard / High Compute)",
                hashcat_mode: Some(3200),
            });
        }

        if text.starts_with("$argon2id$") || text.starts_with("$argon2i$") || text.starts_with("$argon2d$") {
            let variant = if text.starts_with("$argon2id$") {
                "Argon2id (Hybrid Data-Independent + Dependent)"
            } else if text.starts_with("$argon2i$") {
                "Argon2i (Data-Independent)"
            } else {
                "Argon2d (Data-Dependent)"
            };
            return Some(Self {
                is_hash: true,
                category: HashCategory::ModularCrypt {
                    algorithm: "Argon2",
                    variant: variant.into(),
                    cost_or_iter: None,
                },
                display_name: format!("Argon2 Password Hash ({})", variant),
                recommended_engine_desc: "Hybrid Multi-Core CPU (AVX2/AVX-512) + High-VRAM GPU",
                hashcat_mode: Some(13900),
            });
        }

        if text.starts_with("$6$") {
            return Some(Self {
                is_hash: true,
                category: HashCategory::ModularCrypt {
                    algorithm: "SHA-512 Crypt",
                    variant: "Unix $6$".into(),
                    cost_or_iter: Some(5000),
                },
                display_name: "Unix SHA-512 Crypt ($6$, 5000 rounds default)".into(),
                recommended_engine_desc: "GPU Stream Compute (SHA512 Rounds)",
                hashcat_mode: Some(1800),
            });
        }

        if text.starts_with("$5$") {
            return Some(Self {
                is_hash: true,
                category: HashCategory::ModularCrypt {
                    algorithm: "SHA-256 Crypt",
                    variant: "Unix $5$".into(),
                    cost_or_iter: Some(5000),
                },
                display_name: "Unix SHA-256 Crypt ($5$, 5000 rounds default)".into(),
                recommended_engine_desc: "GPU Stream Compute (SHA256 Rounds)",
                hashcat_mode: Some(7400),
            });
        }

        if text.starts_with("$1$") {
            return Some(Self {
                is_hash: true,
                category: HashCategory::ModularCrypt {
                    algorithm: "MD5 Crypt",
                    variant: "Unix $1$".into(),
                    cost_or_iter: Some(1000),
                },
                display_name: "Unix MD5-Crypt ($1$, 1000 rounds)".into(),
                recommended_engine_desc: "GPU Warp Offload (MD5 Crypt)",
                hashcat_mode: Some(500),
            });
        }

        // 2. Kerberos Network Tickets
        if text.starts_with("$krb5tgs$") {
            return Some(Self {
                is_hash: true,
                category: HashCategory::NetworkTicket {
                    protocol: "Kerberos 5 TGS",
                    etype: "etype 23 (RC4-HMAC)",
                },
                display_name: "Kerberos 5 TGS-REP Ticket (Kerberoasting, etype 23)".into(),
                recommended_engine_desc: "High-Speed GPU Warp Brute-Force / Rule Offload",
                hashcat_mode: Some(13100),
            });
        }

        if text.starts_with("$krb5asrep$") {
            return Some(Self {
                is_hash: true,
                category: HashCategory::NetworkTicket {
                    protocol: "Kerberos 5 AS-REP",
                    etype: "etype 23 (RC4-HMAC)",
                },
                display_name: "Kerberos 5 AS-REP Ticket (ASREPRoasting, etype 23)".into(),
                recommended_engine_desc: "High-Speed GPU Warp Brute-Force / Rule Offload",
                hashcat_mode: Some(18200),
            });
        }

        // 3. Raw Hex Digests
        let is_hex = text.chars().all(|c| c.is_ascii_hexdigit());
        if is_hex {
            match text.len() {
                32 => Some(Self {
                    is_hash: true,
                    category: HashCategory::RawDigest {
                        algorithm: "MD5 / NTLM",
                        bit_length: 128,
                        candidates: &["NTLM (Windows SAM)", "MD5 (RFC 1321)", "MD4 (RFC 1320)"],
                    },
                    display_name: "Raw 128-bit Hex Digest (NTLM / MD5 / MD4)".into(),
                    recommended_engine_desc: "Ultra-Fast GPU Warp Offload (>10 GH/s on Modern GPUs)",
                    hashcat_mode: Some(1000), // NTLM default (or 0 for MD5)
                }),
                40 => Some(Self {
                    is_hash: true,
                    category: HashCategory::RawDigest {
                        algorithm: "SHA-1 / RIPEMD-160",
                        bit_length: 160,
                        candidates: &["SHA-1", "RIPEMD-160"],
                    },
                    display_name: "Raw 160-bit Hex Digest (SHA-1 / RIPEMD-160)".into(),
                    recommended_engine_desc: "High-Speed GPU Warp Pipeline",
                    hashcat_mode: Some(100),
                }),
                64 => Some(Self {
                    is_hash: true,
                    category: HashCategory::RawDigest {
                        algorithm: "SHA-256 / SM3",
                        bit_length: 256,
                        candidates: &["SHA-256 (FIPS 180-4)", "SM3 (OSCCA)", "BLAKE2s-256"],
                    },
                    display_name: "Raw 256-bit Hex Digest (SHA-256 / SM3)".into(),
                    recommended_engine_desc: "GPU Stream Compute (SHA-256 Pipeline)",
                    hashcat_mode: Some(1400),
                }),
                128 => Some(Self {
                    is_hash: true,
                    category: HashCategory::RawDigest {
                        algorithm: "SHA-512 / Whirlpool",
                        bit_length: 512,
                        candidates: &["SHA-512 (FIPS 180-4)", "Whirlpool", "BLAKE2b-512"],
                    },
                    display_name: "Raw 512-bit Hex Digest (SHA-512 / Whirlpool)".into(),
                    recommended_engine_desc: "GPU 64-bit Word Vectorized Stream",
                    hashcat_mode: Some(1700),
                }),
                _ => None,
            }
        } else {
            None
        }
    }
}
