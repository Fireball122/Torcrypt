// src/engine/feasibility.rs — Pre-Flight Attack Feasibility & Cryptographic Work-Factor Engine
// Computes mathematical keyspace work-factors, hardware throughput models, and practical exhaustion timeframes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeasibilityTier {
    Trivial,     // < 5 seconds
    Practical,   // < 2 hours
    Feasible,    // < 7 days
    Impractical, // 7 days to 1 year
    Infeasible,  // > 1 year (Cryptographically Secure)
}

impl FeasibilityTier {
    pub fn display_badge(&self) -> (&'static str, &'static str) {
        match self {
            FeasibilityTier::Trivial     => ("⚡ TRIVIAL (<5s)", "Instant exhaustive search"),
            FeasibilityTier::Practical   => ("✔ PRACTICAL (<2h)", "Realistic candidate recovery window"),
            FeasibilityTier::Feasible    => ("⏱ FEASIBLE (<7d)", "Feasible with continuous compute allocation"),
            FeasibilityTier::Impractical => ("⚠️ IMPRACTICAL (>7d)", "Warning: High compute expenditure; recommend dictionary/rules"),
            FeasibilityTier::Infeasible  => ("🔒 INFEASIBLE (>1y)", "Cryptographically secure parameter; brute-force will fail"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FeasibilityReport {
    pub keyspace_size:       u64,
    pub benchmark_speed_hps: f64,
    pub estimated_seconds:   f64,
    pub human_duration:      String,
    pub tier:                FeasibilityTier,
    pub advice:              &'static str,
}

pub fn estimate_feasibility(keyspace: u64, cipher_desc: &str, is_gpu: bool) -> FeasibilityReport {
    let lower = cipher_desc.to_lowercase();

    // Hardware speed model (candidates/sec)
    let speed_hps = if lower.contains("argon2") {
        if is_gpu { 120.0 } else { 180.0 } // Memory-hard bottlenecked
    } else if lower.contains("bcrypt") {
        if is_gpu { 4_500.0 } else { 350.0 }
    } else if lower.contains("7-zip") || lower.contains("524k") {
        if is_gpu { 8_500.0 } else { 8.0 } // 2^19 SHA-256 rounds
    } else if lower.contains("rar5") || lower.contains("32,768") {
        if is_gpu { 65_000.0 } else { 50.0 } // 32,768 PBKDF2-SHA256 rounds
    } else if lower.contains("keepass") || lower.contains("kdbx") || lower.contains("aes-kdf") {
        if is_gpu { 150_000.0 } else { 600.0 } // AES-KDF 6000 rounds
    } else if lower.contains("wpa2") || lower.contains("handshake") {
        if is_gpu { 520_000.0 } else { 400.0 } // 4,096 PBKDF2-SHA1 rounds
    } else if lower.contains("winzip") && lower.contains("aes") {
        if is_gpu { 850_000.0 } else { 1_200.0 } // 1,000 PBKDF2-SHA1 rounds
    } else if lower.contains("pdf") {
        if is_gpu { 1_200_000.0 } else { 120_000.0 }
    } else if lower.contains("zipcrypto") {
        if is_gpu { 2_500_000_000.0 } else { 800_000.0 }
    } else if lower.contains("ntlm") || lower.contains("md5") {
        if is_gpu { 15_000_000_000.0 } else { 3_000_000.0 } // AVX2 8-way SIMD
    } else if lower.contains("sha-256") || lower.contains("sha256") {
        if is_gpu { 3_500_000_000.0 } else { 450_000.0 }
    } else if lower.contains("sha-1") || lower.contains("sha1") {
        if is_gpu { 8_000_000_000.0 } else { 800_000.0 }
    } else {
        if is_gpu { 250_000.0 } else { 1_000.0 }
    };

    let est_secs = if keyspace == 0 || speed_hps <= 0.0 {
        0.0
    } else {
        keyspace as f64 / speed_hps
    };

    let (tier, human_duration, advice) = if est_secs <= 5.0 {
        (
            FeasibilityTier::Trivial,
            format!("{:.1}s", est_secs.max(0.01)),
            "Keyspace is trivially small; immediate resolution expected.",
        )
    } else if est_secs <= 7_200.0 {
        (
            FeasibilityTier::Practical,
            fmt_human_time(est_secs),
            "Optimal attack target; candidate space is practically exhaustible.",
        )
    } else if est_secs <= 604_800.0 {
        (
            FeasibilityTier::Feasible,
            fmt_human_time(est_secs),
            "Compute-feasible within a multi-day dedicated workload window.",
        )
    } else if est_secs <= 31_536_000.0 {
        (
            FeasibilityTier::Impractical,
            fmt_human_time(est_secs),
            "Exhaustive search is impractical; pivot to targeted dictionary + mutation rules.",
        )
    } else {
        (
            FeasibilityTier::Infeasible,
            fmt_human_time(est_secs),
            "Cryptographically secure work factor; full brute-force is computationally impossible.",
        )
    };

    FeasibilityReport {
        keyspace_size: keyspace,
        benchmark_speed_hps: speed_hps,
        estimated_seconds: est_secs,
        human_duration,
        tier,
        advice,
    }
}

fn fmt_human_time(secs: f64) -> String {
    let s = secs as u64;
    if s < 60 {
        format!("{}s", s)
    } else if s < 3600 {
        format!("{}m {}s", s / 60, s % 60)
    } else if s < 86400 {
        format!("{:.1} hours", secs / 3600.0)
    } else if s < 31_536_000 {
        format!("{:.1} days", secs / 86400.0)
    } else {
        let years = secs / 31_536_000.0;
        if years > 1_000_000.0 {
            "> 1 Million years".into()
        } else if years > 1_000.0 {
            format!("{:.0}k years", years / 1000.0)
        } else {
            format!("{:.1} years", years)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feasibility_estimation() {
        // Small keyspace on MD5 -> Trivial
        let r1 = estimate_feasibility(10_000, "MD5", true);
        assert_eq!(r1.tier, FeasibilityTier::Trivial);

        // Moderate keyspace on WPA2 -> Practical (< 2 hours)
        let r2 = estimate_feasibility(14_344_392, "WPA2", true);
        assert!(r2.tier == FeasibilityTier::Trivial || r2.tier == FeasibilityTier::Practical);

        // Huge keyspace on Argon2id -> Infeasible
        let r3 = estimate_feasibility(10_000_000_000, "Argon2id", true);
        assert_eq!(r3.tier, FeasibilityTier::Infeasible);
        assert!(r3.human_duration.contains("years"));
    }
}
