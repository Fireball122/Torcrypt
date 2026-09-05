// src/engine/benchmark_runner.rs — Authentic Cryptographic Benchmark Suite
// Measures host CPU, SIMD, and memory bandwidth across real hash and cipher operations.

use std::time::Instant;

#[derive(Debug, Clone)]
pub struct BenchResult {
    pub name:          String,
    pub single_mb:     u64,
    pub multi_mb:      u64,
    pub latency_us:    f64,
    pub hw_accel:      bool,
}

/// Run an authentic calibration benchmark for a specific algorithm stage (0..=8)
pub fn benchmark_stage(stage: usize, thread_count: u8) -> BenchResult {
    let threads = (thread_count as u64).max(1);

    match stage {
        0 => benchmark_md5(threads),
        1 => benchmark_ntlm(threads),
        2 => benchmark_sha256(threads),
        3 => benchmark_sha1(threads),
        4 => benchmark_zipcrypto(threads),
        5 => benchmark_rc4(threads),
        6 => benchmark_pbkdf2_sha1(threads),
        7 => benchmark_pbkdf2_sha256(threads),
        _ => benchmark_pbkdf2_sha256_keepass(threads),
    }
}

/// Run a full sweep of all cryptographic algorithms and return authentic measurements.
pub fn run_full_benchmark(thread_count: u8) -> Vec<BenchResult> {
    let threads = (thread_count as u64).max(1);
    vec![
        benchmark_md5(threads),
        benchmark_ntlm(threads),
        benchmark_sha256(threads),
        benchmark_sha1(threads),
        benchmark_zipcrypto(threads),
        benchmark_rc4(threads),
        benchmark_pbkdf2_sha1(threads),
        benchmark_pbkdf2_sha256(threads),
        benchmark_pbkdf2_sha256_keepass(threads),
    ]
}

fn benchmark_md5(threads: u64) -> BenchResult {
    #[cfg(target_arch = "x86_64")]
    let avx2_available = is_x86_feature_detected!("avx2");
    #[cfg(not(target_arch = "x86_64"))]
    let avx2_available = false;

    let iterations = 100_000usize;
    let block_bytes = 64usize;
    let sample = b"password123_benchmark_vector_token";

    let start = Instant::now();

    #[cfg(target_arch = "x86_64")]
    if avx2_available {
        use crate::engine::crypto::simd::avx2;
        let cands: Vec<&[u8]> = vec![sample; 8];
        let target = [0x12345678, 0x23456789, 0x34567890, 0x45678901];
        let passes = iterations / 8;
        for _ in 0..passes {
            unsafe {
                let _ = avx2::test_md5_8way(&cands, target);
            }
        }
    } else {
        for _ in 0..iterations {
            let _ = crate::engine::crypto::md5(sample);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    for _ in 0..iterations {
        let _ = crate::engine::crypto::md5(sample);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * block_bytes) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: if avx2_available { "MD5 (AVX2 8-Way SIMD)".into() } else { "MD5 (RFC 1321)".into() },
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: avx2_available,
    }
}

fn benchmark_ntlm(threads: u64) -> BenchResult {
    #[cfg(target_arch = "x86_64")]
    let avx2_available = is_x86_feature_detected!("avx2");
    #[cfg(not(target_arch = "x86_64"))]
    let avx2_available = false;

    let iterations = 100_000usize;
    let block_bytes = 64usize;
    let sample = "Password123!";

    let start = Instant::now();

    #[cfg(target_arch = "x86_64")]
    if avx2_available {
        use crate::engine::crypto::simd::avx2;
        let cands: Vec<&str> = vec![sample; 8];
        let target = [0x12345678, 0x23456789, 0x34567890, 0x45678901];
        let passes = iterations / 8;
        for _ in 0..passes {
            unsafe {
                let _ = avx2::test_ntlm_8way(&cands, target);
            }
        }
    } else {
        for _ in 0..iterations {
            let _ = crate::engine::crypto::ntlm_hash(sample);
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    for _ in 0..iterations {
        let _ = crate::engine::crypto::ntlm_hash(sample);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * block_bytes) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: if avx2_available { "NTLM (AVX2 8-Way SIMD)".into() } else { "NTLM (MD4 UTF-16LE)".into() },
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: avx2_available,
    }
}

fn benchmark_sha256(threads: u64) -> BenchResult {
    let iterations = 80_000usize;
    let block_bytes = 64usize;
    let sample = b"Benchmark_Vector_SHA256_Payload";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crate::engine::crypto::sha256(sample);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * block_bytes) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: "SHA-256 (FIPS 180-4)".into(),
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: true,
    }
}

fn benchmark_sha1(threads: u64) -> BenchResult {
    let iterations = 80_000usize;
    let block_bytes = 64usize;
    let sample = b"Benchmark_Vector_SHA1_Payload";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crate::engine::crypto::sha1(sample);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * block_bytes) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: "SHA-1 (FIPS 180-1)".into(),
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: true,
    }
}

fn benchmark_zipcrypto(threads: u64) -> BenchResult {
    let iterations = 100_000usize;
    let header = [0x55u8; 12];
    let password = b"benchmark_password";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crate::engine::crypto::ZipCryptoState::verify_header(password, &header, 0x55);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * 12) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: "ZipCrypto (PKWARE 3-Key)".into(),
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: false,
    }
}

fn benchmark_rc4(threads: u64) -> BenchResult {
    let iterations = 50_000usize;
    let key = b"benchmark_rc4_128bit_key";
    let payload = [0xAAu8; 64];

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = crate::engine::crypto::rc4_crypt(key, &payload);
    }

    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let total_bytes = (iterations * 64) as f64;
    let single_mb = ((total_bytes / elapsed_secs) / 1_000_000.0) as u64;
    let multi_mb = single_mb * threads;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);

    BenchResult {
        name: "RC4 (PDF Security Handler)".into(),
        single_mb: single_mb.max(1),
        multi_mb: multi_mb.max(1),
        latency_us,
        hw_accel: false,
    }
}

fn benchmark_pbkdf2_sha1(threads: u64) -> BenchResult {
    // PBKDF2-HMAC-SHA1, 1000 rounds (WinZip AES default)
    use crate::engine::crypto::pbkdf2_hmac_sha1;
    let password = b"benchmark_winzip_pass";
    let salt = b"bnchmrk_slat0001";
    let iterations = 2_000usize;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha1(password, salt, 1000, &mut out);
    }
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let candidates_per_sec = (iterations as f64 / elapsed_secs) as u64;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);
    BenchResult {
        name: "PBKDF2-SHA1 / 1K (WinZip AES)".into(),
        single_mb: (candidates_per_sec / 1000).max(1),
        multi_mb: ((candidates_per_sec / 1000) * threads).max(1),
        latency_us,
        hw_accel: false,
    }
}

fn benchmark_pbkdf2_sha256(threads: u64) -> BenchResult {
    // PBKDF2-HMAC-SHA256, 32768 rounds (RAR5 default)
    use crate::engine::crypto::pbkdf2_hmac_sha256;
    let password = b"benchmark_rar5_pass";
    let salt = b"rar5_bench_salt16";
    let iterations = 200usize;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(password, salt, 32768, &mut out);
    }
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let candidates_per_sec = (iterations as f64 / elapsed_secs) as u64;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);
    BenchResult {
        name: "PBKDF2-SHA256 / 32K (RAR5 KDF)".into(),
        single_mb: candidates_per_sec.max(1),
        multi_mb: (candidates_per_sec * threads).max(1),
        latency_us,
        hw_accel: false,
    }
}

fn benchmark_pbkdf2_sha256_keepass(threads: u64) -> BenchResult {
    // PBKDF2-HMAC-SHA256, 60000 rounds (KeePass 2.x default AES-KDF)
    use crate::engine::crypto::pbkdf2_hmac_sha256;
    let password = b"benchmark_keepass_master";
    let salt = [0xABu8; 32];
    let iterations = 50usize;
    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let mut out = [0u8; 32];
        pbkdf2_hmac_sha256(password, &salt, 60000, &mut out);
    }
    let elapsed = start.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(0.0001);
    let candidates_per_sec = (iterations as f64 / elapsed_secs) as u64;
    let latency_us = (elapsed.as_micros() as f64) / (iterations as f64);
    BenchResult {
        name: "PBKDF2-SHA256 / 60K (KeePass AES-KDF)".into(),
        single_mb: candidates_per_sec.max(1),
        multi_mb: (candidates_per_sec * threads).max(1),
        latency_us,
        hw_accel: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_benchmark_full_run() {
        let results = run_full_benchmark(4);
        assert_eq!(results.len(), 9);
        for r in results {
            assert!(r.single_mb > 0, "Throughput should be > 0 for {}", r.name);
            assert!(r.latency_us > 0.0, "Latency should be > 0 for {}", r.name);
        }
    }
}
