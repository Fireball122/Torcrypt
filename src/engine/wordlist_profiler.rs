// src/engine/wordlist_profiler.rs — Wordlist & Dictionary Hygiene / Quality Profiler
// Analyzes wordlists for total candidates, length distributions, character entropy, and NIST policy compliance.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct WordlistProfile {
    pub is_wordlist:        bool,
    pub total_candidates:   usize,
    pub min_len:            usize,
    pub max_len:            usize,
    pub avg_len:            f64,
    pub entropy:            f64,
    pub numeric_pct:        f64,
    pub nist_compliant_pct: f64,
    pub summary:            String,
}

impl WordlistProfile {
    pub fn inspect(path: &Path) -> Option<Self> {
        let file = File::open(path).ok()?;
        let file_len = file.metadata().ok()?.len();
        if file_len == 0 || file_len > 2 * 1024 * 1024 * 1024 {
            return None; // Skip empty or > 2GB files for quick inspection
        }

        let reader = BufReader::new(file);
        let mut count = 0usize;
        let mut min_len = usize::MAX;
        let mut max_len = 0usize;
        let mut total_chars = 0usize;

        let mut numeric_count = 0usize;
        let mut nist_compliant = 0usize;

        let mut char_counts = [0usize; 256];
        let mut total_sampled_bytes = 0usize;

        const MAX_SAMPLE_LINES: usize = 50_000;
        let mut hit_sample_limit = false;
        let mut sampled_raw_bytes = 0usize;

        for line_res in reader.lines() {
            let line = match line_res {
                Ok(l) => l,
                Err(_) => continue,
            };

            sampled_raw_bytes += line.len() + 1;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            count += 1;
            let len = trimmed.chars().count();
            min_len = min_len.min(len);
            max_len = max_len.max(len);
            total_chars += len;

            if trimmed.chars().all(|c| c.is_ascii_digit()) {
                numeric_count += 1;
            }

            // NIST SP 800-63B recommends minimum 8 characters and not purely trivial
            if len >= 8 && !trimmed.chars().all(|c| c.is_ascii_digit()) {
                nist_compliant += 1;
            }

            // Sample character frequencies for entropy across first 20,000 lines
            if count <= 20_000 {
                for b in trimmed.bytes() {
                    char_counts[b as usize] += 1;
                    total_sampled_bytes += 1;
                }
            }

            if count >= MAX_SAMPLE_LINES {
                hit_sample_limit = true;
                break;
            }
        }
        if count == 0 {
            return None;
        }

        let avg_len = total_chars as f64 / count as f64;
        let numeric_pct = (numeric_count as f64 / count as f64) * 100.0;
        let nist_compliant_pct = (nist_compliant as f64 / count as f64) * 100.0;

        // Shannon entropy across sampled character bytes
        let mut entropy = 0.0;
        if total_sampled_bytes > 0 {
            for &c in &char_counts {
                if c > 0 {
                    let p = c as f64 / total_sampled_bytes as f64;
                    entropy -= p * p.log2();
                }
            }
        }

        let estimated_total = if hit_sample_limit && sampled_raw_bytes > 0 {
            let avg_line_bytes = (sampled_raw_bytes as f64 / count as f64).max(1.0);
            ((file_len as f64 / avg_line_bytes) as usize).max(count)
        } else {
            count
        };

        let summary = if hit_sample_limit {
            format!(
                "Wordlist: ~{} candidates (sampled {}) │ Length: {}-{} (avg {:.1}) │ NIST: {:.1}%",
                fmt_num(estimated_total as u64), fmt_num(count as u64), min_len, max_len, avg_len, nist_compliant_pct
            )
        } else {
            format!(
                "Wordlist: {} candidates │ Length: {}-{} (avg {:.1}) │ NIST Compliance: {:.1}%",
                fmt_num(count as u64), min_len, max_len, avg_len, nist_compliant_pct
            )
        };

        Some(WordlistProfile {
            is_wordlist: true,
            total_candidates: estimated_total,
            min_len,
            max_len,
            avg_len,
            entropy,
            numeric_pct,
            nist_compliant_pct,
            summary,
        })
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { out.push(','); }
        out.push(c);
    }
    out.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_wordlist_profiler() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("torcrypt_test_wordlist.txt");

        let mut f = File::create(&test_path).unwrap();
        writeln!(f, "password").unwrap(); // len 8, compliant
        writeln!(f, "123456").unwrap(); // len 6, numeric
        writeln!(f, "admin123").unwrap(); // len 8, compliant
        writeln!(f, "P@ssword2026!").unwrap(); // len 13, compliant
        writeln!(f, "test").unwrap(); // len 4, non-compliant
        drop(f);

        let prof = WordlistProfile::inspect(&test_path).expect("Should profile wordlist");
        assert!(prof.is_wordlist);
        assert_eq!(prof.total_candidates, 5);
        assert_eq!(prof.min_len, 4);
        assert_eq!(prof.max_len, 13);
        assert_eq!(prof.numeric_pct, 20.0); // 1 out of 5
        assert_eq!(prof.nist_compliant_pct, 60.0); // 3 out of 5 (>=8 chars, non-numeric)
        assert!(prof.entropy > 0.0);

        let _ = std::fs::remove_file(test_path);
    }
}
