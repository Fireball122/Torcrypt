// src/engine/crypto/simd.rs — SIMD Vectorized Multi-Lane Cryptographic Hashing Kernels
// Executes 8-way parallel MD5 and NTLM candidate evaluation using x86_64 AVX2 intrinsics
// with zero memory allocations per hash, falling back to portable scalar loops on other platforms.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimdBackend {
    Avx2_8Way,
    PortableScalar,
}

pub fn active_simd_backend() -> SimdBackend {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return SimdBackend::Avx2_8Way;
        }
    }
    SimdBackend::PortableScalar
}

// ─── AVX2 8-Way Parallel MD5 & NTLM ────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
pub mod avx2 {
    use std::arch::x86_64::*;

    macro_rules! rotl {
        ($x:expr, $s:expr) => {
            _mm256_or_si256(
                _mm256_slli_epi32($x, $s),
                _mm256_srli_epi32($x, 32 - $s),
            )
        };
    }

    /// Tests up to 8 candidate passwords against a target MD5 digest (4 u32 words in little endian).
    /// Candidates must be <= 55 bytes so they fit into a single 64-byte MD5 block.
    /// Returns Some(index) if any lane matches target.
    #[target_feature(enable = "avx2")]
    pub unsafe fn test_md5_8way(
        candidates: &[&[u8]],
        target_words: [u32; 4],
    ) -> Option<usize> {
        let count = candidates.len().min(8);
        if count == 0 {
            return None;
        }

        let mut raw_words = [[0u32; 16]; 8];

        for lane in 0..count {
            let cand = candidates[lane];
            if cand.len() > 55 {
                return None;
            }

            let mut block = [0u8; 64];
            block[..cand.len()].copy_from_slice(cand);
            block[cand.len()] = 0x80;
            let bit_len = (cand.len() as u64) * 8;
            block[56..64].copy_from_slice(&bit_len.to_le_bytes());

            for w in 0..16 {
                raw_words[lane][w] = u32::from_le_bytes([
                    block[w * 4],
                    block[w * 4 + 1],
                    block[w * 4 + 2],
                    block[w * 4 + 3],
                ]);
            }
        }

        // Transpose raw_words into 16 __m256i registers
        let mut m = [_mm256_setzero_si256(); 16];
        for w in 0..16 {
            m[w] = _mm256_setr_epi32(
                raw_words[0][w] as i32,
                raw_words[1][w] as i32,
                raw_words[2][w] as i32,
                raw_words[3][w] as i32,
                raw_words[4][w] as i32,
                raw_words[5][w] as i32,
                raw_words[6][w] as i32,
                raw_words[7][w] as i32,
            );
        }

        let mut a = _mm256_set1_epi32(0x67452301u32 as i32);
        let mut b = _mm256_set1_epi32(0xefcdab89u32 as i32);
        let mut c = _mm256_set1_epi32(0x98badcfeu32 as i32);
        let mut d = _mm256_set1_epi32(0x10325476u32 as i32);

        let a0 = a;
        let b0 = b;
        let c0 = c;
        let d0 = d;

        macro_rules! step_f {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $m_idx:expr) => {
                let f = _mm256_or_si256(_mm256_and_si256($b, $c), _mm256_andnot_si256($b, $d));
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, f), _mm256_add_epi32(_mm256_set1_epi32($k as i32), m[$m_idx]));
                $a = _mm256_add_epi32($b, rotl!(sum, $s));
            };
        }

        macro_rules! step_g {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $m_idx:expr) => {
                let g = _mm256_or_si256(_mm256_and_si256($d, $b), _mm256_andnot_si256($d, $c));
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, g), _mm256_add_epi32(_mm256_set1_epi32($k as i32), m[$m_idx]));
                $a = _mm256_add_epi32($b, rotl!(sum, $s));
            };
        }

        macro_rules! step_h {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $m_idx:expr) => {
                let h = _mm256_xor_si256(_mm256_xor_si256($b, $c), $d);
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, h), _mm256_add_epi32(_mm256_set1_epi32($k as i32), m[$m_idx]));
                $a = _mm256_add_epi32($b, rotl!(sum, $s));
            };
        }

        macro_rules! step_i {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr, $m_idx:expr) => {
                let not_d = _mm256_xor_si256($d, _mm256_set1_epi32(-1));
                let i_fun = _mm256_xor_si256($c, _mm256_or_si256($b, not_d));
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, i_fun), _mm256_add_epi32(_mm256_set1_epi32($k as i32), m[$m_idx]));
                $a = _mm256_add_epi32($b, rotl!(sum, $s));
            };
        }

        // Round 1
        step_f!(a, b, c, d, 0xd76aa478u32, 7,  0);
        step_f!(d, a, b, c, 0xe8c7b756u32, 12, 1);
        step_f!(c, d, a, b, 0x242070dbu32, 17, 2);
        step_f!(b, c, d, a, 0xc1bdceeeu32, 22, 3);
        step_f!(a, b, c, d, 0xf57c0fafu32, 7,  4);
        step_f!(d, a, b, c, 0x4787c62au32, 12, 5);
        step_f!(c, d, a, b, 0xa8304613u32, 17, 6);
        step_f!(b, c, d, a, 0xfd469501u32, 22, 7);
        step_f!(a, b, c, d, 0x698098d8u32, 7,  8);
        step_f!(d, a, b, c, 0x8b44f7afu32, 12, 9);
        step_f!(c, d, a, b, 0xffff5bb1u32, 17, 10);
        step_f!(b, c, d, a, 0x895cd7beu32, 22, 11);
        step_f!(a, b, c, d, 0x6b901122u32, 7,  12);
        step_f!(d, a, b, c, 0xfd987193u32, 12, 13);
        step_f!(c, d, a, b, 0xa679438eu32, 17, 14);
        step_f!(b, c, d, a, 0x49b40821u32, 22, 15);

        // Round 2
        step_g!(a, b, c, d, 0xf61e2562u32, 5,  1);
        step_g!(d, a, b, c, 0xc040b340u32, 9,  6);
        step_g!(c, d, a, b, 0x265e5a51u32, 14, 11);
        step_g!(b, c, d, a, 0xe9b6c7aau32, 20, 0);
        step_g!(a, b, c, d, 0xd62f105du32, 5,  5);
        step_g!(d, a, b, c, 0x02441453u32, 9,  10);
        step_g!(c, d, a, b, 0xd8a1e681u32, 14, 15);
        step_g!(b, c, d, a, 0xe7d3fbc8u32, 20, 4);
        step_g!(a, b, c, d, 0x21e1cde6u32, 5,  9);
        step_g!(d, a, b, c, 0xc33707d6u32, 9,  14);
        step_g!(c, d, a, b, 0xf4d50d87u32, 14, 3);
        step_g!(b, c, d, a, 0x455a14edu32, 20, 8);
        step_g!(a, b, c, d, 0xa9e3e905u32, 5,  13);
        step_g!(d, a, b, c, 0xfcefa3f8u32, 9,  2);
        step_g!(c, d, a, b, 0x676f02d9u32, 14, 7);
        step_g!(b, c, d, a, 0x8d2a4c8au32, 20, 12);

        // Round 3
        step_h!(a, b, c, d, 0xfffa3942u32, 4,  5);
        step_h!(d, a, b, c, 0x8771f681u32, 11, 8);
        step_h!(c, d, a, b, 0x6d9d6122u32, 16, 11);
        step_h!(b, c, d, a, 0xfde5380cu32, 23, 14);
        step_h!(a, b, c, d, 0xa4beea44u32, 4,  1);
        step_h!(d, a, b, c, 0x4bdecfa9u32, 11, 4);
        step_h!(c, d, a, b, 0xf6bb4b60u32, 16, 7);
        step_h!(b, c, d, a, 0xbebfbc70u32, 23, 10);
        step_h!(a, b, c, d, 0x289b7ec6u32, 4,  13);
        step_h!(d, a, b, c, 0xeaa127fau32, 11, 0);
        step_h!(c, d, a, b, 0xd4ef3085u32, 16, 3);
        step_h!(b, c, d, a, 0x04881d05u32, 23, 6);
        step_h!(a, b, c, d, 0xd9d4d039u32, 4,  9);
        step_h!(d, a, b, c, 0xe6db99e5u32, 11, 12);
        step_h!(c, d, a, b, 0x1fa27cf8u32, 16, 15);
        step_h!(b, c, d, a, 0xc4ac5665u32, 23, 2);

        // Round 4
        step_i!(a, b, c, d, 0xf4292244u32, 6,  0);
        step_i!(d, a, b, c, 0x432aff97u32, 10, 7);
        step_i!(c, d, a, b, 0xab9423a7u32, 15, 14);
        step_i!(b, c, d, a, 0xfc93a039u32, 21, 5);
        step_i!(a, b, c, d, 0x655b59c3u32, 6,  12);
        step_i!(d, a, b, c, 0x8f0ccc92u32, 10, 3);
        step_i!(c, d, a, b, 0xffeff47du32, 15, 10);
        step_i!(b, c, d, a, 0x85845dd1u32, 21, 1);
        step_i!(a, b, c, d, 0x6fa87e4fu32, 6,  8);
        step_i!(d, a, b, c, 0xfe2ce6e0u32, 10, 15);
        step_i!(c, d, a, b, 0xa3014314u32, 15, 6);
        step_i!(b, c, d, a, 0x4e0811a1u32, 21, 13);
        step_i!(a, b, c, d, 0xf7537e82u32, 6,  4);
        step_i!(d, a, b, c, 0xbd3af235u32, 10, 11);
        step_i!(c, d, a, b, 0x2ad7d2bbu32, 15, 2);
        step_i!(b, c, d, a, 0xeb86d391u32, 21, 9);

        let final_a = _mm256_add_epi32(a0, a);
        let final_b = _mm256_add_epi32(b0, b);
        let final_c = _mm256_add_epi32(c0, c);
        let final_d = _mm256_add_epi32(d0, d);

        // Compare all 4 output state vectors against target words
        let t_a = _mm256_set1_epi32(target_words[0] as i32);
        let t_b = _mm256_set1_epi32(target_words[1] as i32);
        let t_c = _mm256_set1_epi32(target_words[2] as i32);
        let t_d = _mm256_set1_epi32(target_words[3] as i32);

        let eq_a = _mm256_cmpeq_epi32(final_a, t_a);
        let eq_b = _mm256_cmpeq_epi32(final_b, t_b);
        let eq_c = _mm256_cmpeq_epi32(final_c, t_c);
        let eq_d = _mm256_cmpeq_epi32(final_d, t_d);

        let match_vec = _mm256_and_si256(
            _mm256_and_si256(eq_a, eq_b),
            _mm256_and_si256(eq_c, eq_d),
        );

        let mask = _mm256_movemask_epi8(match_vec) as u32;
        if mask != 0 {
            for lane in 0..count {
                let lane_mask = 0xF << (lane * 4);
                if (mask & lane_mask) == lane_mask {
                    return Some(lane);
                }
            }
        }

        None
    }

    /// Tests up to 8 candidate passwords against an NTLM target digest (MD4 of UTF-16LE).
    /// Candidates must be <= 27 characters so UTF-16LE (<= 54 bytes) fits in one 64-byte block.
    #[target_feature(enable = "avx2")]
    pub unsafe fn test_ntlm_8way(
        candidates: &[&str],
        target_words: [u32; 4],
    ) -> Option<usize> {
        let count = candidates.len().min(8);
        if count == 0 {
            return None;
        }

        let mut raw_words = [[0u32; 16]; 8];

        for lane in 0..count {
            let cand = candidates[lane];
            if cand.len() > 27 {
                return None;
            }

            let mut block = [0u8; 64];
            let mut byte_len = 0usize;
            for b in cand.bytes() {
                block[byte_len] = b;
                block[byte_len + 1] = 0x00;
                byte_len += 2;
            }
            block[byte_len] = 0x80;
            let bit_len = (byte_len as u64) * 8;
            block[56..64].copy_from_slice(&bit_len.to_le_bytes());

            for w in 0..16 {
                raw_words[lane][w] = u32::from_le_bytes([
                    block[w * 4],
                    block[w * 4 + 1],
                    block[w * 4 + 2],
                    block[w * 4 + 3],
                ]);
            }
        }

        let mut m = [_mm256_setzero_si256(); 16];
        for w in 0..16 {
            m[w] = _mm256_setr_epi32(
                raw_words[0][w] as i32,
                raw_words[1][w] as i32,
                raw_words[2][w] as i32,
                raw_words[3][w] as i32,
                raw_words[4][w] as i32,
                raw_words[5][w] as i32,
                raw_words[6][w] as i32,
                raw_words[7][w] as i32,
            );
        }

        let mut a = _mm256_set1_epi32(0x67452301u32 as i32);
        let mut b = _mm256_set1_epi32(0xefcdab89u32 as i32);
        let mut c = _mm256_set1_epi32(0x98badcfeu32 as i32);
        let mut d = _mm256_set1_epi32(0x10325476u32 as i32);

        let a0 = a;
        let b0 = b;
        let c0 = c;
        let d0 = d;

        // MD4 Round 1: F(x, y, z) = (x & y) | (~x & z)
        macro_rules! r1 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                let f = _mm256_or_si256(_mm256_and_si256($b, $c), _mm256_andnot_si256($b, $d));
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, f), m[$k]);
                $a = rotl!(sum, $s);
            };
        }

        // MD4 Round 2: G(x, y, z) = (x & y) | (x & z) | (y & z) + 0x5a827999
        macro_rules! r2 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                let g = _mm256_or_si256(
                    _mm256_or_si256(_mm256_and_si256($b, $c), _mm256_and_si256($b, $d)),
                    _mm256_and_si256($c, $d),
                );
                let c_const = _mm256_set1_epi32(0x5a827999u32 as i32);
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, g), _mm256_add_epi32(m[$k], c_const));
                $a = rotl!(sum, $s);
            };
        }

        // MD4 Round 3: H(x, y, z) = x ^ y ^ z + 0x6ed9eba1
        macro_rules! r3 {
            ($a:expr, $b:expr, $c:expr, $d:expr, $k:expr, $s:expr) => {
                let h = _mm256_xor_si256(_mm256_xor_si256($b, $c), $d);
                let c_const = _mm256_set1_epi32(0x6ed9eba1u32 as i32);
                let sum = _mm256_add_epi32(_mm256_add_epi32($a, h), _mm256_add_epi32(m[$k], c_const));
                $a = rotl!(sum, $s);
            };
        }

        // Round 1
        r1!(a, b, c, d, 0,  3);
        r1!(d, a, b, c, 1,  7);
        r1!(c, d, a, b, 2,  11);
        r1!(b, c, d, a, 3,  19);
        r1!(a, b, c, d, 4,  3);
        r1!(d, a, b, c, 5,  7);
        r1!(c, d, a, b, 6,  11);
        r1!(b, c, d, a, 7,  19);
        r1!(a, b, c, d, 8,  3);
        r1!(d, a, b, c, 9,  7);
        r1!(c, d, a, b, 10, 11);
        r1!(b, c, d, a, 11, 19);
        r1!(a, b, c, d, 12, 3);
        r1!(d, a, b, c, 13, 7);
        r1!(c, d, a, b, 14, 11);
        r1!(b, c, d, a, 15, 19);

        // Round 2
        r2!(a, b, c, d, 0,  3);
        r2!(d, a, b, c, 4,  5);
        r2!(c, d, a, b, 8,  9);
        r2!(b, c, d, a, 12, 13);
        r2!(a, b, c, d, 1,  3);
        r2!(d, a, b, c, 5,  5);
        r2!(c, d, a, b, 9,  9);
        r2!(b, c, d, a, 13, 13);
        r2!(a, b, c, d, 2,  3);
        r2!(d, a, b, c, 6,  5);
        r2!(c, d, a, b, 10, 9);
        r2!(b, c, d, a, 14, 13);
        r2!(a, b, c, d, 3,  3);
        r2!(d, a, b, c, 7,  5);
        r2!(c, d, a, b, 11, 9);
        r2!(b, c, d, a, 15, 13);

        // Round 3
        r3!(a, b, c, d, 0,  3);
        r3!(d, a, b, c, 8,  9);
        r3!(c, d, a, b, 4,  11);
        r3!(b, c, d, a, 12, 15);
        r3!(a, b, c, d, 2,  3);
        r3!(d, a, b, c, 10, 9);
        r3!(c, d, a, b, 6,  11);
        r3!(b, c, d, a, 14, 15);
        r3!(a, b, c, d, 1,  3);
        r3!(d, a, b, c, 9,  9);
        r3!(c, d, a, b, 5,  11);
        r3!(b, c, d, a, 13, 15);
        r3!(a, b, c, d, 3,  3);
        r3!(d, a, b, c, 11, 9);
        r3!(c, d, a, b, 7,  11);
        r3!(b, c, d, a, 15, 15);

        let final_a = _mm256_add_epi32(a0, a);
        let final_b = _mm256_add_epi32(b0, b);
        let final_c = _mm256_add_epi32(c0, c);
        let final_d = _mm256_add_epi32(d0, d);

        let t_a = _mm256_set1_epi32(target_words[0] as i32);
        let t_b = _mm256_set1_epi32(target_words[1] as i32);
        let t_c = _mm256_set1_epi32(target_words[2] as i32);
        let t_d = _mm256_set1_epi32(target_words[3] as i32);

        let eq_a = _mm256_cmpeq_epi32(final_a, t_a);
        let eq_b = _mm256_cmpeq_epi32(final_b, t_b);
        let eq_c = _mm256_cmpeq_epi32(final_c, t_c);
        let eq_d = _mm256_cmpeq_epi32(final_d, t_d);

        let match_vec = _mm256_and_si256(
            _mm256_and_si256(eq_a, eq_b),
            _mm256_and_si256(eq_c, eq_d),
        );

        let mask = _mm256_movemask_epi8(match_vec) as u32;
        if mask != 0 {
            for lane in 0..count {
                let lane_mask = 0xF << (lane * 4);
                if (mask & lane_mask) == lane_mask {
                    return Some(lane);
                }
            }
        }

        None
    }

    /// Tests up to 8 candidate passwords against a target SHA-256 digest (8 u32 words big-endian).
    /// Candidates must be <= 55 bytes to fit a single 64-byte SHA-256 block.
    /// Returns Some(index) if any lane matches the target.
    #[target_feature(enable = "avx2")]
    pub unsafe fn test_sha256_8way(
        candidates: &[&[u8]],
        target_words: [u32; 8],
    ) -> Option<usize> {
        let count = candidates.len().min(8);
        if count == 0 { return None; }

        // SHA-256 round constants K
        const K: [u32; 64] = [
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
        ];

        // SHA-256 initial hash values (big-endian)
        let h0_init = 0x6a09e667u32;
        let h1_init = 0xbb67ae85u32;
        let h2_init = 0x3c6ef372u32;
        let h3_init = 0xa54ff53au32;
        let h4_init = 0x510e527fu32;
        let h5_init = 0x9b05688cu32;
        let h6_init = 0x1f83d9abu32;
        let h7_init = 0x5be0cd19u32;

        // Prepare padded message blocks for each lane (big-endian)
        let mut raw_words = [[0u32; 16]; 8];
        for lane in 0..count {
            let cand = candidates[lane];
            if cand.len() > 55 { return None; }
            let mut block = [0u8; 64];
            block[..cand.len()].copy_from_slice(cand);
            block[cand.len()] = 0x80;
            let bit_len = (cand.len() as u64) * 8;
            block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            for w in 0..16 {
                raw_words[lane][w] = u32::from_be_bytes([
                    block[w * 4], block[w * 4 + 1], block[w * 4 + 2], block[w * 4 + 3],
                ]);
            }
        }

        // Transpose into 16 AVX2 registers (one per message word, 8 lanes wide)
        let mut w_reg = [_mm256_setzero_si256(); 16];
        for i in 0..16 {
            w_reg[i] = _mm256_setr_epi32(
                raw_words[0][i] as i32, raw_words[1][i] as i32,
                raw_words[2][i] as i32, raw_words[3][i] as i32,
                raw_words[4][i] as i32, raw_words[5][i] as i32,
                raw_words[6][i] as i32, raw_words[7][i] as i32,
            );
        }

        // Extend message schedule W[16..63] using AVX2 bitwise ops
        // s0 = rotr(w,7) ^ rotr(w,18) ^ (w >> 3)
        // s1 = rotr(w,17) ^ rotr(w,19) ^ (w >> 10)
        macro_rules! rotr {
            ($x:expr, $s:expr) => {
                _mm256_or_si256(
                    _mm256_srli_epi32($x, $s),
                    _mm256_slli_epi32($x, 32 - $s),
                )
            };
        }

        let mut w_ext = [_mm256_setzero_si256(); 64];
        for i in 0..16usize { w_ext[i] = w_reg[i]; }
        for i in 16..64usize {
            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(rotr!(w_ext[i-15], 7), rotr!(w_ext[i-15], 18)),
                _mm256_srli_epi32(w_ext[i-15], 3),
            );
            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(rotr!(w_ext[i-2], 17), rotr!(w_ext[i-2], 19)),
                _mm256_srli_epi32(w_ext[i-2], 10),
            );
            w_ext[i] = _mm256_add_epi32(
                _mm256_add_epi32(w_ext[i-16], s0),
                _mm256_add_epi32(w_ext[i-7], s1),
            );
        }

        // Initialize working variables across all 8 lanes
        let mut a = _mm256_set1_epi32(h0_init as i32);
        let mut b = _mm256_set1_epi32(h1_init as i32);
        let mut c = _mm256_set1_epi32(h2_init as i32);
        let mut d = _mm256_set1_epi32(h3_init as i32);
        let mut e = _mm256_set1_epi32(h4_init as i32);
        let mut f = _mm256_set1_epi32(h5_init as i32);
        let mut g = _mm256_set1_epi32(h6_init as i32);
        let mut h = _mm256_set1_epi32(h7_init as i32);

        // 64 compression rounds
        for i in 0..64usize {
            // S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25)
            let s1 = _mm256_xor_si256(
                _mm256_xor_si256(rotr!(e, 6), rotr!(e, 11)),
                rotr!(e, 25),
            );
            // ch = (e & f) ^ (~e & g)
            let ch = _mm256_xor_si256(
                _mm256_and_si256(e, f),
                _mm256_andnot_si256(e, g),
            );
            // temp1 = h + S1 + ch + K[i] + W[i]
            let temp1 = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(h, s1),
                    _mm256_add_epi32(ch, _mm256_set1_epi32(K[i] as i32)),
                ),
                w_ext[i],
            );
            // S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22)
            let s0 = _mm256_xor_si256(
                _mm256_xor_si256(rotr!(a, 2), rotr!(a, 13)),
                rotr!(a, 22),
            );
            // maj = (a & b) ^ (a & c) ^ (b & c)
            let maj = _mm256_xor_si256(
                _mm256_xor_si256(
                    _mm256_and_si256(a, b),
                    _mm256_and_si256(a, c),
                ),
                _mm256_and_si256(b, c),
            );
            // temp2 = S0 + maj
            let temp2 = _mm256_add_epi32(s0, maj);
            h = g;
            g = f;
            f = e;
            e = _mm256_add_epi32(d, temp1);
            d = c;
            c = b;
            b = a;
            a = _mm256_add_epi32(temp1, temp2);
        }

        // Add initial hash values
        a = _mm256_add_epi32(a, _mm256_set1_epi32(h0_init as i32));
        b = _mm256_add_epi32(b, _mm256_set1_epi32(h1_init as i32));
        c = _mm256_add_epi32(c, _mm256_set1_epi32(h2_init as i32));
        d = _mm256_add_epi32(d, _mm256_set1_epi32(h3_init as i32));
        e = _mm256_add_epi32(e, _mm256_set1_epi32(h4_init as i32));
        f = _mm256_add_epi32(f, _mm256_set1_epi32(h5_init as i32));
        g = _mm256_add_epi32(g, _mm256_set1_epi32(h6_init as i32));
        h = _mm256_add_epi32(h, _mm256_set1_epi32(h7_init as i32));

        // Extract each lane and compare against target
        let results = [a, b, c, d, e, f, g, h];
        for lane in 0..count {
            let mut digest = [0u32; 8];
            for (wi, reg) in results.iter().enumerate() {
                let mut tmp = [0i32; 8];
                _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, *reg);
                digest[wi] = tmp[lane] as u32;
            }
            if digest == target_words {
                return Some(lane);
            }
        }
        None
    }

    /// Tests up to 8 candidate passwords against a target SHA-1 digest (5 u32 words big-endian).
    /// Candidates must be <= 55 bytes to fit a single 64-byte SHA-1 block.
    #[target_feature(enable = "avx2")]
    pub unsafe fn test_sha1_8way(
        candidates: &[&[u8]],
        target_words: [u32; 5],
    ) -> Option<usize> {
        let count = candidates.len().min(8);
        if count == 0 { return None; }

        // SHA-1 initial state
        let h0i = 0x67452301u32;
        let h1i = 0xefcdab89u32;
        let h2i = 0x98badcfeu32;
        let h3i = 0x10325476u32;
        let h4i = 0xc3d2e1f0u32;

        macro_rules! rotl_sha1 {
            ($x:expr, $s:expr) => {
                _mm256_or_si256(
                    _mm256_slli_epi32($x, $s),
                    _mm256_srli_epi32($x, 32 - $s),
                )
            };
        }

        // Build padded blocks
        let mut raw_words = [[0u32; 16]; 8];
        for lane in 0..count {
            let cand = candidates[lane];
            if cand.len() > 55 { return None; }
            let mut block = [0u8; 64];
            block[..cand.len()].copy_from_slice(cand);
            block[cand.len()] = 0x80;
            let bit_len = (cand.len() as u64) * 8;
            block[56..64].copy_from_slice(&bit_len.to_be_bytes());
            for w in 0..16 {
                raw_words[lane][w] = u32::from_be_bytes([
                    block[w * 4], block[w * 4 + 1], block[w * 4 + 2], block[w * 4 + 3],
                ]);
            }
        }

        // Transpose into 16 registers
        let mut w = [_mm256_setzero_si256(); 16];
        for i in 0..16 {
            w[i] = _mm256_setr_epi32(
                raw_words[0][i] as i32, raw_words[1][i] as i32,
                raw_words[2][i] as i32, raw_words[3][i] as i32,
                raw_words[4][i] as i32, raw_words[5][i] as i32,
                raw_words[6][i] as i32, raw_words[7][i] as i32,
            );
        }

        // Extend schedule W[16..79]
        let mut ws = [_mm256_setzero_si256(); 80];
        for i in 0..16usize { ws[i] = w[i]; }
        for i in 16..80usize {
            let x = _mm256_xor_si256(
                _mm256_xor_si256(ws[i-3], ws[i-8]),
                _mm256_xor_si256(ws[i-14], ws[i-16]),
            );
            ws[i] = rotl_sha1!(x, 1);
        }

        let mut a = _mm256_set1_epi32(h0i as i32);
        let mut b = _mm256_set1_epi32(h1i as i32);
        let mut c = _mm256_set1_epi32(h2i as i32);
        let mut d = _mm256_set1_epi32(h3i as i32);
        let mut e = _mm256_set1_epi32(h4i as i32);

        for i in 0..80usize {
            let (f, k) = if i < 20 {
                // Ch
                let f = _mm256_xor_si256(
                    _mm256_and_si256(b, c),
                    _mm256_andnot_si256(b, d),
                );
                (f, 0x5a827999u32)
            } else if i < 40 {
                // Parity
                let f = _mm256_xor_si256(_mm256_xor_si256(b, c), d);
                (f, 0x6ed9eba1u32)
            } else if i < 60 {
                // Maj
                let f = _mm256_xor_si256(
                    _mm256_xor_si256(
                        _mm256_and_si256(b, c),
                        _mm256_and_si256(b, d),
                    ),
                    _mm256_and_si256(c, d),
                );
                (f, 0x8f1bbcdcu32)
            } else {
                // Parity
                let f = _mm256_xor_si256(_mm256_xor_si256(b, c), d);
                (f, 0xca62c1d6u32)
            };
            let temp = _mm256_add_epi32(
                _mm256_add_epi32(
                    _mm256_add_epi32(rotl_sha1!(a, 5), f),
                    _mm256_add_epi32(e, _mm256_set1_epi32(k as i32)),
                ),
                ws[i],
            );
            e = d;
            d = c;
            c = rotl_sha1!(b, 30);
            b = a;
            a = temp;
        }

        a = _mm256_add_epi32(a, _mm256_set1_epi32(h0i as i32));
        b = _mm256_add_epi32(b, _mm256_set1_epi32(h1i as i32));
        c = _mm256_add_epi32(c, _mm256_set1_epi32(h2i as i32));
        d = _mm256_add_epi32(d, _mm256_set1_epi32(h3i as i32));
        e = _mm256_add_epi32(e, _mm256_set1_epi32(h4i as i32));

        let regs = [a, b, c, d, e];
        for lane in 0..count {
            let mut digest = [0u32; 5];
            for (wi, reg) in regs.iter().enumerate() {
                let mut tmp = [0i32; 8];
                _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, *reg);
                digest[wi] = tmp[lane] as u32;
            }
            if digest == target_words {
                return Some(lane);
            }
        }
        None
    }
}

/// Parse a 32-character hex string into four 32-bit little-endian words (standard MD5 / NTLM order).
pub fn parse_hex_words_32(hex: &str) -> Option<[u32; 4]> {
    if hex.len() != 32 {
        return None;
    }
    let mut words = [0u32; 4];
    for i in 0..4 {
        let chunk = &hex[i * 8..(i + 1) * 8];
        let mut b = [0u8; 4];
        for byte_idx in 0..4 {
            b[byte_idx] = u8::from_str_radix(&chunk[byte_idx * 2..byte_idx * 2 + 2], 16).ok()?;
        }
        words[i] = u32::from_le_bytes(b);
    }
    Some(words)
}

/// Parse a 64-character hex string into eight 32-bit big-endian words (SHA-256 digest).
pub fn parse_hex_words_64(hex: &str) -> Option<[u32; 8]> {
    if hex.len() != 64 { return None; }
    let bytes = hex.as_bytes();
    let mut out = [0u32; 8];
    for i in 0..8 {
        let s = std::str::from_utf8(&bytes[i*8..(i+1)*8]).ok()?;
        out[i] = u32::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Parse a 40-character hex string into five 32-bit big-endian words (SHA-1 digest).
pub fn parse_hex_words_40(hex: &str) -> Option<[u32; 5]> {
    if hex.len() != 40 { return None; }
    let bytes = hex.as_bytes();
    let mut out = [0u32; 5];
    for i in 0..5 {
        let s = std::str::from_utf8(&bytes[i*8..(i+1)*8]).ok()?;
        out[i] = u32::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_simd_backend() {
        let backend = active_simd_backend();
        println!("Active SIMD backend on this machine: {:?}", backend);
    }

    #[test]
    fn test_parse_hex_words() {
        let words = parse_hex_words_32("5d41402abc4b2a76b9719d911017c592").expect("Should parse hex");
        assert_eq!(words[0], 0x2a40415d);
    }

    #[test]
    fn test_avx2_md5_8way_matching() {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // MD5("admin123") = 0192023a7bbd73250516f069df18b500
                let target = parse_hex_words_32("0192023a7bbd73250516f069df18b500").unwrap();
                let candidates: Vec<&[u8]> = vec![
                    b"123456",
                    b"password",
                    b"welcome",
                    b"admin123", // Lane 3
                    b"qwerty",
                    b"dragon",
                    b"football",
                    b"monkey",
                ];

                unsafe {
                    let hit = avx2::test_md5_8way(&candidates, target);
                    assert_eq!(hit, Some(3), "Should detect admin123 in lane 3");

                    let bad_target = parse_hex_words_32("ffffffffffffffffffffffffffffffff").unwrap();
                    let hit_none = avx2::test_md5_8way(&candidates, bad_target);
                    assert_eq!(hit_none, None, "Should not detect non-matching target");
                }
            }
        }
    }

    #[test]
    fn test_avx2_ntlm_8way_matching() {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                // NTLM("password") = 8846f7eaee8fb117ad06bdd830b7586c
                let target = parse_hex_words_32("8846f7eaee8fb117ad06bdd830b7586c").unwrap();
                let candidates = vec![
                    "123456",
                    "welcome",
                    "admin",
                    "qwerty",
                    "football",
                    "password", // Lane 5
                    "dragon",
                    "monkey",
                ];

                unsafe {
                    let hit = avx2::test_ntlm_8way(&candidates, target);
                    assert_eq!(hit, Some(5), "Should detect password in lane 5");

                    let bad_target = parse_hex_words_32("ffffffffffffffffffffffffffffffff").unwrap();
                    let hit_none = avx2::test_ntlm_8way(&candidates, bad_target);
                    assert_eq!(hit_none, None, "Should not detect non-matching target");
                }
            }
        }
    }

    #[test]
    fn test_sha256_8way_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let target = parse_hex_words_64(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ).unwrap();
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if is_x86_feature_detected!("avx2") {
                let cands: &[&[u8]] = &[b"wrong1", b"wrong2", b"", b"wrong4"];
                assert_eq!(avx2::test_sha256_8way(cands, target), Some(2));
            }
        }
    }

    #[test]
    fn test_sha1_8way_vector() {
        // SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let target = parse_hex_words_40(
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        ).unwrap();
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if is_x86_feature_detected!("avx2") {
                let cands: &[&[u8]] = &[b"nope", b"", b"also_nope"];
                assert_eq!(avx2::test_sha1_8way(cands, target), Some(1));
            }
        }
    }
}
