// src/engine/crypto/md4.rs — RFC 1320 MD4 Message-Digest & NTLM Algorithm
// Pure-Rust implementation with zero dependencies.

pub fn md4(input: &[u8]) -> [u8; 16] {
    let mut a = 0x67452301u32;
    let mut b = 0xefcdab89u32;
    let mut c = 0x98badcfeu32;
    let mut d = 0x10325476u32;

    let orig_len_bits = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut x = [0u32; 16];
        for i in 0..16 {
            x[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        let aa = a;
        let bb = b;
        let cc = c;
        let dd = d;

        // Round 1
        let f = |x: u32, y: u32, z: u32| (x & y) | ((!x) & z);
        let r1 = |a_ref: &mut u32, b_val: u32, c_val: u32, d_val: u32, k: usize, s: u32| {
            *a_ref = a_ref.wrapping_add(f(b_val, c_val, d_val)).wrapping_add(x[k]).rotate_left(s);
        };

        r1(&mut a, b, c, d, 0, 3);
        r1(&mut d, a, b, c, 1, 7);
        r1(&mut c, d, a, b, 2, 11);
        r1(&mut b, c, d, a, 3, 19);
        r1(&mut a, b, c, d, 4, 3);
        r1(&mut d, a, b, c, 5, 7);
        r1(&mut c, d, a, b, 6, 11);
        r1(&mut b, c, d, a, 7, 19);
        r1(&mut a, b, c, d, 8, 3);
        r1(&mut d, a, b, c, 9, 7);
        r1(&mut c, d, a, b, 10, 11);
        r1(&mut b, c, d, a, 11, 19);
        r1(&mut a, b, c, d, 12, 3);
        r1(&mut d, a, b, c, 13, 7);
        r1(&mut c, d, a, b, 14, 11);
        r1(&mut b, c, d, a, 15, 19);

        // Round 2
        let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
        let r2 = |a_ref: &mut u32, b_val: u32, c_val: u32, d_val: u32, k: usize, s: u32| {
            *a_ref = a_ref.wrapping_add(g(b_val, c_val, d_val)).wrapping_add(x[k]).wrapping_add(0x5a827999).rotate_left(s);
        };

        r2(&mut a, b, c, d, 0, 3);
        r2(&mut d, a, b, c, 4, 5);
        r2(&mut c, d, a, b, 8, 9);
        r2(&mut b, c, d, a, 12, 13);
        r2(&mut a, b, c, d, 1, 3);
        r2(&mut d, a, b, c, 5, 5);
        r2(&mut c, d, a, b, 9, 9);
        r2(&mut b, c, d, a, 13, 13);
        r2(&mut a, b, c, d, 2, 3);
        r2(&mut d, a, b, c, 6, 5);
        r2(&mut c, d, a, b, 10, 9);
        r2(&mut b, c, d, a, 14, 13);
        r2(&mut a, b, c, d, 3, 3);
        r2(&mut d, a, b, c, 7, 5);
        r2(&mut c, d, a, b, 11, 9);
        r2(&mut b, c, d, a, 15, 13);

        // Round 3
        let h = |x: u32, y: u32, z: u32| x ^ y ^ z;
        let r3 = |a_ref: &mut u32, b_val: u32, c_val: u32, d_val: u32, k: usize, s: u32| {
            *a_ref = a_ref.wrapping_add(h(b_val, c_val, d_val)).wrapping_add(x[k]).wrapping_add(0x6ed9eba1).rotate_left(s);
        };

        r3(&mut a, b, c, d, 0, 3);
        r3(&mut d, a, b, c, 8, 9);
        r3(&mut c, d, a, b, 4, 11);
        r3(&mut b, c, d, a, 12, 15);
        r3(&mut a, b, c, d, 2, 3);
        r3(&mut d, a, b, c, 10, 9);
        r3(&mut c, d, a, b, 6, 11);
        r3(&mut b, c, d, a, 14, 15);
        r3(&mut a, b, c, d, 1, 3);
        r3(&mut d, a, b, c, 9, 9);
        r3(&mut c, d, a, b, 5, 11);
        r3(&mut b, c, d, a, 13, 15);
        r3(&mut a, b, c, d, 3, 3);
        r3(&mut d, a, b, c, 11, 9);
        r3(&mut c, d, a, b, 7, 11);
        r3(&mut b, c, d, a, 15, 15);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

pub fn md4_hex(input: &[u8]) -> String {
    let digest = md4(input);
    let mut s = String::with_capacity(32);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Computes the NTLM hash of a UTF-8 password (MD4 of UTF-16LE encoded bytes)
pub fn ntlm_hash(password: &str) -> [u8; 16] {
    let mut utf16_bytes = Vec::with_capacity(password.len() * 2);
    for c in password.encode_utf16() {
        utf16_bytes.extend_from_slice(&c.to_le_bytes());
    }
    md4(&utf16_bytes)
}

pub fn ntlm_hex(password: &str) -> String {
    let digest = ntlm_hash(password);
    let mut s = String::with_capacity(32);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md4_standard() {
        assert_eq!(md4_hex(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(md4_hex(b"a"), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(md4_hex(b"abc"), "a448017aaf21d8525fc10ae87aa6729d");
    }

    #[test]
    fn test_ntlm_standard() {
        assert_eq!(ntlm_hex(""), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(ntlm_hex("password"), "8846f7eaee8fb117ad06bdd830b7586c");
        assert_eq!(ntlm_hex("admin"), "209c6174da490caeb422f3fa5a7ae634");
    }
}
