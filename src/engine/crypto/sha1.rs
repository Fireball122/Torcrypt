// src/engine/crypto/sha1.rs — FIPS 180-1 SHA-1 Message-Digest Algorithm
// Pure-Rust implementation with zero dependencies and allocation-free single-block path.

pub fn sha1(input: &[u8]) -> [u8; 20] {
    if input.len() <= 55 {
        return sha1_single_block(input);
    }

    let mut h0 = 0x67452301u32;
    let mut h1 = 0xEFCDAB89u32;
    let mut h2 = 0x98BADCFEu32;
    let mut h3 = 0x10325476u32;
    let mut h4 = 0xC3D2E1F0u32;

    let orig_len_bits = (input.len() as u64).wrapping_mul(8);
    let mut msg = input.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for i in 0..80 {
            let (f, k) = if i < 20 {
                ((b & c) | ((!b) & d), 0x5A827999u32)
            } else if i < 40 {
                (b ^ c ^ d, 0x6ED9EBA1u32)
            } else if i < 60 {
                ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
            } else {
                (b ^ c ^ d, 0xCA62C1D6u32)
            };

            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

/// Zero-allocation single-block SHA-1 for inputs <= 55 bytes.
pub fn sha1_single_block(input: &[u8]) -> [u8; 20] {
    let mut block = [0u8; 64];
    let len = input.len().min(55);
    block[..len].copy_from_slice(&input[..len]);
    block[len] = 0x80;
    let orig_len_bits = (len as u64) * 8;
    block[56..64].copy_from_slice(&orig_len_bits.to_be_bytes());

    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let mut a = 0x67452301u32;
    let mut b = 0xEFCDAB89u32;
    let mut c = 0x98BADCFEu32;
    let mut d = 0x10325476u32;
    let mut e = 0xC3D2E1F0u32;

    for i in 0..80 {
        let (f, k) = if i < 20 {
            ((b & c) | ((!b) & d), 0x5A827999u32)
        } else if i < 40 {
            (b ^ c ^ d, 0x6ED9EBA1u32)
        } else if i < 60 {
            ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32)
        } else {
            (b ^ c ^ d, 0xCA62C1D6u32)
        };

        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(w[i]);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&0x67452301u32.wrapping_add(a).to_be_bytes());
    out[4..8].copy_from_slice(&0xEFCDAB89u32.wrapping_add(b).to_be_bytes());
    out[8..12].copy_from_slice(&0x98BADCFEu32.wrapping_add(c).to_be_bytes());
    out[12..16].copy_from_slice(&0x10325476u32.wrapping_add(d).to_be_bytes());
    out[16..20].copy_from_slice(&0xC3D2E1F0u32.wrapping_add(e).to_be_bytes());
    out
}

pub fn sha1_hex(input: &[u8]) -> String {
    let digest = sha1(input);
    let mut out = String::with_capacity(40);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_standard() {
        // FIPS 180-1 vector: "abc"
        let digest = sha1(b"abc");
        assert_eq!(
            sha1_hex(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(digest, sha1_single_block(b"abc"));
    }
}
