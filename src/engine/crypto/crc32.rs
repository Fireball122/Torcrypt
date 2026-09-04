// src/engine/crypto/crc32.rs — Standard IEEE 802.3 CRC-32 Implementation
// Used for ZipCrypto state key updating and archive header validation.

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = 0xEDB88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

#[inline(always)]
pub fn crc32_update(crc: u32, byte: u8) -> u32 {
    CRC_TABLE[((crc ^ (byte as u32)) & 0xFF) as usize] ^ (crc >> 8)
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc = crc32_update(crc, b);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_standard() {
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b""), 0x00000000);
    }
}
