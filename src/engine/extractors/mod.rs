// src/engine/extractors/mod.rs — In-Process Container Extractors & Metadata Parsers

pub mod hash_type;
pub mod keepass;
pub mod pdf;
pub mod seven_zip;
pub mod zip;
pub mod hash_formatter;
pub use hash_formatter::format_archive_hash;

pub use hash_type::{HashCategory, HashClassification};
pub use keepass::KeePassInspection;
pub use pdf::PdfInspection;
pub use seven_zip::SevenZipInspection;
pub use zip::{ZipEncryption, ZipInspection};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_classification() {
        // MD5 / NTLM (32 hex)
        let md5_input = b"5d41402abc4b2a76b9719d911017c592";
        let c = HashClassification::classify(md5_input).expect("Should classify 32-hex");
        assert!(c.display_name.contains("MD5"));
        assert_eq!(c.hashcat_mode, Some(1000));

        // SHA-256 (64 hex)
        let sha256_input = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let c = HashClassification::classify(sha256_input).expect("Should classify 64-hex");
        assert!(c.display_name.contains("SHA-256"));
        assert_eq!(c.hashcat_mode, Some(1400));

        // Bcrypt ($2b$12$)
        let bcrypt_input = b"$2b$12$e87.g3.i2pUoN.5gZ7fW7e1A4rK7qB2vV9hT5sP8mQ4oN2rT6uY7i";
        let c = HashClassification::classify(bcrypt_input).expect("Should classify bcrypt");
        assert!(c.display_name.contains("Bcrypt"));
        assert_eq!(c.hashcat_mode, Some(3200));

        // Argon2 ($argon2id$)
        let argon_input = b"$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgqlrefresh";
        let c = HashClassification::classify(argon_input).expect("Should classify argon2");
        assert!(c.display_name.contains("Argon2"));
        assert_eq!(c.hashcat_mode, Some(13900));

        // Kerberos 5 TGS
        let krb_input = b"$krb5tgs$23$user$realm$test$c3757827828282828282";
        let c = HashClassification::classify(krb_input).expect("Should classify krb5");
        assert!(c.display_name.contains("Kerberos 5"));
        assert_eq!(c.hashcat_mode, Some(13100));
    }

    #[test]
    fn test_zip_inspector_unencrypted() {
        let temp_dir = std::env::temp_dir();
        let test_zip_path = temp_dir.join("torcrypt_test_plain.zip");

        // Construct valid minimal ZIP with 1 file ("test.txt")
        let mut zip_bytes = Vec::new();
        // Local file header (30 bytes + 8 bytes filename)
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // PK\x03\x04
        zip_bytes.extend_from_slice(&[20, 0]); // version needed (2.0)
        zip_bytes.extend_from_slice(&[0, 0]); // flags: UNENCRYPTED
        zip_bytes.extend_from_slice(&[0, 0]); // compression: stored
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // mod time/date
        zip_bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // CRC-32
        zip_bytes.extend_from_slice(&[5, 0, 0, 0]); // comp size
        zip_bytes.extend_from_slice(&[5, 0, 0, 0]); // uncomp size
        zip_bytes.extend_from_slice(&[8, 0]); // filename len: 8
        zip_bytes.extend_from_slice(&[0, 0]); // extra field len: 0
        zip_bytes.extend_from_slice(b"test.txt"); // filename
        zip_bytes.extend_from_slice(b"hello"); // payload

        let cd_offset = zip_bytes.len() as u32;
        // Central directory header (46 bytes + 8 bytes filename)
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // PK\x01\x02
        zip_bytes.extend_from_slice(&[20, 0]); // version made by
        zip_bytes.extend_from_slice(&[20, 0]); // version needed
        zip_bytes.extend_from_slice(&[0, 0]); // flags: UNENCRYPTED
        zip_bytes.extend_from_slice(&[0, 0]); // compression: stored
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // mod time/date
        zip_bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // CRC-32
        zip_bytes.extend_from_slice(&[5, 0, 0, 0]); // comp size
        zip_bytes.extend_from_slice(&[5, 0, 0, 0]); // uncomp size
        zip_bytes.extend_from_slice(&[8, 0]); // filename len
        zip_bytes.extend_from_slice(&[0, 0]); // extra len
        zip_bytes.extend_from_slice(&[0, 0]); // comment len
        zip_bytes.extend_from_slice(&[0, 0]); // disk start
        zip_bytes.extend_from_slice(&[0, 0]); // internal attrs
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // external attrs
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]); // local header offset: 0
        zip_bytes.extend_from_slice(b"test.txt");

        let cd_size = (zip_bytes.len() as u32) - cd_offset;
        // EOCD (22 bytes)
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // PK\x05\x06
        zip_bytes.extend_from_slice(&[0, 0]); // disk num
        zip_bytes.extend_from_slice(&[0, 0]); // start disk
        zip_bytes.extend_from_slice(&[1, 0]); // entries on disk: 1
        zip_bytes.extend_from_slice(&[1, 0]); // total entries: 1
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes()); // CD size
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        zip_bytes.extend_from_slice(&[0, 0]); // comment len: 0

        std::fs::write(&test_zip_path, zip_bytes).unwrap();
        let inspection = ZipInspection::inspect(&test_zip_path).expect("Should inspect ZIP");
        assert!(inspection.is_zip);
        assert_eq!(inspection.encryption, ZipEncryption::None);
        assert_eq!(inspection.total_files, 1);
        assert_eq!(inspection.encrypted_files, 0);
        let _ = std::fs::remove_file(test_zip_path);
    }

    #[test]
    fn test_zip_inspector_encrypted() {
        let temp_dir = std::env::temp_dir();
        let test_zip_path = temp_dir.join("torcrypt_test_enc.zip");

        // Construct valid minimal ZIP with 1 encrypted file (ZipCrypto flag 0x0001)
        let mut zip_bytes = Vec::new();
        // Local file header
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]); // Flag 0x0001 = ENCRYPTED
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // CRC
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(b"data.bin");
        zip_bytes.extend_from_slice(&[0u8; 12]); // 12-byte encryption header

        let cd_offset = zip_bytes.len() as u32;
        // Central directory header
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]);
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[20, 0]);
        zip_bytes.extend_from_slice(&[1, 0]); // Flag 0x0001 = ENCRYPTED
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        zip_bytes.extend_from_slice(&[12, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[8, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(&[0, 0, 0, 0]);
        zip_bytes.extend_from_slice(b"data.bin");

        let cd_size = (zip_bytes.len() as u32) - cd_offset;
        // EOCD
        zip_bytes.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[0, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&[1, 0]);
        zip_bytes.extend_from_slice(&cd_size.to_le_bytes());
        zip_bytes.extend_from_slice(&cd_offset.to_le_bytes());
        zip_bytes.extend_from_slice(&[0, 0]);

        std::fs::write(&test_zip_path, zip_bytes).unwrap();
        let inspection = ZipInspection::inspect(&test_zip_path).expect("Should inspect encrypted ZIP");
        assert!(inspection.is_zip);
        assert!(matches!(inspection.encryption, ZipEncryption::ZipCrypto { .. }));
        assert_eq!(inspection.encrypted_files, 1);
        assert!(inspection.summary.contains("ZipCrypto"));
        let _ = std::fs::remove_file(test_zip_path);
    }

    #[test]
    fn test_pdf_inspector_encrypted() {
        let temp_dir = std::env::temp_dir();
        let test_pdf_path = temp_dir.join("torcrypt_test_enc.pdf");

        let pdf_content = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Encrypt << /Filter /Standard /V 5 /R 6 /Length 256 /P -4 /U <41424344> /O <45464748> >> >>\n%%EOF";
        std::fs::write(&test_pdf_path, pdf_content).unwrap();

        let inspection = PdfInspection::inspect(&test_pdf_path).expect("Should inspect PDF");
        assert!(inspection.is_pdf);
        assert!(inspection.is_encrypted);
        assert_eq!(inspection.v_version, 5);
        assert_eq!(inspection.r_revision, 6);
        assert_eq!(inspection.key_length_bits, 256);
        assert_eq!(inspection.permissions, -4);
        assert_eq!(inspection.user_hash_hex, Some("41424344".into()));
        assert_eq!(inspection.owner_hash_hex, Some("45464748".into()));
        assert!(inspection.summary.contains("AES-256"));
        let _ = std::fs::remove_file(test_pdf_path);
    }

    #[test]
    fn test_seven_zip_inspector() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("torcrypt_test.7z");

        let mut seven_z_bytes = vec![0u8; 32];
        seven_z_bytes[0..6].copy_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]);
        seven_z_bytes[6] = 0; // major version
        seven_z_bytes[7] = 4; // minor version

        std::fs::write(&test_path, seven_z_bytes).unwrap();
        let inspection = SevenZipInspection::inspect(&test_path).expect("Should inspect 7z");
        assert!(inspection.is_7z);
        assert_eq!(inspection.version_major, 0);
        assert_eq!(inspection.version_minor, 4);
        let _ = std::fs::remove_file(test_path);
    }

    #[test]
    fn test_keepass_inspector() {
        let temp_dir = std::env::temp_dir();
        let test_path = temp_dir.join("torcrypt_test.kdbx");

        // Signature: 0x9AA2D903, 0xB54BFB67 (KDBX 4.0)
        let mut kdbx_bytes = vec![0u8; 16];
        kdbx_bytes[0..4].copy_from_slice(&0x9AA2D903u32.to_le_bytes());
        kdbx_bytes[4..8].copy_from_slice(&0xB54BFB67u32.to_le_bytes());
        kdbx_bytes[8..10].copy_from_slice(&0u16.to_le_bytes()); // minor
        kdbx_bytes[10..12].copy_from_slice(&4u16.to_le_bytes()); // major

        std::fs::write(&test_path, kdbx_bytes).unwrap();
        let inspection = KeePassInspection::inspect(&test_path).expect("Should inspect KDBX");
        assert!(inspection.is_keepass);
        assert_eq!(inspection.format_version, "KeePass 4.0");
        let _ = std::fs::remove_file(test_path);
    }
}
