// src/engine/session_db.rs — SQLite Persistent Session Database
// Stores cryptographic audit and analysis sessions persistently in ~/.local/share/torcrypt/torcrypt.db

use std::fs;
use std::path::PathBuf;
use rusqlite::{params, Connection, Result};

#[derive(Debug, Clone)]
pub struct DbSession {
    pub id:           String,
    pub target:       String,
    pub cipher:       String,
    pub kdf:          String,
    pub status:       String,
    pub created_at:   String,
    pub keys_checked: u64,
    pub speed_mbps:   f64,
    pub memory_mb:    u32,
    pub threads:      u8,
}

#[derive(Debug, Clone)]
pub struct PotfileRecord {
    pub hash_or_sig: String,
    pub plaintext:   String,
    pub algo:        String,
    pub cracked_at:  String,
}

pub struct SessionDatabase {
    conn: Connection,
}

impl SessionDatabase {
    pub fn init() -> Result<Self> {
        let db_path = get_database_path();
        if let Some(parent) = db_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS sessions (
                 id           TEXT PRIMARY KEY,
                 target       TEXT NOT NULL,
                 cipher       TEXT NOT NULL,
                 kdf          TEXT NOT NULL,
                 status       TEXT NOT NULL,
                 created_at   TEXT NOT NULL,
                 keys_checked INTEGER NOT NULL,
                 speed_mbps   REAL NOT NULL,
                 memory_mb    INTEGER NOT NULL,
                 threads      INTEGER NOT NULL,
                 checkpoint_offset INTEGER DEFAULT 0
             );
             CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
             CREATE TABLE IF NOT EXISTS potfile (
                 hash_or_sig TEXT PRIMARY KEY,
                 plaintext   TEXT NOT NULL,
                 algo        TEXT NOT NULL,
                 cracked_at  TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_potfile_sig ON potfile(hash_or_sig);"
        )?;

        // Non-destructive migration for existing tables
        let _ = conn.execute("ALTER TABLE sessions ADD COLUMN checkpoint_offset INTEGER DEFAULT 0;", []);

        Ok(Self { conn })
    }

    pub fn load_all(&self) -> Vec<DbSession> {
        let mut stmt = match self.conn.prepare(
            "SELECT id, target, cipher, kdf, status, created_at, keys_checked, speed_mbps, memory_mb, threads
             FROM sessions
             ORDER BY rowid DESC;"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map([], |row| {
            Ok(DbSession {
                id:           row.get(0)?,
                target:       row.get(1)?,
                cipher:       row.get(2)?,
                kdf:          row.get(3)?,
                status:       row.get(4)?,
                created_at:   row.get(5)?,
                keys_checked: row.get::<_, i64>(6)? as u64,
                speed_mbps:   row.get(7)?,
                memory_mb:    row.get::<_, i64>(8)? as u32,
                threads:      row.get::<_, i64>(9)? as u8,
            })
        });

        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn insert(&self, s: &DbSession) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions
             (id, target, cipher, kdf, status, created_at, keys_checked, speed_mbps, memory_mb, threads)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10);",
            params![
                s.id,
                s.target,
                s.cipher,
                s.kdf,
                s.status,
                s.created_at,
                s.keys_checked as i64,
                s.speed_mbps,
                s.memory_mb as i64,
                s.threads as i64,
            ],
        )?;
        Ok(())
    }

    pub fn potfile_lookup(&self, hash_or_sig: &str) -> Option<String> {
        let mut stmt = self.conn.prepare("SELECT plaintext FROM potfile WHERE hash_or_sig = ?1 LIMIT 1;").ok()?;
        stmt.query_row(params![hash_or_sig], |row| row.get::<_, String>(0)).ok()
    }

    pub fn potfile_insert(&self, hash_or_sig: &str, plaintext: &str, algo: &str) -> Result<()> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "INSERT OR REPLACE INTO potfile (hash_or_sig, plaintext, algo, cracked_at) VALUES (?1, ?2, ?3, ?4);",
            params![hash_or_sig, plaintext, algo, now],
        )?;
        Ok(())
    }

    pub fn load_potfile(&self) -> Vec<PotfileRecord> {
        let mut stmt = match self.conn.prepare(
            "SELECT hash_or_sig, plaintext, algo, cracked_at FROM potfile ORDER BY rowid DESC;"
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map([], |row| {
            Ok(PotfileRecord {
                hash_or_sig: row.get(0)?,
                plaintext:   row.get(1)?,
                algo:        row.get(2)?,
                cracked_at:  row.get(3)?,
            })
        });

        match rows {
            Ok(mapped) => mapped.flatten().collect(),
            Err(_) => Vec::new(),
        }
    }

    pub fn update_checkpoint(&self, session_id: &str, offset: u64, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE sessions SET checkpoint_offset = ?1, status = ?2 WHERE id = ?3;",
            params![offset as i64, status, session_id],
        )?;
        Ok(())
    }

    pub fn get_latest_checkpoint(&self, target_path: &str) -> Option<(String, u64)> {
        let mut stmt = self.conn.prepare(
            "SELECT id, checkpoint_offset FROM sessions WHERE target = ?1 AND checkpoint_offset > 0 ORDER BY rowid DESC LIMIT 1;"
        ).ok()?;
        stmt.query_row(params![target_path], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        }).ok()
    }
}

fn get_database_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("torcrypt")
            .join("torcrypt.db")
    } else {
        PathBuf::from("torcrypt.db")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_db_operations() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (
                 id TEXT PRIMARY KEY, target TEXT, cipher TEXT, kdf TEXT,
                 status TEXT, created_at TEXT, keys_checked INTEGER,
                 speed_mbps REAL, memory_mb INTEGER, threads INTEGER
             );
             CREATE TABLE potfile (
                 hash_or_sig TEXT PRIMARY KEY, plaintext TEXT, algo TEXT, cracked_at TEXT
             );"
        ).unwrap();

        let db = SessionDatabase { conn };

        let session = DbSession {
            id: "SES-TEST".into(),
            target: "vault.enc".into(),
            cipher: "AES-256".into(),
            kdf: "PBKDF2".into(),
            status: "DECRYPTED".into(),
            created_at: "2026-09-02 12:00".into(),
            keys_checked: 42000,
            speed_mbps: 18450.0,
            memory_mb: 64,
            threads: 12,
        };

        db.insert(&session).expect("Insert should succeed");

        let all = db.load_all();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "SES-TEST");
        assert_eq!(all[0].target, "vault.enc");
        assert_eq!(all[0].cipher, "AES-256");
        assert_eq!(all[0].status, "DECRYPTED");
        assert_eq!(all[0].keys_checked, 42000);
        db.potfile_insert("5d41402abc4b2a76b9719d911017c592", "hello", "MD5").unwrap();
        assert_eq!(db.potfile_lookup("5d41402abc4b2a76b9719d911017c592"), Some("hello".to_string()));
        assert_eq!(db.potfile_lookup("nonexistent"), None);
    }
}
