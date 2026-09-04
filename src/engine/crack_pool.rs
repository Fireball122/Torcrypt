// src/engine/crack_pool.rs — Persistent Cryptographic Cracking Thread Pool
// Spawns N worker threads at attack-start time; they live for the duration of the
// attack.  Each tick the engine feeds a batch; workers drain it and return results.
// Eliminates the per-tick thread::scope allocation overhead.

use crossbeam_channel::{bounded, Receiver, Sender};
use std::thread::JoinHandle;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

use super::crackers::ActiveCracker;

// Work sent to worker threads: Some(chunk) to evaluate, None to exit.
type WorkItem = Option<Vec<String>>;

pub struct CrackPool {
    work_tx:   Sender<WorkItem>,
    result_rx: Receiver<Option<String>>,
    found_flag: Arc<AtomicBool>,
    size:      usize,
    _handles:  Vec<JoinHandle<()>>,
}

impl CrackPool {
    /// Spawn `thread_count` worker threads, each with its own clone of `cracker`.
    pub fn spawn(cracker: &ActiveCracker, thread_count: usize) -> Self {
        let n = thread_count.max(1);
        // Bounded channels: cap to 2×n so senders can't run far ahead of receivers.
        let (work_tx, work_rx) = bounded::<WorkItem>(n * 2);
        let (result_tx, result_rx) = bounded::<Option<String>>(n * 2);
        let found_flag = Arc::new(AtomicBool::new(false));

        let mut handles = Vec::with_capacity(n);
        for _ in 0..n {
            let c        = cracker.clone();
            let rx       = work_rx.clone();
            let tx       = result_tx.clone();
            let flag     = Arc::clone(&found_flag);
            handles.push(std::thread::spawn(move || {
                while let Ok(Some(batch)) = rx.recv() {
                    // Skip evaluation if another lane already found the key.
                    let found = if flag.load(Ordering::Relaxed) {
                        None
                    } else {
                        let hit = c.test_batch(&batch);
                        if hit.is_some() {
                            flag.store(true, Ordering::Relaxed);
                        }
                        hit
                    };
                    // Always send a result slot so the caller can count completions.
                    let _ = tx.send(found);
                }
                // Received None (shutdown signal) — exit cleanly.
            }));
        }

        Self { work_tx, result_rx, found_flag, size: n, _handles: handles }
    }

    /// Distribute `candidates` across all threads and return the first cracked key,
    /// or None if the entire batch was exhausted.
    pub fn evaluate(&self, candidates: Vec<String>) -> Option<String> {
        if candidates.is_empty() {
            return None;
        }
        self.found_flag.store(false, Ordering::Relaxed);

        let chunk_size = ((candidates.len() + self.size - 1) / self.size).max(1);
        let chunks: Vec<&[String]> = candidates.chunks(chunk_size).collect();
        let sent = chunks.len();

        for chunk in chunks {
            // Cloning is unavoidable here: each thread needs its own data.
            let _ = self.work_tx.send(Some(chunk.to_vec()));
        }

        let mut result = None;
        for _ in 0..sent {
            match self.result_rx.recv() {
                Ok(Some(key)) if result.is_none() => result = Some(key),
                _ => {}
            }
        }
        result
    }

    pub fn thread_count(&self) -> usize {
        self.size
    }
}

impl Drop for CrackPool {
    fn drop(&mut self) {
        // Send one shutdown signal per worker thread.
        for _ in 0..self.size {
            let _ = self.work_tx.send(None);
        }
        // _handles are dropped here; threads will exit after draining their None.
    }
}
