//! Process-wide logger for the GUI: `env_filter`-driven (same `RUST_LOG`
//! semantics and default filter as the CLI), teeing every record into a
//! bounded in-memory ring for the Logs tab and a size-rotated file in the
//! platform log directory.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

const RING_CAPACITY: usize = 2000;
const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const LOG_FILE: &str = "flextunnel-desktop.log";
const ROTATED_FILE: &str = "flextunnel-desktop.log.old";

static SINK: OnceLock<Sink> = OnceLock::new();
static REVISION: AtomicU64 = AtomicU64::new(0);

struct Sink {
    filter: env_filter::Filter,
    ring: Mutex<VecDeque<String>>,
    file: Mutex<Option<LogFile>>,
}

struct LogFile {
    file: File,
    written: u64,
    dir: PathBuf,
}

/// Never panic inside the logger: recover the guard from a poisoned mutex.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn log_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().map(|h| h.join("Library/Logs/flextunnel"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        dirs::data_local_dir().map(|d| d.join("flextunnel").join("logs"))
    }
}

fn open_log(dir: PathBuf) -> Option<LogFile> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(LOG_FILE))
        .ok()?;
    let written = file.metadata().map(|m| m.len()).unwrap_or(0);
    Some(LogFile { file, written, dir })
}

impl LogFile {
    fn write_line(&mut self, line: &str) {
        if self.written > MAX_LOG_BYTES {
            let _ = fs::rename(self.dir.join(LOG_FILE), self.dir.join(ROTATED_FILE));
            match open_log(self.dir.clone()) {
                Some(fresh) => *self = fresh,
                None => return,
            }
        }
        if writeln!(self.file, "{line}").is_ok() {
            self.written += line.len() as u64 + 1;
        }
    }
}

impl log::Log for Sink {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &log::Record) {
        if !self.filter.matches(record) {
            return;
        }
        let line = format!(
            "{} {:5} {}: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            record.target(),
            record.args()
        );
        {
            let mut ring = lock(&self.ring);
            if ring.len() == RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(line.clone());
        }
        if let Some(f) = lock(&self.file).as_mut() {
            f.write_line(&line);
        }
        REVISION.fetch_add(1, Ordering::Relaxed);
    }

    fn flush(&self) {
        if let Some(f) = lock(&self.file).as_mut() {
            let _ = f.file.flush();
        }
    }
}

/// Install the logger. `RUST_LOG` overrides the CLI's default filter.
pub fn init() {
    let spec = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| flextunnel_core::app::DEFAULT_LOG_FILTER.to_string());
    let filter = env_filter::Builder::new().parse(&spec).build();
    let max_level = filter.filter();
    let file = log_dir().and_then(|dir| {
        fs::create_dir_all(&dir).ok()?;
        open_log(dir)
    });
    let sink = SINK.get_or_init(|| Sink {
        filter,
        ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
        file: Mutex::new(file),
    });
    if log::set_logger(sink).is_ok() {
        log::set_max_level(max_level);
    }
}

/// Bumped on every record; lets the Logs tab skip re-fetching when idle.
pub fn revision() -> u64 {
    REVISION.load(Ordering::Relaxed)
}

/// Snapshot of the most recent log lines, oldest first.
pub fn recent_lines() -> Vec<String> {
    SINK.get()
        .map(|s| lock(&s.ring).iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_dir_is_available() {
        assert!(log_dir().is_some());
    }
}
