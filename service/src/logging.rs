//! Size-based rotating file log for the service (`svc-skeleton` DoD:
//! "logs rotate at size limit").
//!
//! # Why hand-rolled and not `tracing-appender`
//!
//! `tracing-appender`'s `RollingFileAppender` only rotates on a *time*
//! boundary (minutely/hourly/daily). The DoD is an explicit *size* limit, so
//! time-based rolling doesn't satisfy it — a quiet day never rotates while a
//! chatty minute can blow past any disk budget. This module rotates strictly
//! on bytes written.
//!
//! # Rotation scheme
//!
//! Numbered generations, newest-first:
//! - active file: `<stem>.log`
//! - rotated:     `<stem>.log.1` (most recent) … `<stem>.log.N` (oldest),
//!   where `N = keep_files`.
//!
//! The size check runs **once per log record**, before the record is written
//! (see [`RotatingMakeWriter::make_writer`]). That is deliberate: a record is
//! never split across two files. The consequence is that the active file may
//! exceed `max_size_bytes` by at most the final record that crossed the
//! limit, and the *next* record triggers the rollover. This is the same
//! "check on the way in, roll the whole next record over" behaviour common to
//! size-based rotators, and it keeps every JSON log line individually valid.
//!
//! # The Windows open-handle-rename hazard
//!
//! Windows refuses to rename a file that still has an open handle unless that
//! handle was opened with `FILE_SHARE_DELETE` — otherwise `MoveFileEx` fails
//! with `ERROR_SHARING_VIOLATION`. Rather than depend on that share-mode
//! subtlety, [`RotatingLog::rotate`] *closes* the active handle (drops the
//! `Option<File>`) before renaming and reopens a fresh one afterwards. That
//! is portable and needs no platform-specific `OpenOptionsExt`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use tracing::Subscriber;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::EnvFilter;

use crate::config::ServiceConfig;

#[derive(Debug, Clone, Copy)]
pub struct RotationPolicy {
    pub max_size_bytes: u64,
    /// Number of rotated generations kept besides the active file. Must be
    /// at least 1 (enforced by [`ServiceConfig::validate`]); a value below 1
    /// is treated as 1 here as a defensive floor so the rotate loop is sound.
    pub keep_files: usize,
}

/// A single append-only log file that rotates by size.
pub struct RotatingLog {
    dir: PathBuf,
    stem: String,
    policy: RotationPolicy,
    /// `None` only transiently, inside [`RotatingLog::rotate`], while the old
    /// handle is closed so it can be renamed on Windows.
    file: Option<File>,
    /// Bytes in the *current* active file. Seeded from the existing file's
    /// length on open, so a restart onto an already-large log rotates
    /// promptly rather than appending unboundedly.
    written: u64,
}

impl RotatingLog {
    pub fn open(dir: impl AsRef<Path>, stem: &str, policy: RotationPolicy) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let file = open_active(&dir, stem)?;
        let written = file.metadata()?.len();
        Ok(Self {
            dir,
            stem: stem.to_string(),
            policy,
            file: Some(file),
            written,
        })
    }

    fn active_path(&self) -> PathBuf {
        active_path(&self.dir, &self.stem)
    }

    fn rotated_path(&self, n: usize) -> PathBuf {
        self.dir.join(format!("{}.log.{}", self.stem, n))
    }

    /// Rotates iff the active file has reached the configured size limit.
    /// Called once per record before it is written. A rotation failure is
    /// logged to stderr and swallowed: a background service must not fall
    /// over because a rename lost a race — it keeps writing to the (oversized)
    /// active file, which is strictly better than crashing the filter.
    pub fn rotate_if_needed(&mut self) {
        if self.written >= self.policy.max_size_bytes {
            if let Err(e) = self.rotate() {
                // Cannot use `tracing` here: this *is* the tracing writer, so
                // logging would re-enter. Bypass to the real stderr.
                let _ = writeln!(io::stderr(), "cf-service: log rotation failed: {e}");
            }
        }
    }

    fn rotate(&mut self) -> io::Result<()> {
        let keep = self.policy.keep_files.max(1);

        // Close the active handle *before* any rename (Windows hazard, see
        // module docs). Reopened at the end.
        if let Some(mut f) = self.file.take() {
            let _ = f.flush();
        }

        // Drop the oldest generation, then shift each remaining generation up
        // by one (N-1 -> N, … 1 -> 2), then move the active file into slot 1.
        let oldest = self.rotated_path(keep);
        if oldest.exists() {
            fs::remove_file(&oldest)?;
        }
        for n in (1..keep).rev() {
            let from = self.rotated_path(n);
            if from.exists() {
                fs::rename(&from, self.rotated_path(n + 1))?;
            }
        }
        let active = self.active_path();
        if active.exists() {
            fs::rename(&active, self.rotated_path(1))?;
        }

        // Fresh active file; if reopening fails we still leave `file` as None
        // and surface the error — the next write will error loudly rather
        // than silently vanish.
        self.file = Some(open_active(&self.dir, &self.stem)?);
        self.written = 0;
        Ok(())
    }
}

impl Write for RotatingLog {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("rotating log has no open file"))?;
        let n = file.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.flush(),
            None => Ok(()),
        }
    }
}

fn active_path(dir: &Path, stem: &str) -> PathBuf {
    dir.join(format!("{stem}.log"))
}

fn open_active(dir: &Path, stem: &str) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(active_path(dir, stem))
}

/// A [`MakeWriter`] over a [`RotatingLog`] behind a mutex. The rotation
/// decision is made in `make_writer` — i.e. once per event, before the
/// event's bytes are written — so records are never split across files, and
/// the returned guard holds the lock for the whole event so concurrent
/// events can't interleave their bytes.
pub struct RotatingMakeWriter {
    inner: Mutex<RotatingLog>,
}

impl RotatingMakeWriter {
    pub fn new(log: RotatingLog) -> Self {
        Self {
            inner: Mutex::new(log),
        }
    }
}

impl<'a> MakeWriter<'a> for RotatingMakeWriter {
    type Writer = LockedWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        // Recover from a poisoned lock rather than panicking inside the
        // logging path: a prior panic while formatting an event must not take
        // out all future logging.
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.rotate_if_needed();
        LockedWriter(guard)
    }
}

pub struct LockedWriter<'a>(MutexGuard<'a, RotatingLog>);

impl Write for LockedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// Builds the JSON `tracing` subscriber that writes the rotating service log.
/// Returned rather than installed so callers control global-vs-scoped
/// installation (the SCM path installs it globally; tests use
/// `with_default`).
pub fn file_subscriber(
    config: &ServiceConfig,
) -> io::Result<impl Subscriber + Send + Sync + 'static> {
    let policy = RotationPolicy {
        max_size_bytes: config.log.max_size_bytes,
        keep_files: config.log.keep_files,
    };
    let log = RotatingLog::open(config.log_dir(), crate::config::LOG_STEM, policy)?;
    // An invalid directive shouldn't sink the whole service into log
    // silence; fall back to a sane default and note it.
    let filter = EnvFilter::try_new(&config.log.level).unwrap_or_else(|_| {
        let _ = writeln!(
            io::stderr(),
            "cf-service: invalid log.level {:?}, defaulting to info",
            config.log.level
        );
        EnvFilter::new("info")
    });
    Ok(tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(RotatingMakeWriter::new(log))
        .finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max: u64, keep: usize) -> RotationPolicy {
        RotationPolicy {
            max_size_bytes: max,
            keep_files: keep,
        }
    }

    /// Writes one "record" the way the MakeWriter path does: rotate-check,
    /// then write the bytes. Returns nothing; asserts happen on the files.
    fn write_record(log: &mut RotatingLog, bytes: &[u8]) {
        log.rotate_if_needed();
        log.write_all(bytes).unwrap();
        log.flush().unwrap();
    }

    fn read(path: &Path) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    #[test]
    fn writing_past_the_limit_rotates_the_active_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(10, 3)).unwrap();

        // Each record is 6 bytes; the limit is 10. After the first record the
        // active file is 6 bytes (< 10, no rotation yet). Before the second,
        // 6 >= 10 is false, so still no rotation. Use records that clearly
        // cross the limit.
        write_record(&mut log, b"aaaaaa"); // active = 6
        write_record(&mut log, b"bbbbbb"); // active = 12 (>10 now)
                                           // The next record sees written(12) >= 10 and rotates first.
        write_record(&mut log, b"cccccc");

        let active = dir.path().join("cf-service.log");
        let gen1 = dir.path().join("cf-service.log.1");
        assert!(gen1.exists(), "a rotated generation must exist");
        assert_eq!(
            read(&gen1),
            b"aaaaaabbbbbb",
            "rotated file holds the pre-rotation bytes"
        );
        assert_eq!(
            read(&active),
            b"cccccc",
            "active file restarted after rotation"
        );
    }

    #[test]
    fn active_file_holds_at_most_the_record_that_crossed_the_limit() {
        // The property behind the DoD: the active file is bounded — it never
        // grows without limit, it is reset each time it crosses the size line.
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(100, 5)).unwrap();
        for _ in 0..50 {
            write_record(&mut log, &[b'x'; 30]);
        }
        let active_len = std::fs::metadata(dir.path().join("cf-service.log"))
            .unwrap()
            .len();
        // With a 100-byte limit and 30-byte records, the active file crosses
        // the limit at 120 and rolls on the next record, so it never exceeds
        // limit + one record.
        assert!(
            active_len <= 100 + 30,
            "active file {active_len} exceeded limit + one record"
        );
    }

    #[test]
    fn rotation_preserves_every_byte_across_generations() {
        // No data loss on rotation: with enough kept generations, the ordered
        // concatenation of oldest→newest rotated files plus the active file
        // equals everything ever written.
        let dir = tempfile::tempdir().unwrap();
        let keep = 20usize;
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(10, keep)).unwrap();

        let mut expected = Vec::new();
        for i in 0..10u8 {
            let rec = [b'0' + i; 8];
            expected.extend_from_slice(&rec);
            write_record(&mut log, &rec);
        }

        // Reassemble oldest → newest: highest-numbered generation first, then
        // down to .1, then the active file.
        let mut reassembled = Vec::new();
        for n in (1..=keep).rev() {
            let p = dir.path().join(format!("cf-service.log.{n}"));
            if p.exists() {
                reassembled.extend_from_slice(&read(&p));
            }
        }
        reassembled.extend_from_slice(&read(&dir.path().join("cf-service.log")));
        assert_eq!(
            reassembled, expected,
            "rotation must not drop or reorder bytes"
        );
    }

    #[test]
    fn generations_beyond_keep_files_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(5, 2)).unwrap();
        // Force many rotations.
        for i in 0..10u8 {
            write_record(&mut log, &[b'0' + i; 6]);
        }
        // keep_files = 2 → only .1 and .2 may exist, never .3.
        assert!(dir.path().join("cf-service.log.1").exists());
        assert!(dir.path().join("cf-service.log.2").exists());
        assert!(
            !dir.path().join("cf-service.log.3").exists(),
            "a generation beyond keep_files must never survive"
        );
    }

    #[test]
    fn a_single_record_larger_than_the_limit_is_written_not_infinitely_rotated() {
        // Landmine: if rotation triggered on an *empty* active file it could
        // loop forever on an over-limit record. The `written >= limit` check
        // on a freshly-reset (0-byte) file is false, so the big record is
        // written once, oversize, and accepted.
        let dir = tempfile::tempdir().unwrap();
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(4, 3)).unwrap();
        write_record(&mut log, b"this record is way over the four byte limit");
        let active = read(&dir.path().join("cf-service.log"));
        assert_eq!(active, b"this record is way over the four byte limit");
        // No spurious extra generations from a rotate storm.
        assert!(!dir.path().join("cf-service.log.2").exists());
    }

    #[test]
    fn reopening_seeds_size_from_the_existing_file_so_a_restart_rotates() {
        // Restart safety: a service that restarts onto an already-full log
        // must rotate on its next write, not keep appending forever.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut log = RotatingLog::open(dir.path(), "cf-service", policy(10, 3)).unwrap();
            write_record(&mut log, b"already twelve"); // 14 bytes, > 10
        }
        // Reopen: `written` is seeded to 14, so the very next record rotates.
        let mut log = RotatingLog::open(dir.path(), "cf-service", policy(10, 3)).unwrap();
        write_record(&mut log, b"new");
        assert!(dir.path().join("cf-service.log.1").exists());
        assert_eq!(read(&dir.path().join("cf-service.log")), b"new");
    }

    #[test]
    fn end_to_end_tracing_writes_json_lines_and_rotates() {
        // Prove the wiring: driving the real subscriber writes JSON events to
        // the rotating file and rolls it over under load. Uses a scoped
        // subscriber (no global install) so it can't collide with other tests.
        let dir = tempfile::tempdir().unwrap();
        let log = RotatingLog::open(dir.path(), "cf-service", policy(200, 5)).unwrap();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_env_filter(EnvFilter::new("info"))
            .with_writer(RotatingMakeWriter::new(log))
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            for i in 0..50 {
                tracing::info!(i, "heartbeat");
            }
        });

        // At least one rotation happened and the active file parses as JSON
        // lines.
        assert!(dir.path().join("cf-service.log.1").exists());
        let active = String::from_utf8(read(&dir.path().join("cf-service.log"))).unwrap();
        for line in active.lines().filter(|l| !l.is_empty()) {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|_| panic!("log line is not valid JSON: {line}"));
            assert!(v.get("fields").is_some() || v.get("message").is_some());
        }
    }
}
