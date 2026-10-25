//! The JSONL event log: one serialized [`Envelope`] per line.
//!
//! * [`EventLogWriter`] appends lines to `<log_dir>/events.jsonl` and rotates
//!   it by size (`events.jsonl.1` is the newest rotated file).
//! * [`last_lines`] and [`Follower`] read it back for `ai-antivirus tail`.
//!
//! The file is created with mode 0640 and opened with `O_NOFOLLOW`, so a
//! symlink planted at the log path is refused instead of followed. Each event
//! is written with a single `write` call so readers normally see whole lines;
//! readers still tolerate a partial or corrupt line, because a full disk can
//! leave one behind.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::event::Envelope;

/// File name of the live log inside the log directory.
pub const EVENT_LOG_NAME: &str = "events.jsonl";

const LOG_FILE_MODE: u32 = 0o640;
const LOG_DIR_MODE: u32 = 0o750;
/// `last_lines` never reads more than this from the end of the file.
const MAX_TAIL_BYTES: u64 = 8 * 1024 * 1024;
/// A follower reads at most this much per `poll` call.
const MAX_READ_PER_POLL: u64 = 16 * 1024 * 1024;
/// An unterminated line longer than this is garbage and is discarded.
const MAX_PENDING_LINE: usize = 4 * 1024 * 1024;

/// Path of the live log inside `dir`.
pub fn log_path(dir: &Path) -> PathBuf {
    dir.join(EVENT_LOG_NAME)
}

fn rotated_path(dir: &Path, n: u32) -> PathBuf {
    dir.join(format!("{EVENT_LOG_NAME}.{n}"))
}

fn open_log(dir: &Path) -> Result<(File, u64)> {
    let path = log_path(dir);
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(LOG_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|e| Error::io(&path, e))?;
    let meta = file.metadata().map_err(|e| Error::io(&path, e))?;
    if !meta.is_file() {
        return Err(Error::io(
            &path,
            io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"),
        ));
    }
    Ok((file, meta.len()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(path, e)),
    }
}

fn rename_if_exists(from: &Path, to: &Path) -> Result<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(from, e)),
    }
}

/// Appends events to the live log and rotates it by size.
#[derive(Debug)]
pub struct EventLogWriter {
    dir: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
    keep: u32,
}

impl EventLogWriter {
    /// Create `dir` (mode 0750) if needed and open the live log for appending.
    /// `keep` is the number of rotated files retained (at least 1).
    pub fn open(dir: &Path, max_bytes: u64, keep: u32) -> Result<EventLogWriter> {
        DirBuilder::new()
            .recursive(true)
            .mode(LOG_DIR_MODE)
            .create(dir)
            .map_err(|e| Error::io(dir, e))?;
        let (file, size) = open_log(dir)?;
        Ok(EventLogWriter {
            dir: dir.to_path_buf(),
            file,
            size,
            max_bytes: max_bytes.max(1),
            keep: keep.max(1),
        })
    }

    /// Serialize and append one event, rotating afterwards if the file is full.
    pub fn append(&mut self, envelope: &Envelope) -> Result<()> {
        let mut line = serde_json::to_vec(envelope)?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(|e| Error::io(log_path(&self.dir), e))?;
        self.size = self
            .size
            .saturating_add(u64::try_from(line.len()).unwrap_or(u64::MAX));
        if self.size >= self.max_bytes {
            self.rotate()?;
        }
        Ok(())
    }

    /// Size in bytes of the live log (as tracked by this writer).
    pub fn size(&self) -> u64 {
        self.size
    }

    fn rotate(&mut self) -> Result<()> {
        remove_if_exists(&rotated_path(&self.dir, self.keep))?;
        for n in (1..self.keep).rev() {
            rename_if_exists(&rotated_path(&self.dir, n), &rotated_path(&self.dir, n + 1))?;
        }
        rename_if_exists(&log_path(&self.dir), &rotated_path(&self.dir, 1))?;
        let (file, size) = open_log(&self.dir)?;
        self.file = file;
        self.size = size;
        Ok(())
    }
}

/// The last `n` complete lines of the log at `path` (oldest first).
///
/// Looks at no more than the final 8 MiB. A missing file is an empty log.
/// Rotated files are not consulted.
pub fn last_lines(path: &Path, n: usize) -> Result<Vec<Vec<u8>>> {
    if n == 0 {
        return Ok(Vec::new());
    }
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(path, e)),
    };
    let len = file.metadata().map_err(|e| Error::io(path, e))?.len();
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))
        .map_err(|e| Error::io(path, e))?;
    let mut buf = Vec::new();
    file.take(MAX_TAIL_BYTES)
        .read_to_end(&mut buf)
        .map_err(|e| Error::io(path, e))?;

    let mut slice: &[u8] = &buf;
    if start > 0 {
        // We began mid-file, so the first line is probably cut off: skip it.
        slice = match slice.iter().position(|b| *b == b'\n') {
            Some(i) => slice.get(i + 1..).unwrap_or(&[]),
            None => &[],
        };
    }
    // Drop a trailing incomplete line.
    slice = match slice.iter().rposition(|b| *b == b'\n') {
        Some(i) => slice.get(..i).unwrap_or(&[]),
        None => &[],
    };
    let mut lines: Vec<Vec<u8>> = slice
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(<[u8]>::to_vec)
        .collect();
    if lines.len() > n {
        lines = lines.split_off(lines.len() - n);
    }
    Ok(lines)
}

/// Follows a log file the way `tail -F` does: it survives rotation and
/// truncation and waits for the file to appear.
#[derive(Debug)]
pub struct Follower {
    path: PathBuf,
    file: Option<File>,
    id: Option<(u64, u64)>,
    pending: Vec<u8>,
}

fn file_id(meta: &fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

impl Follower {
    /// Start following at the current end of the file (or at its creation if
    /// it does not exist yet).
    pub fn from_end(path: &Path) -> Result<Follower> {
        let mut follower = Follower {
            path: path.to_path_buf(),
            file: None,
            id: None,
            pending: Vec::new(),
        };
        match File::open(path) {
            Ok(mut file) => {
                let meta = file.metadata().map_err(|e| Error::io(path, e))?;
                file.seek(SeekFrom::End(0))
                    .map_err(|e| Error::io(path, e))?;
                follower.id = Some(file_id(&meta));
                follower.file = Some(file);
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(path, e)),
        }
        Ok(follower)
    }

    /// Return the complete lines appended since the last call.
    pub fn poll(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut lines = Vec::new();
        // At most two rounds: drain the file we hold, then (if the path now
        // names a different file) drain the new one from its start.
        for _ in 0..2 {
            self.drain_current(&mut lines)?;
            match fs::metadata(&self.path) {
                Ok(meta) => {
                    if self.id == Some(file_id(&meta)) {
                        break;
                    }
                    let file = File::open(&self.path).map_err(|e| Error::io(&self.path, e))?;
                    let opened = file.metadata().map_err(|e| Error::io(&self.path, e))?;
                    self.id = Some(file_id(&opened));
                    self.file = Some(file);
                    self.pending.clear();
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => break,
                Err(e) => return Err(Error::io(&self.path, e)),
            }
        }
        Ok(lines)
    }

    fn drain_current(&mut self, lines: &mut Vec<Vec<u8>>) -> Result<()> {
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        let path = &self.path;

        // Truncation in place (copytruncate style): start over from the top.
        let pos = file.stream_position().map_err(|e| Error::io(path, e))?;
        let len = file.metadata().map_err(|e| Error::io(path, e))?.len();
        if len < pos {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Error::io(path, e))?;
            self.pending.clear();
        }

        let mut chunk = Vec::new();
        Read::take(&mut *file, MAX_READ_PER_POLL)
            .read_to_end(&mut chunk)
            .map_err(|e| Error::io(path, e))?;
        self.pending.extend_from_slice(&chunk);

        let mut start = 0usize;
        while let Some(rel) = self
            .pending
            .get(start..)
            .and_then(|s| s.iter().position(|b| *b == b'\n'))
        {
            let end = start + rel;
            if let Some(line) = self.pending.get(start..end) {
                if !line.is_empty() {
                    lines.push(line.to_vec());
                }
            }
            start = end + 1;
        }
        self.pending = self.pending.split_off(start);
        if self.pending.len() > MAX_PENDING_LINE {
            self.pending.clear();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::sample_envelope;
    use std::os::unix::fs::PermissionsExt;

    fn line_len() -> u64 {
        let json = serde_json::to_vec(&sample_envelope(1, 1_700_000_000_000_000_000)).unwrap();
        u64::try_from(json.len()).unwrap() + 1
    }

    fn envelope(seq: u64) -> Envelope {
        sample_envelope(seq, 1_700_000_000_000_000_000)
    }

    #[test]
    fn writes_one_parsable_line_per_event_with_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path().join("logs");
        let mut w = EventLogWriter::open(&logs, 1 << 20, 3).unwrap();
        w.append(&envelope(1)).unwrap();
        w.append(&envelope(2)).unwrap();

        let text = fs::read_to_string(log_path(&logs)).unwrap();
        let seqs: Vec<u64> = text
            .lines()
            .map(|l| serde_json::from_str::<Envelope>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![1, 2]);
        assert_eq!(w.size(), u64::try_from(text.len()).unwrap());

        let file_mode = fs::metadata(log_path(&logs)).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode & 0o007, 0, "log must not be world accessible");
        let dir_mode = fs::metadata(&logs).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode & 0o007, 0, "log dir must not be world accessible");
    }

    #[test]
    fn refuses_a_symlinked_log() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, log_path(dir.path())).unwrap();
        assert!(EventLogWriter::open(dir.path(), 1 << 20, 3).is_err());
    }

    #[test]
    fn rotation_keeps_the_configured_number_of_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = EventLogWriter::open(dir.path(), line_len() * 2, 2).unwrap();
        for seq in 1..=9 {
            w.append(&envelope(seq)).unwrap();
        }
        assert!(log_path(dir.path()).exists());
        assert!(rotated_path(dir.path(), 1).exists());
        assert!(rotated_path(dir.path(), 2).exists());
        assert!(!rotated_path(dir.path(), 3).exists());

        // The newest rotated file holds the most recent full file's lines.
        let newest = fs::read_to_string(rotated_path(dir.path(), 1)).unwrap();
        let seqs: Vec<u64> = newest
            .lines()
            .map(|l| serde_json::from_str::<Envelope>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![7, 8]);
    }

    #[test]
    fn last_lines_returns_the_tail_and_ignores_a_partial_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        assert!(last_lines(&path, 5).unwrap().is_empty(), "missing file");

        fs::write(&path, b"one\ntwo\nthree\nfour-incompl").unwrap();
        let lines = last_lines(&path, 2).unwrap();
        assert_eq!(lines, vec![b"two".to_vec(), b"three".to_vec()]);
        assert_eq!(last_lines(&path, 10).unwrap().len(), 3);
        assert!(last_lines(&path, 0).unwrap().is_empty());
    }

    #[test]
    fn follower_sees_only_new_lines_and_joins_split_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        fs::write(&path, b"old\n").unwrap();

        let mut f = Follower::from_end(&path).unwrap();
        assert!(f.poll().unwrap().is_empty());

        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"new1\nnew2-par").unwrap();
        assert_eq!(f.poll().unwrap(), vec![b"new1".to_vec()]);
        file.write_all(b"tial\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec![b"new2-partial".to_vec()]);
    }

    #[test]
    fn follower_waits_for_a_file_that_does_not_exist_yet() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        let mut f = Follower::from_end(&path).unwrap();
        assert!(f.poll().unwrap().is_empty());
        fs::write(&path, b"first\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec![b"first".to_vec()]);
    }

    #[test]
    fn follower_loses_nothing_across_one_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        // Rotates after the 3rd append, so 5 events span two files.
        let mut w = EventLogWriter::open(dir.path(), line_len() * 3, 2).unwrap();
        let mut f = Follower::from_end(&path).unwrap();
        for seq in 1..=5 {
            w.append(&envelope(seq)).unwrap();
        }
        let seqs: Vec<u64> = f
            .poll()
            .unwrap()
            .iter()
            .map(|l| serde_json::from_slice::<Envelope>(l).unwrap().seq)
            .collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        assert!(f.poll().unwrap().is_empty());
    }

    #[test]
    fn follower_restarts_after_in_place_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = log_path(dir.path());
        fs::write(&path, b"aaaa\nbbbb\n").unwrap();
        let mut f = Follower::from_end(&path).unwrap();
        // Truncate the same file and write something shorter than before.
        fs::write(&path, b"c\n").unwrap();
        assert_eq!(f.poll().unwrap(), vec![b"c".to_vec()]);
    }
}
