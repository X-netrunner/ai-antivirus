//! Exceptions: programs and folders AI Antivirus leaves alone, kept in `engine.exceptions_file`
//! (`/etc/ai-antivirus/exceptions.toml`). Edited with `ai-antivirus exceptions add|remove|reset` (root) or from the
//! Halcyon Security center. Without the file the built-in defaults apply: AI coding tools such as Claude Code and
//! Antigravity, which run shells, download scripts and rewrite many files as part of their normal work.
//!
//! What an exception does (the engine applies it, `ai-antivirus-engined/src/engine.rs`):
//! - **program**: behavior alerts about the program, and about everything it starts, are dropped. Malware found in a
//!   file (hash or YARA) is still reported, but only as a notification: nothing is quarantined or killed.
//! - **folder**: files in the folder are not scanned automatically and alerts about them are dropped; programs that
//!   run from the folder count as program exceptions.
//!
//! Some alerts are never dropped (`NEVER_EXCEPTED_RULES`, and the engine's self-protection): writes to
//! `/etc/ld.so.preload` and to AI Antivirus's own files.
//!
//! Matching:
//! - a **name** (no `/`), such as `claude`, matches a program whose file is called that, a program installed in a
//!   folder of that name (`~/.local/share/claude/versions/2.1.3`, `/opt/cursor/cursor`), or a script run by an
//!   interpreter (`node /usr/bin/gemini`). Case does not matter. A name never matches a file in a temporary or
//!   download folder (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `~/Downloads`), so a copy dropped there and named
//!   `claude` is not excepted.
//! - a **path** starts with `/` or `~/` (`~` is every home folder). `*` matches within one folder name, `**` any
//!   number of folders. A program path must match the whole executable (or script) path; a folder matches itself and
//!   everything below it.
//!
//! Exceptions that would switch the antivirus off for most of the system are refused: shells and interpreters,
//! `sudo` and friends, and folders such as `/usr/bin`, a whole home folder, `~/Downloads` or `/tmp`.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const DEFAULT_EXCEPTIONS_PATH: &str = "/etc/ai-antivirus/exceptions.toml";

/// Rules whose alerts no exception can drop.
pub const NEVER_EXCEPTED_RULES: &[&str] = &["AV-B-0004", "AV-B-0020"];

const MAX_PATTERN: usize = 256;
const MAX_NAME: usize = 80;
const MAX_ENTRIES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Program,
    Folder,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Program => "program",
            Kind::Folder => "folder",
        }
    }
}

impl std::str::FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Kind, String> {
        match s {
            "program" | "app" | "tool" => Ok(Kind::Program),
            "folder" | "dir" | "path" => Ok(Kind::Folder),
            _ => Err(format!("unknown kind {s:?} (program or folder)")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub kind: Kind,
    /// A program name or a path pattern (see the module docs).
    #[serde(rename = "match")]
    pub pattern: String,
    /// What it is, for people ("Claude Code").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
}

impl Exception {
    pub fn program(pattern: &str, name: &str) -> Exception {
        Exception {
            kind: Kind::Program,
            pattern: pattern.to_owned(),
            name: name.to_owned(),
        }
    }

    pub fn folder(pattern: &str, name: &str) -> Exception {
        Exception {
            kind: Kind::Folder,
            pattern: pattern.to_owned(),
            name: name.to_owned(),
        }
    }

    /// The name, or the pattern when there is none.
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.pattern
        } else {
            &self.name
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExceptionsFile {
    #[serde(default)]
    exception: Vec<Exception>,
}

/// The built-in list, used while no exceptions file exists.
pub fn defaults() -> Vec<Exception> {
    [
        ("claude", "Claude Code"),
        ("agy", "Antigravity CLI"),
        ("antigravity", "Antigravity"),
        ("gemini", "Gemini CLI"),
        ("codex", "OpenAI Codex CLI"),
        ("cursor-agent", "Cursor CLI"),
        ("cursor", "Cursor"),
        ("windsurf", "Windsurf"),
        ("aider", "Aider"),
        ("opencode", "OpenCode"),
        ("copilot", "GitHub Copilot CLI"),
        ("goose", "Goose"),
    ]
    .into_iter()
    .map(|(p, n)| Exception::program(p, n))
    .collect()
}

/// Parse an exceptions file. Every entry is validated; one bad entry rejects the file.
pub fn parse(text: &str) -> Result<Vec<Exception>, String> {
    let f: ExceptionsFile = toml::from_str(text).map_err(|e| e.to_string())?;
    if f.exception.len() > MAX_ENTRIES {
        return Err(format!("more than {MAX_ENTRIES} exceptions"));
    }
    for e in &f.exception {
        validate(e).map_err(|m| format!("{:?}: {m}", e.pattern))?;
    }
    Ok(f.exception)
}

/// The list in `path` and whether it came from the file (`false`: there is no file, these are the defaults).
pub fn load(path: &Path) -> Result<(Vec<Exception>, bool), String> {
    match std::fs::read_to_string(path) {
        Ok(text) => parse(&text)
            .map(|l| (l, true))
            .map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((defaults(), false)),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub fn to_toml(list: &[Exception]) -> Result<String, String> {
    let body = toml::to_string(&ExceptionsFile {
        exception: list.to_vec(),
    })
    .map_err(|e| e.to_string())?;
    Ok(format!(
        "# AI Antivirus exceptions: programs and folders it leaves alone.\n\
         # Managed by `ai-antivirus exceptions` and the Halcyon Security center; delete this file for the defaults.\n\
         # kind = 'program': a name (claude) or a path (~/.local/bin/tool, /opt/app/*); kind = 'folder': a path.\n\n{body}"
    ))
}

/// Write the list atomically (temporary file + rename), mode 0644: the engine and the Security center read it.
pub fn save(path: &Path, list: &[Exception]) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt;
    for e in list {
        validate(e).map_err(|m| format!("{:?}: {m}", e.pattern))?;
    }
    let text = to_toml(list)?;
    let dir = path
        .parent()
        .ok_or_else(|| format!("{}: no parent folder", path.display()))?;
    let tmp = dir.join(format!(".exceptions.{}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    };
    write().map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", path.display())
    })
}

/// Programs that would except nearly everything: every script runs under one of them.
const BROAD_PROGRAMS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "nu",
    "node",
    "nodejs",
    "bun",
    "deno",
    "python",
    "python2",
    "python3",
    "pypy",
    "pypy3",
    "perl",
    "ruby",
    "php",
    "lua",
    "java",
    "env",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "run0",
    "systemd",
    "init",
    "sshd",
    "ssh",
    "busybox",
    "xargs",
    "nohup",
    "setsid",
    "timeout",
    "nice",
    "strace",
    "gdb",
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "kitty",
    "alacritty",
    "foot",
    "konsole",
    "wezterm",
    "ghostty",
    "gnome-terminal-server",
    "tmux",
    "screen",
    "hyprland",
    "sway",
];

/// Folders no exception may cover: system programs, whole homes, and the places downloads and droppers land.
const PROTECTED_PROBES: &[&str] = &[
    "/usr/bin/x",
    "/usr/sbin/x",
    "/usr/lib/x",
    "/usr/lib64/x",
    "/usr/local/bin/x",
    "/usr/local/sbin/x",
    "/bin/x",
    "/sbin/x",
    "/lib/x",
    "/etc/x",
    "/boot/x",
    "/var/x",
    "/opt/x",
    "/home/user/x",
    "/root/x",
    "/tmp/x",
    "/var/tmp/x",
    "/dev/shm/x",
    "/run/x",
    "/run/user/1000/x",
    "/home/user/Downloads/x",
    "/home/user/.config/x",
    "/home/user/.config/autostart/x",
    "/home/user/.config/systemd/x",
    "/home/user/.local/bin/x",
    "/home/user/.local/share/x",
    "/home/user/.ssh/x",
    "/home/user/.cache/x",
];

fn is_name(pattern: &str) -> bool {
    !pattern.contains('/')
}

/// Check one exception: length, characters, and that it is not so broad that it switches the antivirus off.
pub fn validate(e: &Exception) -> Result<(), String> {
    let p = e.pattern.as_str();
    if p.is_empty() {
        return Err("empty".into());
    }
    if p.len() > MAX_PATTERN {
        return Err(format!("longer than {MAX_PATTERN} characters"));
    }
    if e.name.chars().count() > MAX_NAME {
        return Err(format!("name longer than {MAX_NAME} characters"));
    }
    if p.chars().any(char::is_control) || e.name.chars().any(char::is_control) {
        return Err("control characters".into());
    }
    if p.trim() != p {
        return Err("leading or trailing spaces".into());
    }
    let pat = Pattern::parse(p)?;
    match (&pat, e.kind) {
        (Pattern::Name(_), Kind::Folder) => {
            return Err("a folder must start with / or ~/".into());
        }
        (Pattern::Name(n), Kind::Program) => {
            if n.iter().all(|b| matches!(b, b'*' | b'?' | b'.')) {
                return Err("matches every program".into());
            }
            if let Some(b) = BROAD_PROGRAMS.iter().find(|b| wild(n, b.as_bytes())) {
                return Err(format!(
                    "matches {b}, which runs almost everything: except the tool itself instead"
                ));
            }
            if wild(n, b"python3.12")
                || wild(n, b"ai-antivirus")
                || wild(n, b"ai-antivirus-engined")
            {
                return Err("too broad".into());
            }
        }
        (Pattern::Path(segs), kind) => {
            let real = segs.iter().filter(|s| matches!(s, Seg::Lit(_))).count();
            if real == 0 {
                return Err("matches every path".into());
            }
            for probe in PROTECTED_PROBES {
                let probe_segs = split(probe.as_bytes());
                // a folder covering the probe, or a program pattern matching programs in it
                let hit = match kind {
                    Kind::Folder => match_segs(segs, &probe_segs, true),
                    Kind::Program => {
                        match_segs(segs, &probe_segs, false)
                            || BROAD_PROGRAMS.iter().any(|b| {
                                let mut s = probe_segs.clone();
                                s.pop();
                                s.push(b.as_bytes());
                                match_segs(segs, &s, false)
                            })
                    }
                };
                if hit {
                    let shown = probe.trim_end_matches("/x").replace("/home/user", "~");
                    return Err(format!("covers {shown}, which must stay protected"));
                }
            }
            if p.contains("ai-antivirus") {
                return Err("AI Antivirus's own files cannot be excepted".into());
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Seg {
    /// `~`: `/home/<anyone>` or `/root`
    Home,
    /// `**`: any number of folders
    Any,
    /// one folder name, with `*` and `?` wildcards
    Lit(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    /// lower-case program name
    Name(Vec<u8>),
    Path(Vec<Seg>),
}

impl Pattern {
    fn parse(p: &str) -> Result<Pattern, String> {
        if is_name(p) {
            return Ok(Pattern::Name(p.to_ascii_lowercase().into_bytes()));
        }
        let (home, rest) = if p == "~" {
            (true, "")
        } else if let Some(r) = p.strip_prefix("~/") {
            (true, r)
        } else if let Some(r) = p.strip_prefix('/') {
            (false, r)
        } else {
            return Err("a path must start with / or ~/".into());
        };
        let mut segs = Vec::new();
        if home {
            segs.push(Seg::Home);
        }
        for s in rest.split('/').filter(|s| !s.is_empty()) {
            match s {
                "." | ".." => return Err("no . or .. in paths".into()),
                "**" => segs.push(Seg::Any),
                s => segs.push(Seg::Lit(s.as_bytes().to_vec())),
            }
        }
        Ok(Pattern::Path(segs))
    }
}

fn split(p: &[u8]) -> Vec<&[u8]> {
    p.split(|b| *b == b'/').filter(|s| !s.is_empty()).collect()
}

/// `*` (any run of bytes) and `?` (one byte) wildcards, whole string.
fn wild(p: &[u8], s: &[u8]) -> bool {
    let (mut pi, mut si) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = si;
            pi += 1;
        } else if let Some(st) = star {
            pi = st + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|b| *b == b'*')
}

/// Does `pat` match `path` (all of it, or with `prefix`, its start)?
fn match_segs(pat: &[Seg], path: &[&[u8]], prefix: bool) -> bool {
    let Some((first, rest)) = pat.split_first() else {
        return prefix || path.is_empty();
    };
    match first {
        Seg::Home => match path {
            [h, _, tail @ ..] if *h == b"home" && match_segs(rest, tail, prefix) => true,
            [r, tail @ ..] if *r == b"root" => match_segs(rest, tail, prefix),
            _ => false,
        },
        Seg::Any => (0..=path.len()).any(|i| match_segs(rest, &path[i..], prefix)),
        Seg::Lit(l) => match path.split_first() {
            Some((p, tail)) => wild(l, p) && match_segs(rest, tail, prefix),
            None => false,
        },
    }
}

fn base(p: &[u8]) -> &[u8] {
    p.rsplit(|b| *b == b'/').next().unwrap_or(p)
}

/// Programs that run a script named by their first argument.
fn is_interpreter(name: &[u8]) -> bool {
    const I: &[&[u8]] = &[
        b"node", b"nodejs", b"bun", b"deno", b"perl", b"ruby", b"sh", b"bash", b"zsh", b"dash",
        b"fish", b"php", b"lua",
    ];
    I.contains(&name) || name.starts_with(b"python") || name.starts_with(b"pypy")
}

/// Temporary and download folders: a name never matches a file there.
fn untrusted_place(segs: &[&[u8]]) -> bool {
    match segs {
        [t, ..] if *t == b"tmp" => true,
        [v, t, ..] if *v == b"var" && *t == b"tmp" => true,
        [d, s, ..] if *d == b"dev" && *s == b"shm" => true,
        [r, u, ..] if *r == b"run" && *u == b"user" => true,
        [h, _, d, ..] if *h == b"home" && *d == b"Downloads" => true,
        [r, d, ..] if *r == b"root" && *d == b"Downloads" => true,
        _ => false,
    }
}

/// The names a file answers to: its own name, and the folder it is installed in (the one under `share`, `lib`,
/// `libexec` or `opt`), lower case.
fn names_of(path: &[u8]) -> Vec<Vec<u8>> {
    let segs = split(path);
    if segs.is_empty() || untrusted_place(&segs) {
        return Vec::new();
    }
    let mut out = vec![base(path).to_ascii_lowercase()];
    for w in segs.windows(2).take(segs.len().saturating_sub(2)) {
        if matches!(w[0], b"share" | b"lib" | b"lib64" | b"libexec" | b"opt") {
            out.push(w[1].to_ascii_lowercase());
        }
    }
    out
}

/// The exceptions, ready for matching.
#[derive(Debug, Clone, Default)]
pub struct Matcher {
    list: Vec<Exception>,
    pats: Vec<Pattern>,
}

impl Matcher {
    /// Entries that do not validate are left out (the file was checked when it was written; this is a second guard).
    pub fn new(list: Vec<Exception>) -> Matcher {
        let mut keep = Vec::new();
        let mut pats = Vec::new();
        for e in list {
            if validate(&e).is_err() {
                continue;
            }
            if let Ok(p) = Pattern::parse(&e.pattern) {
                keep.push(e);
                pats.push(p);
            }
        }
        Matcher { list: keep, pats }
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn get(&self, i: usize) -> Option<&Exception> {
        self.list.get(i)
    }

    /// The folder exception covering `path`, if any.
    pub fn folder(&self, path: &Path) -> Option<usize> {
        let segs = split(path.as_os_str().as_bytes());
        self.list.iter().zip(&self.pats).position(|(e, p)| {
            e.kind == Kind::Folder && matches!(p, Pattern::Path(s) if match_segs(s, &segs, true))
        })
    }

    /// The exception matching a process (its executable and arguments), if any.
    pub fn program(&self, exe: &Path, argv: &[OsString]) -> Option<usize> {
        if self.list.is_empty() {
            return None;
        }
        let exe_b = exe.as_os_str().as_bytes();
        // the script an interpreter runs: `node /usr/bin/gemini`, `python3 /usr/bin/aider`
        let script: Option<&[u8]> = (is_interpreter(base(exe_b))
            || argv
                .first()
                .is_some_and(|a| is_interpreter(base(a.as_bytes()))))
        .then(|| argv.get(1).map(|a| a.as_bytes()))
        .flatten()
        .filter(|a| !a.is_empty() && !a.starts_with(b"-"));
        let mut files: Vec<&[u8]> = Vec::with_capacity(2);
        if !exe_b.is_empty() {
            files.push(exe_b);
        }
        files.extend(script);
        let names: Vec<Vec<u8>> = files.iter().flat_map(|f| names_of(f)).collect();
        let segs: Vec<Vec<&[u8]>> = files.iter().map(|f| split(f)).collect();
        self.list.iter().zip(&self.pats).position(|(e, p)| match p {
            Pattern::Name(n) => e.kind == Kind::Program && names.iter().any(|x| wild(n, x)),
            Pattern::Path(s) => {
                let prefix = e.kind == Kind::Folder;
                // a script path must be absolute to be matched against a path pattern
                segs.iter()
                    .zip(&files)
                    .any(|(seg, f)| f.starts_with(b"/") && match_segs(s, seg, prefix))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<OsString> {
        a.iter().map(OsString::from).collect()
    }

    fn m() -> Matcher {
        Matcher::new(defaults())
    }

    #[test]
    fn the_defaults_validate_and_cover_the_usual_installs() {
        for e in defaults() {
            validate(&e).unwrap();
        }
        let m = m();
        assert_eq!(m.len(), defaults().len());
        // Claude Code, native install: the file is the version number, the folder is the name
        let claude = Path::new("/home/u/.local/share/claude/versions/2.1.310");
        assert!(m.program(claude, &argv(&["claude"])).is_some());
        assert!(m
            .program(Path::new("/usr/bin/agy"), &argv(&["agy"]))
            .is_some());
        // npm scripts run by node
        let g = m.program(
            Path::new("/usr/bin/node"),
            &argv(&["node", "/usr/bin/gemini", "-p"]),
        );
        assert_eq!(m.get(g.unwrap()).unwrap().pattern, "gemini");
        assert!(m
            .program(
                Path::new("/usr/bin/node"),
                &argv(&["node", "/usr/lib/node_modules/x/claude"])
            )
            .is_some());
        // an app installed under /opt or /usr/share
        assert!(m
            .program(Path::new("/opt/Antigravity/antigravity"), &argv(&["x"]))
            .is_some());
        assert!(m
            .program(Path::new("/usr/share/cursor/cursor"), &argv(&["x"]))
            .is_some());
        // python tools
        assert!(m
            .program(
                Path::new("/usr/bin/python3.13"),
                &argv(&["/usr/bin/python3", "/usr/bin/aider"])
            )
            .is_some());
    }

    #[test]
    fn ordinary_programs_and_lookalikes_are_not_excepted() {
        let m = m();
        assert!(m
            .program(Path::new("/usr/bin/bash"), &argv(&["bash"]))
            .is_none());
        assert!(m
            .program(Path::new("/usr/bin/node"), &argv(&["node", "server.js"]))
            .is_none());
        // argv[0] alone is not trusted
        assert!(m
            .program(Path::new("/usr/bin/python3"), &argv(&["claude"]))
            .is_none());
        // a copy named after a tool, in a temporary or download folder
        assert!(m
            .program(Path::new("/tmp/claude"), &argv(&["claude"]))
            .is_none());
        assert!(m
            .program(Path::new("/dev/shm/x/agy"), &argv(&["agy"]))
            .is_none());
        assert!(m
            .program(Path::new("/home/u/Downloads/codex"), &argv(&["codex"]))
            .is_none());
        assert!(m
            .program(Path::new("/usr/bin/bash"), &argv(&["bash", "/tmp/claude"]))
            .is_none());
        // `bash -c claude` runs a command line, not a script called claude
        assert!(m
            .program(Path::new("/usr/bin/bash"), &argv(&["bash", "-c", "claude"]))
            .is_none());
        // a folder named like a tool, but not an install folder
        assert!(m
            .program(Path::new("/home/u/src/claude/run"), &argv(&["run"]))
            .is_none());
    }

    #[test]
    fn paths_folders_and_wildcards() {
        let m = Matcher::new(vec![
            Exception::program("~/tools/bin/my-agent", "agent"),
            Exception::program("/opt/vendor/*/bin/run*", ""),
            Exception::folder("~/Projects/malware-samples", "samples"),
            Exception::folder("/srv/**/cache", ""),
        ]);
        assert!(m
            .program(Path::new("/home/a/tools/bin/my-agent"), &[])
            .is_some());
        assert!(m
            .program(Path::new("/root/tools/bin/my-agent"), &[])
            .is_some());
        assert!(m
            .program(Path::new("/home/a/tools/bin/my-agent2"), &[])
            .is_none());
        assert!(m
            .program(Path::new("/opt/vendor/x1/bin/runner"), &[])
            .is_some());
        assert!(m
            .program(Path::new("/opt/vendor/x1/y/bin/runner"), &[])
            .is_none());
        let s = Path::new("/home/a/Projects/malware-samples/x/eicar.com");
        assert_eq!(m.folder(s), Some(2));
        assert_eq!(
            m.folder(Path::new("/home/a/Projects/malware-samples")),
            Some(2)
        );
        assert_eq!(
            m.folder(Path::new("/home/a/Projects/malware-samples2/x")),
            None
        );
        assert_eq!(m.folder(Path::new("/srv/a/b/cache/f")), Some(3));
        assert_eq!(m.folder(Path::new("/srv/cache/f")), Some(3));
        // a program in an excepted folder is excepted
        assert_eq!(m.program(&s.join("run"), &[]), Some(2));
        // but a folder exception does not make folder names count as program names
        assert_eq!(m.folder(Path::new("/home/a/tools/bin/my-agent")), None);
    }

    #[test]
    fn exceptions_that_would_switch_the_antivirus_off_are_refused() {
        for (kind, p) in [
            (Kind::Program, "bash"),
            (Kind::Program, "python3"),
            (Kind::Program, "py*"),
            (Kind::Program, "*"),
            (Kind::Program, "su*"),
            (Kind::Program, "/usr/bin/*"),
            (Kind::Program, "/usr/bin/bash"),
            (Kind::Program, "/**"),
            (Kind::Folder, "/"),
            (Kind::Folder, "~"),
            (Kind::Folder, "~/"),
            (Kind::Folder, "/usr"),
            (Kind::Folder, "/usr/bin"),
            (Kind::Folder, "/home/*"),
            (Kind::Folder, "~/Downloads"),
            (Kind::Folder, "~/.config"),
            (Kind::Folder, "/tmp"),
            (Kind::Folder, "/**/x"),
            (Kind::Folder, "claude"),
            (Kind::Folder, "~/../etc"),
            (Kind::Program, "relative/path"),
            (Kind::Program, ""),
            (Kind::Program, " claude"),
            (Kind::Program, "a\nb"),
            (Kind::Program, "ai-antivirus"),
        ] {
            let e = Exception {
                kind,
                pattern: p.into(),
                name: String::new(),
            };
            assert!(validate(&e).is_err(), "{kind:?} {p:?} was accepted");
        }
        for (kind, p) in [
            (Kind::Program, "claude"),
            (Kind::Program, "my-tool"),
            (Kind::Program, "~/.local/share/claude/versions/*"),
            (Kind::Program, "~/.local/bin/my-agent"),
            (Kind::Folder, "~/Projects/samples"),
            (Kind::Folder, "~/.local/share/Steam/steamapps"),
            (Kind::Folder, "/opt/myapp"),
        ] {
            let e = Exception {
                kind,
                pattern: p.into(),
                name: String::new(),
            };
            assert!(
                validate(&e).is_ok(),
                "{kind:?} {p:?} was refused: {:?}",
                validate(&e)
            );
        }
    }

    #[test]
    fn files_round_trip_and_bad_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("exceptions.toml");
        let (l, from_file) = load(&f).unwrap();
        assert!(!from_file);
        assert_eq!(l, defaults());
        let mut l = l;
        l.retain(|e| e.pattern != "cursor");
        l.push(Exception::folder("~/samples", "Samples"));
        save(&f, &l).unwrap();
        let (back, from_file) = load(&f).unwrap();
        assert!(from_file);
        assert_eq!(back, l);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o644
        );
        // an empty file is an empty list, not the defaults
        std::fs::write(&f, "").unwrap();
        assert!(load(&f).unwrap().0.is_empty());
        std::fs::write(&f, "[[exception]]\nkind = 'program'\nmatch = 'bash'\n").unwrap();
        assert!(load(&f).is_err());
        std::fs::write(
            &f,
            "[[exception]]\nkind = 'program'\nmatch = 'x'\nextra = 1\n",
        )
        .unwrap();
        assert!(load(&f).is_err());
    }

    #[test]
    fn wildcards() {
        assert!(wild(b"*", b""));
        assert!(wild(b"a*c", b"abbbc"));
        assert!(wild(b"a?c", b"abc"));
        assert!(!wild(b"a?c", b"ac"));
        assert!(wild(b"*.py", b"x.py"));
        assert!(!wild(b"claude", b"claude2"));
    }
}
