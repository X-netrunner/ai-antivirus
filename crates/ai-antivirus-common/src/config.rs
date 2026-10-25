//! Configuration: TOML on disk, strict parsing, collected validation errors.
//!
//! Every section is optional and falls back to the defaults below. Unknown keys
//! are errors, so a typo in a security setting can never be silently ignored.

use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::error::{Error, Result};
use crate::model::Severity;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/ai-antivirus/ai-antivirus.toml";
const MAX_CONFIG_BYTES: u64 = 1 << 20;
const PLACEHOLDER_MODEL: &str = "set-your-local-model";
const DB_FILE_NAME: &str = "ai-antivirus.db";

/// Enforcement ladder (spec section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Log and notify only (levels 0 to 1). The default.
    AlertOnly,
    /// Adds freeze and kill (levels 0 to 3).
    Contain,
    /// Adds quarantine, network block and restore (levels 0 to 6), approved rules only.
    Enforce,
}

impl Mode {
    /// Highest response level this mode may ever execute.
    pub fn max_level(self) -> u8 {
        match self {
            Mode::AlertOnly => 1,
            Mode::Contain => 3,
            Mode::Enforce => 6,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::AlertOnly => "alert-only",
            Mode::Contain => "contain",
            Mode::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GeneralConfig {
    pub mode: Mode,
    pub retention_days: u32,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            mode: Mode::AlertOnly,
            retention_days: 14,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SensorsConfig {
    /// One path per filesystem to watch. fanotify marks the whole filesystem
    /// containing each path, so listing both `/` and `/var` is harmless when
    /// they share a filesystem and necessary when they do not.
    pub fanotify_marks: Vec<PathBuf>,
    pub exec_scan_timeout_ms: u32,
    pub use_ebpf: bool,
    /// Compiled eBPF object loaded when `use_ebpf` is true (built by
    /// `cargo xtask build-ebpf`). It must be owned by root and not writable by
    /// group or others; the sensor refuses to load it otherwise.
    pub ebpf_object: PathBuf,
    /// Watch file writes with fanotify (needs `CAP_SYS_ADMIN`).
    pub use_fanotify: bool,
    /// File events under these prefixes are dropped (noisy, low value).
    pub fanotify_exclude: Vec<PathBuf>,
    /// Interval of the `/proc` process poller.
    pub poll_interval_ms: u32,
    /// Rotate `events.jsonl` once it reaches this size.
    pub event_log_max_mb: u32,
    /// Number of rotated files (`events.jsonl.1` ..) to keep.
    pub event_log_keep: u32,
}

impl Default for SensorsConfig {
    fn default() -> Self {
        Self {
            fanotify_marks: ["/", "/home", "/tmp", "/var", "/dev/shm"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            exec_scan_timeout_ms: 200,
            use_ebpf: true,
            ebpf_object: PathBuf::from("/usr/lib/ai-antivirus/ai-antivirus-ebpf.o"),
            use_fanotify: true,
            fanotify_exclude: ["/var/log/journal", "/run/log/journal"]
                .into_iter()
                .map(PathBuf::from)
                .collect(),
            poll_interval_ms: 250,
            event_log_max_mb: 64,
            event_log_keep: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EngineConfig {
    pub allow_exe: Vec<PathBuf>,
    pub max_actions_per_minute: u32,
    /// Behavior rules (`behavior/**/*.toml`) and YARA rules (`yara/*.yar`). Added in M3.
    pub rules_dir: PathBuf,
    /// Files larger than this are hashed and YARA-scanned only on demand (`ai-antivirus scan`).
    pub scan_max_mb: u32,
    /// Limit for one YARA-X scan.
    pub yara_timeout_ms: u32,
    /// Scan written files that are executable or in a temporary or download folder.
    pub scan_on_write: bool,
    /// At most this many automatic scans per second; the rest are skipped and counted.
    pub max_scans_per_sec: u32,
    /// Only load rules whose bundle is signed (`bundle.manifest` + `bundle.sig`, see `ai-antivirus rules-sign`). Added in M6.
    pub require_signed_rules: bool,
    /// The public key that verifies the bundle.
    pub rules_pubkey: PathBuf,
    /// Files the engine checks against pacman's records every few minutes (AI Antivirus's own binaries).
    pub self_check_files: Vec<PathBuf>,
    /// Programs and folders left alone (`ai-antivirus exceptions`); without the file the built-in defaults apply.
    pub exceptions_file: PathBuf,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            allow_exe: [
                "/usr/bin/pacman",
                "/usr/bin/makepkg",
                "/usr/lib/systemd/systemd",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            max_actions_per_minute: 3,
            rules_dir: PathBuf::from("/etc/ai-antivirus/rules"),
            scan_max_mb: 32,
            yara_timeout_ms: 2000,
            scan_on_write: true,
            max_scans_per_sec: 50,
            require_signed_rules: false,
            rules_pubkey: PathBuf::from("/etc/ai-antivirus/rules.pub"),
            self_check_files: [
                "/usr/bin/ai-antivirus-sensord",
                "/usr/bin/ai-antivirus-engined",
                "/usr/bin/ai-antivirus-responderd",
                "/usr/bin/ai-antivirus-analyzer",
                "/usr/bin/ai-antivirus-notify",
                "/usr/bin/ai-antivirus",
                "/usr/lib/ai-antivirus/ai-antivirus-ebpf.o",
            ]
            .into_iter()
            .map(PathBuf::from)
            .collect(),
            exceptions_file: PathBuf::from(crate::exceptions::DEFAULT_EXCEPTIONS_PATH),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AiConfig {
    pub enabled: bool,
    pub endpoint: String,
    pub model: String,
    pub timeout_secs: u32,
    /// Most alerts sent to the model per hour (the rest are not analyzed). Added in M5.
    pub max_per_hour: u32,
    /// Alerts at or above this severity are analyzed.
    pub min_severity: Severity,
    /// A recording of ordinary activity (an event log). A proposed rule that fires on it is rejected automatically.
    pub corpus: PathBuf,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://127.0.0.1:11434".to_owned(),
            model: PLACEHOLDER_MODEL.to_owned(),
            timeout_secs: 30,
            max_per_hour: 60,
            min_severity: Severity::Medium,
            corpus: PathBuf::from("/etc/ai-antivirus/corpus/benign.jsonl"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ResponseConfig {
    /// Highest level that may run without human approval. Capped by the mode.
    pub auto_levels_max: u8,
    pub nft_block_ttl_secs: u32,
    /// Record what would be done (`dry_run`) instead of doing it, whatever the mode. Added in M4.
    pub dry_run: bool,
    /// Mount point of the cgroup v2 hierarchy; suspects are frozen in `<cgroup_root>/ai_antivirus.slice/`.
    pub cgroup_root: PathBuf,
    /// Desktop notifications are spooled here for `ai-antivirus-notify` (setgid directory of group `ai-antivirus-notify`).
    pub notify_dir: PathBuf,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            auto_levels_max: 3,
            nft_block_ttl_secs: 3600,
            dry_run: false,
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            notify_dir: PathBuf::from("/run/ai-antivirus-notify"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageConfig {
    /// Size cap for the SQLite store; oldest events are pruned beyond it.
    pub max_db_mb: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self { max_db_mb: 512 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LoggingConfig {
    pub level: LogLevel,
    pub format: LogFormat,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct PathsConfig {
    pub state_dir: PathBuf,
    pub log_dir: PathBuf,
    pub run_dir: PathBuf,
    /// The analyzer's own folder (`spool/` and `out/`), apart from `state_dir` so `ai-antivirus-analyzer` cannot reach the database
    /// or the event log. Added in M5.
    pub ai_dir: PathBuf,
    /// Root-only data: quarantined files and the evidence copies a restore keeps. Its own folder, not inside `state_dir`:
    /// the engine owns `state_dir`, and a folder the engine could rename or swap must never hold what root works on.
    pub private_dir: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("/var/lib/ai-antivirus"),
            log_dir: PathBuf::from("/var/log/ai-antivirus"),
            run_dir: PathBuf::from("/run/ai-antivirus"),
            ai_dir: PathBuf::from("/var/lib/ai-antivirus-analyzer"),
            private_dir: PathBuf::from("/var/lib/ai-antivirus-private"),
        }
    }
}

/// The complete AI Antivirus configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub general: GeneralConfig,
    pub sensors: SensorsConfig,
    pub engine: EngineConfig,
    pub ai: AiConfig,
    pub response: ResponseConfig,
    pub storage: StorageConfig,
    pub logging: LoggingConfig,
    pub paths: PathsConfig,
}

impl Config {
    /// Parse and validate a TOML document.
    pub fn from_toml_str(text: &str) -> Result<Config> {
        let cfg: Config = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read, parse and validate a config file.
    ///
    /// Refuses non-regular files, files over 1 MiB and world-writable files
    /// (a config anyone can edit is a tamper vector).
    pub fn load(path: &Path) -> Result<Config> {
        let file = File::open(path).map_err(|e| Error::io(path, e))?;
        let meta = file.metadata().map_err(|e| Error::io(path, e))?;
        let mut problems = Vec::new();
        if !meta.is_file() {
            problems.push(format!("{} is not a regular file", path.display()));
        }
        if meta.len() > MAX_CONFIG_BYTES {
            problems.push(format!(
                "{} is larger than {MAX_CONFIG_BYTES} bytes",
                path.display()
            ));
        }
        if meta.permissions().mode() & 0o002 != 0 {
            problems.push(format!(
                "{} is world-writable; run: chmod o-w {}",
                path.display(),
                path.display()
            ));
        }
        if !problems.is_empty() {
            return Err(Error::ConfigInvalid(problems));
        }

        let mut text = String::new();
        file.take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|e| Error::io(path, e))?;
        Config::from_toml_str(&text)
    }

    /// Path of the SQLite database inside `paths.state_dir`.
    pub fn db_path(&self) -> PathBuf {
        self.paths.state_dir.join(DB_FILE_NAME)
    }

    /// Bundles waiting for the AI analyzer (written by the engine, read by `ai-antivirus-analyzer`).
    pub fn ai_spool_dir(&self) -> PathBuf {
        self.paths.ai_dir.join("spool")
    }

    /// The analyzer's answers waiting for the engine (written by `ai-antivirus-analyzer`, read and removed by the engine).
    pub fn ai_out_dir(&self) -> PathBuf {
        self.paths.ai_dir.join("out")
    }

    /// Where quarantined files are kept (never deleted automatically).
    pub fn quarantine_dir(&self) -> PathBuf {
        self.paths.private_dir.join("quarantine")
    }

    /// Where a restore keeps what it replaced (never deleted automatically).
    pub fn restore_evidence_dir(&self) -> PathBuf {
        self.paths.private_dir.join("restore-evidence")
    }

    /// The responder's control socket (`ai-antivirus approve`, `undo` ...).
    pub fn responder_socket(&self) -> PathBuf {
        self.paths.run_dir.join("responder.sock")
    }

    /// Rotation threshold of the JSONL event log in bytes.
    pub fn event_log_max_bytes(&self) -> u64 {
        u64::from(self.sensors.event_log_max_mb) * 1024 * 1024
    }

    /// Store size cap in bytes.
    pub fn max_db_bytes(&self) -> u64 {
        u64::from(self.storage.max_db_mb) * 1024 * 1024
    }

    /// Highest response level that may run automatically: the lower of what
    /// the mode permits and what `response.auto_levels_max` asks for.
    pub fn effective_max_auto_level(&self) -> u8 {
        self.general
            .mode
            .max_level()
            .min(self.response.auto_levels_max)
    }

    /// Check every field and report all problems at once.
    pub fn validate(&self) -> Result<()> {
        let mut p: Vec<String> = Vec::new();

        range(
            &mut p,
            "general.retention_days",
            self.general.retention_days,
            1,
            365,
        );
        range(
            &mut p,
            "sensors.exec_scan_timeout_ms",
            self.sensors.exec_scan_timeout_ms,
            10,
            1000,
        );
        range(
            &mut p,
            "sensors.poll_interval_ms",
            self.sensors.poll_interval_ms,
            50,
            10_000,
        );
        range(
            &mut p,
            "sensors.event_log_max_mb",
            self.sensors.event_log_max_mb,
            1,
            4096,
        );
        range(
            &mut p,
            "sensors.event_log_keep",
            self.sensors.event_log_keep,
            1,
            100,
        );
        range(
            &mut p,
            "engine.max_actions_per_minute",
            self.engine.max_actions_per_minute,
            1,
            60,
        );
        range(
            &mut p,
            "engine.scan_max_mb",
            self.engine.scan_max_mb,
            1,
            4096,
        );
        range(
            &mut p,
            "engine.yara_timeout_ms",
            self.engine.yara_timeout_ms,
            50,
            60_000,
        );
        range(
            &mut p,
            "engine.max_scans_per_sec",
            self.engine.max_scans_per_sec,
            1,
            10_000,
        );
        range(&mut p, "ai.timeout_secs", self.ai.timeout_secs, 1, 300);
        range(&mut p, "ai.max_per_hour", self.ai.max_per_hour, 1, 3600);
        check_abs(&mut p, "ai.corpus", &self.ai.corpus);
        range(
            &mut p,
            "response.auto_levels_max",
            u32::from(self.response.auto_levels_max),
            0,
            6,
        );
        range(
            &mut p,
            "response.nft_block_ttl_secs",
            self.response.nft_block_ttl_secs,
            1,
            604_800,
        );
        range(
            &mut p,
            "storage.max_db_mb",
            self.storage.max_db_mb,
            16,
            65_536,
        );

        for (name, paths) in [
            ("sensors.fanotify_marks", &self.sensors.fanotify_marks),
            ("sensors.fanotify_exclude", &self.sensors.fanotify_exclude),
            ("engine.allow_exe", &self.engine.allow_exe),
        ] {
            for path in paths {
                check_abs(&mut p, name, path);
            }
        }
        if self.sensors.fanotify_marks.is_empty() {
            p.push("sensors.fanotify_marks must not be empty".to_owned());
        }
        check_abs(&mut p, "sensors.ebpf_object", &self.sensors.ebpf_object);
        check_abs(&mut p, "engine.rules_dir", &self.engine.rules_dir);
        check_abs(&mut p, "engine.rules_pubkey", &self.engine.rules_pubkey);
        check_abs(
            &mut p,
            "engine.exceptions_file",
            &self.engine.exceptions_file,
        );
        for f in &self.engine.self_check_files {
            check_abs(&mut p, "engine.self_check_files", f);
        }
        check_abs(&mut p, "paths.state_dir", &self.paths.state_dir);
        check_abs(&mut p, "paths.log_dir", &self.paths.log_dir);
        check_abs(&mut p, "paths.run_dir", &self.paths.run_dir);
        check_abs(&mut p, "paths.ai_dir", &self.paths.ai_dir);
        check_abs(&mut p, "paths.private_dir", &self.paths.private_dir);
        check_abs(&mut p, "response.cgroup_root", &self.response.cgroup_root);
        check_abs(&mut p, "response.notify_dir", &self.response.notify_dir);

        if let Err(msg) = check_loopback_endpoint(&self.ai.endpoint) {
            p.push(format!("ai.endpoint {msg}"));
        }
        if self.ai.enabled && self.ai.model.trim().is_empty() {
            p.push("ai.model must not be empty when ai.enabled = true".to_owned());
        }
        if self.ai.enabled && self.ai.model == PLACEHOLDER_MODEL {
            p.push(format!(
                "ai.model is still the placeholder {PLACEHOLDER_MODEL:?}; set a real local model"
            ));
        }

        if p.is_empty() {
            Ok(())
        } else {
            Err(Error::ConfigInvalid(p))
        }
    }
}

fn range(problems: &mut Vec<String>, name: &str, value: u32, min: u32, max: u32) {
    if !(min..=max).contains(&value) {
        problems.push(format!("{name} = {value} is outside {min}..={max}"));
    }
}

fn check_abs(problems: &mut Vec<String>, name: &str, path: &Path) {
    if !path.is_absolute() {
        problems.push(format!(
            "{name}: {} is not an absolute path",
            path.display()
        ));
    } else if path.as_os_str().as_bytes().contains(&0) {
        problems.push(format!("{name}: path contains a NUL byte"));
    }
}

/// The AI endpoint must be plain HTTP to a loopback IP literal. Host names
/// (even `localhost`) are rejected so name resolution can never redirect
/// untrusted data off the machine.
fn check_loopback_endpoint(endpoint: &str) -> std::result::Result<(), String> {
    let url = Url::parse(endpoint).map_err(|e| format!("is not a valid URL ({e})"))?;
    if url.scheme() != "http" {
        return Err("must use the http scheme (loopback only)".to_owned());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("must not contain credentials".to_owned());
    }
    match url.host() {
        Some(Host::Ipv4(ip)) if ip.is_loopback() => Ok(()),
        Some(Host::Ipv6(ip)) if ip.is_loopback() => Ok(()),
        _ => Err("host must be a loopback IP literal such as 127.0.0.1 or [::1]".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn problems(text: &str) -> Vec<String> {
        match Config::from_toml_str(text) {
            Err(Error::ConfigInvalid(p)) => p,
            other => panic!("expected ConfigInvalid, got {other:?}"),
        }
    }

    #[test]
    fn default_is_valid_and_safe() {
        let cfg = Config::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.general.mode, Mode::AlertOnly);
        assert!(!cfg.ai.enabled);
        assert_eq!(
            cfg.db_path(),
            PathBuf::from("/var/lib/ai-antivirus/ai-antivirus.db")
        );
    }

    #[test]
    fn example_file_matches_defaults() {
        let example = include_str!("../../../config/ai-antivirus.example.toml");
        let parsed = Config::from_toml_str(example).unwrap();
        assert_eq!(
            parsed,
            Config::default(),
            "example config drifted from defaults"
        );
    }

    #[test]
    fn sensor_knobs_are_range_checked() {
        let p = problems(
            "[sensors]\npoll_interval_ms = 5\nevent_log_max_mb = 0\nevent_log_keep = 101\n\
             fanotify_exclude = ['relative']\nebpf_object = 'ai-antivirus-ebpf.o'\n",
        );
        for needle in [
            "sensors.poll_interval_ms",
            "sensors.event_log_max_mb",
            "sensors.event_log_keep",
            "sensors.fanotify_exclude",
            "sensors.ebpf_object",
        ] {
            assert!(
                p.iter().any(|m| m.contains(needle)),
                "missing {needle}: {p:?}"
            );
        }
    }

    #[test]
    fn event_log_size_is_in_bytes() {
        let cfg = Config::default();
        assert_eq!(cfg.event_log_max_bytes(), 64 * 1024 * 1024);
    }

    #[test]
    fn empty_document_gives_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), Config::default());
    }

    #[test]
    fn partial_section_keeps_other_defaults() {
        let cfg = Config::from_toml_str("[general]\nretention_days = 30\n").unwrap();
        assert_eq!(cfg.general.retention_days, 30);
        assert_eq!(cfg.general.mode, Mode::AlertOnly);
        assert_eq!(cfg.sensors, SensorsConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert!(matches!(
            Config::from_toml_str("[general]\nmodee = 'enforce'\n"),
            Err(Error::ConfigParse(_))
        ));
        assert!(matches!(
            Config::from_toml_str("[nonsense]\nx = 1\n"),
            Err(Error::ConfigParse(_))
        ));
    }

    #[test]
    fn mode_names() {
        for (text, mode) in [
            ("alert-only", Mode::AlertOnly),
            ("contain", Mode::Contain),
            ("enforce", Mode::Enforce),
        ] {
            let cfg = Config::from_toml_str(&format!("[general]\nmode = '{text}'\n")).unwrap();
            assert_eq!(cfg.general.mode, mode);
            assert_eq!(mode.as_str(), text);
        }
        assert!(Config::from_toml_str("[general]\nmode = 'alert_only'\n").is_err());
    }

    #[test]
    fn all_problems_are_reported_together() {
        let p = problems(
            "[general]\nretention_days = 0\n[sensors]\nexec_scan_timeout_ms = 5000\n\
             fanotify_marks = ['relative']\n[engine]\nmax_actions_per_minute = 0\n",
        );
        assert_eq!(p.len(), 4, "{p:?}");
    }

    #[test]
    fn empty_marks_rejected() {
        let p = problems("[sensors]\nfanotify_marks = []\n");
        assert!(p.iter().any(|m| m.contains("must not be empty")));
    }

    #[test]
    fn ai_endpoint_must_be_loopback_http() {
        for good in [
            "http://127.0.0.1:11434",
            "http://127.0.0.2:1",
            "http://[::1]:11434",
        ] {
            let text = format!("[ai]\nendpoint = '{good}'\n");
            Config::from_toml_str(&text).unwrap();
        }
        for bad in [
            "http://localhost:11434",
            "http://192.168.1.10:11434",
            "http://example.com",
            "https://127.0.0.1:11434",
            "http://user:pw@127.0.0.1:11434",
            "not a url",
            "http://0.0.0.0:11434",
        ] {
            let text = format!("[ai]\nendpoint = '{bad}'\n");
            let p = problems(&text);
            assert!(
                p.iter().any(|m| m.starts_with("ai.endpoint")),
                "{bad}: {p:?}"
            );
        }
    }

    #[test]
    fn enabled_ai_needs_a_real_model() {
        let p = problems("[ai]\nenabled = true\n");
        assert!(p.iter().any(|m| m.contains("placeholder")));
        let p = problems("[ai]\nenabled = true\nmodel = '  '\n");
        assert!(p.iter().any(|m| m.contains("must not be empty")));
        Config::from_toml_str("[ai]\nenabled = true\nmodel = 'qwen2.5-coder:7b'\n").unwrap();
        // The placeholder is fine while the analyzer is off.
        Config::from_toml_str("[ai]\nenabled = false\n").unwrap();
    }

    #[test]
    fn effective_level_is_capped_by_mode() {
        let mut cfg = Config::default();
        cfg.response.auto_levels_max = 6;
        assert_eq!(cfg.effective_max_auto_level(), 1, "alert-only caps at 1");
        cfg.general.mode = Mode::Contain;
        assert_eq!(cfg.effective_max_auto_level(), 3);
        cfg.general.mode = Mode::Enforce;
        assert_eq!(cfg.effective_max_auto_level(), 6);
        cfg.response.auto_levels_max = 2;
        assert_eq!(cfg.effective_max_auto_level(), 2);
    }

    #[test]
    fn load_reads_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.toml");
        std::fs::write(&path, "[general]\nretention_days = 7\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(Config::load(&path).unwrap().general.retention_days, 7);
    }

    #[test]
    fn load_rejects_world_writable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ai-antivirus.toml");
        std::fs::write(&path, "").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("world-writable"), "{err}");
    }

    #[test]
    fn load_rejects_oversized_and_non_files_and_missing() {
        let dir = tempfile::tempdir().unwrap();

        let big = dir.path().join("big.toml");
        let mut f = File::create(&big).unwrap();
        f.write_all(&vec![b'#'; usize::try_from(MAX_CONFIG_BYTES).unwrap() + 1])
            .unwrap();
        drop(f);
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(&big)
            .unwrap_err()
            .to_string()
            .contains("larger than"));

        assert!(Config::load(dir.path())
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));

        assert!(matches!(
            Config::load(&dir.path().join("missing.toml")),
            Err(Error::Io { .. })
        ));
    }
}
