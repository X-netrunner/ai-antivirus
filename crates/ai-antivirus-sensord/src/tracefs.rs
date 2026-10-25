//! Tracepoint record layouts, read from tracefs at start-up.
//!
//! The eBPF programs read fields out of raw tracepoint records at fixed byte
//! offsets. Those offsets are kernel ABI, but instead of trusting constants the
//! sensor reads `/sys/kernel/tracing/events/<category>/<event>/format`, checks
//! the field exists with the expected size, and passes the offset to the
//! kernel program as a global. A kernel that renames or resizes a field then
//! disables the one program that needs it, instead of making it read garbage.
//!
//! If tracefs cannot be read at all, the offsets Linux has used for years are
//! assumed (the `DEFAULT_*` values), and the daemon logs that it did so.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Where tracefs is usually mounted, newest location first.
const TRACEFS_ROOTS: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

pub const DEFAULT_FORK_CHILD_PID: u32 = 44;
pub const DEFAULT_EXEC_FILENAME: u32 = 8;
pub const DEFAULT_EXEC_OLD_PID: u32 = 16;
pub const DEFAULT_EXECVE_ARGV: u32 = 24;
pub const DEFAULT_EXECVEAT_ARGV: u32 = 32;
pub const DEFAULT_EXIT_GROUP_CODE: u32 = 16;

/// One field of a tracepoint record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub offset: u32,
    pub size: u32,
}

/// The fields of one tracepoint, by name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EventFormat {
    fields: HashMap<String, Field>,
}

impl EventFormat {
    /// The field `name`, if it exists with one of the `sizes` (in bytes).
    pub fn field(&self, name: &str, sizes: &[u32]) -> Option<u32> {
        self.fields
            .get(name)
            .filter(|f| sizes.contains(&f.size))
            .map(|f| f.offset)
    }
}

/// Parse the text of a tracefs `format` file. Lines that are not field
/// descriptions are ignored.
pub fn parse_format(text: &str) -> EventFormat {
    let mut fields = HashMap::new();
    for line in text.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let mut declaration = None;
        let mut offset = None;
        let mut size = None;
        for (index, part) in rest.split(';').enumerate() {
            let part = part.trim();
            if index == 0 {
                declaration = Some(part);
            } else if let Some(v) = part.strip_prefix("offset:") {
                offset = v.trim().parse::<u32>().ok();
            } else if let Some(v) = part.strip_prefix("size:") {
                size = v.trim().parse::<u32>().ok();
            }
        }
        let (Some(declaration), Some(offset), Some(size)) = (declaration, offset, size) else {
            continue;
        };
        if let Some(name) = field_name(declaration) {
            fields.insert(name.to_owned(), Field { offset, size });
        }
    }
    EventFormat { fields }
}

/// The identifier in a C declaration such as `char parent_comm[16]`,
/// `__data_loc char[] filename` or `const char *const * argv`.
fn field_name(declaration: &str) -> Option<&str> {
    let last = declaration.split_whitespace().last()?;
    let name = last.trim_start_matches('*').split('[').next()?;
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Read and parse `events/<category>/<event>/format` under `root`.
pub fn load_format_from(root: &Path, category: &str, event: &str) -> Option<EventFormat> {
    let path: PathBuf = root
        .join("events")
        .join(category)
        .join(event)
        .join("format");
    let text = fs::read_to_string(path).ok()?;
    Some(parse_format(&text))
}

/// Read a tracepoint's format from wherever tracefs is mounted.
pub fn load_format(category: &str, event: &str) -> Option<EventFormat> {
    TRACEFS_ROOTS
        .iter()
        .find_map(|root| load_format_from(Path::new(root), category, event))
}

/// The field offsets the eBPF programs need. `None` means the running kernel
/// does not have that field in the expected shape, so the program that needs it
/// must not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offsets {
    pub fork_child_pid: Option<u32>,
    pub exec_filename: Option<u32>,
    pub exec_old_pid: Option<u32>,
    pub execve_argv: Option<u32>,
    pub execveat_argv: Option<u32>,
    pub exit_group_code: Option<u32>,
    /// True when at least one tracepoint's format file could not be read and a
    /// built-in default was used for it.
    pub used_defaults: bool,
}

impl Offsets {
    /// Resolve every offset through `load`, which returns the format of
    /// `(category, event)`. A tracepoint whose format cannot be loaded gets the
    /// built-in default; one that loads but lacks the field gets `None`.
    pub fn resolve<F>(load: F) -> Offsets
    where
        F: Fn(&str, &str) -> Option<EventFormat>,
    {
        let mut used_defaults = false;
        let mut pick =
            |category: &str, event: &str, field: &str, sizes: &[u32], default: u32| match load(
                category, event,
            ) {
                Some(format) => format.field(field, sizes),
                None => {
                    used_defaults = true;
                    Some(default)
                }
            };
        let fork_child_pid = pick(
            "sched",
            "sched_process_fork",
            "child_pid",
            &[4],
            DEFAULT_FORK_CHILD_PID,
        );
        let exec_filename = pick(
            "sched",
            "sched_process_exec",
            "filename",
            &[4],
            DEFAULT_EXEC_FILENAME,
        );
        let exec_old_pid = pick(
            "sched",
            "sched_process_exec",
            "old_pid",
            &[4],
            DEFAULT_EXEC_OLD_PID,
        );
        let execve_argv = pick(
            "syscalls",
            "sys_enter_execve",
            "argv",
            &[8],
            DEFAULT_EXECVE_ARGV,
        );
        let execveat_argv = pick(
            "syscalls",
            "sys_enter_execveat",
            "argv",
            &[8],
            DEFAULT_EXECVEAT_ARGV,
        );
        let exit_group_code = pick(
            "syscalls",
            "sys_enter_exit_group",
            "error_code",
            &[4, 8],
            DEFAULT_EXIT_GROUP_CODE,
        );
        Offsets {
            fork_child_pid,
            exec_filename,
            exec_old_pid,
            execve_argv,
            execveat_argv,
            exit_group_code,
            used_defaults,
        }
    }

    /// Resolve against the tracefs of the running system.
    pub fn from_system() -> Offsets {
        Offsets::resolve(load_format)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FORK_FORMAT: &str = "\
name: sched_process_fork
ID: 311
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;
\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;
\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;

\tfield:char parent_comm[16];\toffset:8;\tsize:16;\tsigned:0;
\tfield:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;
\tfield:char child_comm[16];\toffset:28;\tsize:16;\tsigned:0;
\tfield:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;

print fmt: \"comm=%s pid=%d child_comm=%s child_pid=%d\", REC->parent_comm, REC->parent_pid, REC->child_comm, REC->child_pid
";

    const EXEC_FORMAT: &str = "\
name: sched_process_exec
format:
\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
\tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;
\tfield:pid_t pid;\toffset:12;\tsize:4;\tsigned:1;
\tfield:pid_t old_pid;\toffset:16;\tsize:4;\tsigned:1;
";

    const EXECVE_FORMAT: &str = "\
name: sys_enter_execve
format:
\tfield:int __syscall_nr;\toffset:8;\tsize:4;\tsigned:1;
\tfield:const char * filename;\toffset:16;\tsize:8;\tsigned:0;
\tfield:const char *const * argv;\toffset:24;\tsize:8;\tsigned:0;
\tfield:const char *const * envp;\toffset:32;\tsize:8;\tsigned:0;
";

    #[test]
    fn parses_names_offsets_and_sizes() {
        let f = parse_format(FORK_FORMAT);
        assert_eq!(f.field("child_pid", &[4]), Some(44));
        assert_eq!(f.field("parent_pid", &[4]), Some(24));
        assert_eq!(
            f.field("child_comm", &[16]),
            Some(28),
            "array suffix stripped"
        );
        assert_eq!(f.field("common_type", &[2]), Some(0));
    }

    #[test]
    fn wrong_size_means_not_found() {
        let f = parse_format(FORK_FORMAT);
        assert_eq!(f.field("child_pid", &[8]), None);
        assert_eq!(f.field("no_such_field", &[4]), None);
    }

    #[test]
    fn data_loc_and_pointer_declarations() {
        let exec = parse_format(EXEC_FORMAT);
        assert_eq!(exec.field("filename", &[4]), Some(8));
        assert_eq!(exec.field("old_pid", &[4]), Some(16));
        let execve = parse_format(EXECVE_FORMAT);
        assert_eq!(execve.field("argv", &[8]), Some(24));
        assert_eq!(execve.field("filename", &[8]), Some(16));
    }

    #[test]
    fn garbage_is_ignored() {
        let f = parse_format(
            "field:\nfield:int x;\noffset:1;\nfield:int y;\toffset:z;\tsize:4;\n\u{0}\u{1}",
        );
        assert_eq!(f, EventFormat::default());
    }

    #[test]
    fn name_extraction() {
        assert_eq!(field_name("char parent_comm[16]"), Some("parent_comm"));
        assert_eq!(field_name("__data_loc char[] filename"), Some("filename"));
        assert_eq!(field_name("const char *const * argv"), Some("argv"));
        assert_eq!(field_name("char *name"), Some("name"));
        assert_eq!(field_name(""), None);
    }

    fn fixture(tracepoint: &str) -> Option<EventFormat> {
        match tracepoint {
            "sched_process_fork" => Some(parse_format(FORK_FORMAT)),
            "sched_process_exec" => Some(parse_format(EXEC_FORMAT)),
            "sys_enter_execve" => Some(parse_format(EXECVE_FORMAT)),
            _ => None,
        }
    }

    #[test]
    fn resolve_uses_the_kernel_values_and_defaults_for_unreadable_formats() {
        let offsets = Offsets::resolve(|_, event| fixture(event));
        assert_eq!(offsets.fork_child_pid, Some(44));
        assert_eq!(offsets.exec_filename, Some(8));
        assert_eq!(offsets.exec_old_pid, Some(16));
        assert_eq!(offsets.execve_argv, Some(24));
        // execveat and exit_group formats were "unreadable": defaults.
        assert_eq!(offsets.execveat_argv, Some(DEFAULT_EXECVEAT_ARGV));
        assert_eq!(offsets.exit_group_code, Some(DEFAULT_EXIT_GROUP_CODE));
        assert!(offsets.used_defaults);
    }

    #[test]
    fn a_renamed_field_disables_only_the_program_that_needs_it() {
        let offsets = Offsets::resolve(|_, event| {
            if event == "sched_process_fork" {
                Some(parse_format(
                    "\tfield:pid_t renamed_pid;\toffset:44;\tsize:4;\tsigned:1;\n",
                ))
            } else {
                fixture(event)
            }
        });
        assert_eq!(offsets.fork_child_pid, None);
        assert_eq!(offsets.exec_filename, Some(8));
    }

    #[test]
    fn nothing_readable_means_all_defaults() {
        let offsets = Offsets::resolve(|_, _| None);
        assert_eq!(offsets.fork_child_pid, Some(DEFAULT_FORK_CHILD_PID));
        assert_eq!(offsets.exec_filename, Some(DEFAULT_EXEC_FILENAME));
        assert_eq!(offsets.exec_old_pid, Some(DEFAULT_EXEC_OLD_PID));
        assert_eq!(offsets.execve_argv, Some(DEFAULT_EXECVE_ARGV));
        assert_eq!(offsets.execveat_argv, Some(DEFAULT_EXECVEAT_ARGV));
        assert_eq!(offsets.exit_group_code, Some(DEFAULT_EXIT_GROUP_CODE));
        assert!(offsets.used_defaults);
    }

    #[test]
    fn reads_a_format_file_from_a_directory_tree() {
        let dir = tempfile::tempdir().unwrap();
        let event_dir = dir.path().join("events/sched/sched_process_fork");
        fs::create_dir_all(&event_dir).unwrap();
        fs::write(event_dir.join("format"), FORK_FORMAT).unwrap();

        let format = load_format_from(dir.path(), "sched", "sched_process_fork").unwrap();
        assert_eq!(format.field("child_pid", &[4]), Some(44));
        assert!(load_format_from(dir.path(), "sched", "missing").is_none());
    }
}
