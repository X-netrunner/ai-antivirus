//! `cargo xtask build-ebpf [--release]`: build the kernel-side eBPF programs.
//!
//! They are compiled for `bpfel-unknown-none` with a nightly toolchain and
//! linked with `bpf-linker`, none of which the stable workspace needs. The
//! result is copied to `target/bpf/synapse-ebpf.o`, which is the file the
//! sensor loads (`sensors.ebpf_object`).

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask build-ebpf [--release]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("build-ebpf") => {
            let release = args.iter().skip(1).any(|a| a == "--release");
            if let Some(bad) = args.iter().skip(1).find(|a| *a != "--release") {
                eprintln!("unknown argument {bad:?}\n{USAGE}");
                return ExitCode::FAILURE;
            }
            match build_ebpf(release) {
                Ok(out) => {
                    println!("eBPF object: {}", out.display());
                    ExitCode::SUCCESS
                }
                Err(msg) => {
                    eprintln!("xtask: {msg}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn workspace_root() -> PathBuf {
    // xtask/ is directly under the workspace root.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// The CPU architecture name `aya-ebpf` expects in `bpf_target_arch`.
fn bpf_arch() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        other => Err(format!("unsupported architecture {other}")),
    }
}

fn build_ebpf(release: bool) -> Result<PathBuf, String> {
    let root = workspace_root();
    let crate_dir = root.join("crates").join("synapse-ebpf");

    // Fail early, with the fix, when the toolchain is not there.
    if Command::new("bpf-linker")
        .arg("--version")
        .output()
        .is_err()
    {
        return Err(
            "bpf-linker not found in PATH (install it: `cargo install bpf-linker`, or the Arch package if available)"
                .to_owned(),
        );
    }

    let arch = bpf_arch()?;
    // Separated by 0x1f, as CARGO_ENCODED_RUSTFLAGS requires. This replaces any
    // RUSTFLAGS on purpose: nothing else may leak into the BPF build.
    let flags = [
        "-Cdebuginfo=2".to_owned(),
        "-Clink-arg=--btf".to_owned(),
        format!("--cfg=bpf_target_arch=\"{arch}\""),
    ]
    .join("\x1f");

    // Run from the crate directory so its rust-toolchain.toml (nightly) and
    // .cargo/config.toml (target, build-std) apply. This needs `cargo` to be
    // the rustup proxy; with a distro `rust` package nightly is not available.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&crate_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .arg("build");
    if release {
        cmd.arg("--release");
    }
    let status = cmd.status().map_err(|e| format!("cannot run cargo: {e}"))?;
    if !status.success() {
        return Err(
            "the eBPF build failed. It needs rustup with a nightly toolchain and the rust-src component: \
             `rustup toolchain install nightly --component rust-src`"
                .to_owned(),
        );
    }

    let profile = if release { "release" } else { "debug" };
    let built = crate_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(profile)
        .join("synapse-ebpf");
    let out_dir = root.join("target").join("bpf");
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| format!("cannot create {}: {e}", out_dir.display()))?;
    let out = out_dir.join("synapse-ebpf.o");
    std::fs::copy(&built, &out)
        .map_err(|e| format!("cannot copy {} to {}: {e}", built.display(), out.display()))?;
    Ok(out)
}
