//! xtask development and CI helper tasks.
//!
//! The binary intentionally depends only on `std` and shells out to the cargo
//! tools pinned by the workspace. Usage: `cargo xtask
//! <coverage|ci|deny|dist|fingerprint-check|fuzz>`.
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{exit, Command};

const MACOS_DIST_TARGETS: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
];
const LINUX_DIST_TARGETS: &[&str] = &["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];
const WINDOWS_DIST_TARGETS: &[&str] = &["x86_64-pc-windows-msvc"];

fn main() {
    let mut args = env::args().skip(1);
    let task = args.next().unwrap_or_default();
    let rest = args.collect::<Vec<_>>();
    let code = match task.as_str() {
        "coverage" => coverage(),
        "ci" => ci(),
        "deny" => run("cargo", &["deny", "check"]),
        "dist" => dist(&rest),
        "fingerprint-check" => fingerprint_check(),
        "fuzz" => {
            eprintln!("fuzz: use `cargo +nightly fuzz run <target>`; see fuzz/ and AGENTS.md");
            0
        }
        other => {
            eprintln!("unknown task: {other:?}");
            print_usage();
            2
        }
    };
    exit(code);
}

/// Run the 90% line-coverage gate with `cargo-llvm-cov` and `cargo-nextest`.
fn coverage() -> i32 {
    run(
        "cargo",
        &[
            "llvm-cov",
            "nextest",
            "--workspace",
            "--all-features",
            "--run-ignored",
            "all",
            "--ignore-filename-regex",
            "(^|/)(xtask|fuzz)/|crates/umbra/src/main\\.rs",
            "--fail-under-lines",
            "90",
        ],
    )
}

/// Reproduce the CI gate locally: formatting, clippy, deny, fingerprints, coverage.
fn ci() -> i32 {
    let steps: &[(&str, &[&str])] = &[
        ("cargo", &["fmt", "--all", "--check"]),
        (
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        ),
        ("cargo", &["deny", "check"]),
        ("cargo", &["xtask", "fingerprint-check"]),
    ];
    for (cmd, args) in steps {
        let code = run(cmd, args);
        if code != 0 {
            return code;
        }
    }
    coverage()
}

/// Fingerprint profile self-checks for component J.
fn fingerprint_check() -> i32 {
    let steps: &[(&str, &[&str])] = &[
        (
            "cargo",
            &[
                "test",
                "-p",
                "umbra-fingerprint",
                "--test",
                "fingerprint_profiles",
            ],
        ),
        (
            "cargo",
            &[
                "test",
                "-p",
                "umbra-tls",
                "--test",
                "tls13_stack",
                "scenario_extension_order_follows_profile",
            ],
        ),
    ];
    for (cmd, args) in steps {
        let code = run(cmd, args);
        if code != 0 {
            return code;
        }
    }
    0
}

/// Build release binaries for common desktop/server targets into `target/dist/`.
fn dist(args: &[String]) -> i32 {
    let targets = match parse_dist_targets(args) {
        Ok(targets) => targets,
        Err(message) => {
            eprintln!("{message}");
            print_dist_usage();
            return 2;
        }
    };

    if targets.is_empty() {
        print_dist_usage();
        return 0;
    }

    if let Err(error) = fs::create_dir_all(dist_dir()) {
        eprintln!("failed to create dist directory: {error}");
        return 1;
    }

    for target in targets {
        if let Err(error) = build_dist_target(&target) {
            eprintln!("dist target {target} failed: {error}");
            return 1;
        }
    }

    eprintln!("dist artifacts written to {}", dist_dir().display());
    0
}

/// Parse comma-separated and repeated `cargo xtask dist` target arguments.
fn parse_dist_targets(args: &[String]) -> Result<Vec<String>, String> {
    if args.is_empty() {
        return Ok(default_dist_targets()
            .iter()
            .map(ToString::to_string)
            .collect());
    }

    let mut targets = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(Vec::new()),
            "--target" | "--targets" => {
                let Some(value) = iter.next() else {
                    return Err(format!("{arg} requires a target triple"));
                };
                push_targets(&mut targets, value);
            }
            value if value.starts_with("--") => {
                return Err(format!("unknown dist argument: {value}"));
            }
            value => push_targets(&mut targets, value),
        }
    }

    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(target.clone()));
    Ok(targets)
}

/// Append one comma-separated target argument while ignoring empty segments.
fn push_targets(targets: &mut Vec<String>, value: &str) {
    targets.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(ToString::to_string),
    );
}

/// Build one release binary and copy it to the distribution directory.
fn build_dist_target(target: &str) -> Result<(), String> {
    validate_dist_target(target)?;
    ensure_rust_target(target)?;

    let mut command = Command::new("cargo");
    command.args([
        "build",
        "--package",
        "umbra",
        "--release",
        "--locked",
        "--target",
        target,
    ]);

    if let Some(zig_target) = zig_target(target) {
        let linker = ensure_zig_cc_wrapper(target, zig_target)?;
        let archiver = ensure_zig_ar_wrapper(target)?;
        let env_target = target.replace('-', "_");
        let cargo_target_key = target.replace('-', "_").to_ascii_uppercase();
        let cargo_linker_key = format!("CARGO_TARGET_{cargo_target_key}_LINKER");

        command
            .env(cargo_linker_key, &linker)
            .env(format!("CC_{env_target}"), &linker)
            .env(format!("AR_{env_target}"), &archiver);
    }

    run_command(&mut command)?;

    let source = target_binary_path(target);
    let destination = dist_binary_path(target);
    fs::copy(&source, &destination).map_err(|error| {
        format!(
            "failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    eprintln!("built {}", destination.display());
    Ok(())
}

/// Ensure `rustup` has the requested compilation target installed.
fn ensure_rust_target(target: &str) -> Result<(), String> {
    let output = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map_err(|error| format!("failed to run rustup target list --installed: {error}"))?;
    if !output.status.success() {
        return Err("rustup target list --installed failed".to_string());
    }

    let installed = String::from_utf8_lossy(&output.stdout);
    if installed.lines().any(|line| line.trim() == target) {
        return Ok(());
    }

    let mut command = Command::new("rustup");
    command.args(["target", "add", target]);
    run_command(&mut command)
}

/// Create or refresh the `zig cc` wrapper used for local Linux cross builds.
fn ensure_zig_cc_wrapper(target: &str, zig_target: &str) -> Result<PathBuf, String> {
    ensure_tool("zig")?;
    let path = linker_dir().join(script_name(&format!("zig-cc-{target}")));
    let body = zig_cc_script(zig_target);
    write_executable_script(&path, &body)?;
    absolute_path(&path)
}

/// Create or refresh the `zig ar` wrapper paired with the Zig C compiler.
fn ensure_zig_ar_wrapper(target: &str) -> Result<PathBuf, String> {
    ensure_tool("zig")?;
    let path = linker_dir().join(script_name(&format!("zig-ar-{target}")));
    let body = shell_script("exec zig ar \"$@\"");
    write_executable_script(&path, &body)?;
    absolute_path(&path)
}

/// Verify that a required command-line tool can be executed.
fn ensure_tool(tool: &str) -> Result<(), String> {
    let status = Command::new(tool)
        .arg("version")
        .status()
        .map_err(|error| format!("failed to run {tool}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{tool} version returned a failing status"))
    }
}

/// Reject targets that this host cannot build without external toolchains.
fn validate_dist_target(target: &str) -> Result<(), String> {
    if target.contains("windows") && !cfg!(windows) && !mingw_toolchain_available() {
        return Err(format!(
            "{target} requires a Windows runner/MSVC or a local MinGW-w64 toolchain; this macOS environment is validated for macOS/Linux targets."
        ));
    }
    Ok(())
}

/// Return true when a MinGW toolchain is available for local Windows builds.
fn mingw_toolchain_available() -> bool {
    tool_available("x86_64-w64-mingw32-gcc") || tool_available("x86_64-w64-mingw32-clang")
}

/// Return true when `tool --version` exits successfully.
fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

/// Write a helper script and make it executable on platforms that require it.
fn write_executable_script(path: &Path, body: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("failed to resolve script directory: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    fs::write(path, body)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))?;
    make_executable(path)
}

#[cfg(unix)]
/// Mark a generated helper script executable on Unix-like hosts.
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("failed to read permissions for {}: {error}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("failed to make {} executable: {error}", path.display()))
}

#[cfg(not(unix))]
/// Keep script generation portable on platforms without Unix execute bits.
fn make_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

/// Build a tiny platform-specific shell wrapper around a command.
fn shell_script(command: &str) -> String {
    if cfg!(windows) {
        format!("@echo off\r\n{command} %*\r\n")
    } else {
        format!("#!/bin/sh\n{command}\n")
    }
}

/// Build a Zig C compiler wrapper that removes cargo-provided target flags.
fn zig_cc_script(zig_target: &str) -> String {
    if cfg!(windows) {
        return format!("@echo off\r\nzig cc -target {zig_target} %*\r\n");
    }

    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail
args=()
while (($#)); do
  case "$1" in
    --target=*) shift ;;
    -target) shift; if (($#)); then shift; fi ;;
    *) args+=("$1"); shift ;;
  esac
done
exec zig cc -target {zig_target} "${{args[@]}}"
"#
    )
}

/// Return the platform-specific script file name for a wrapper stem.
fn script_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.cmd")
    } else {
        stem.to_string()
    }
}

/// Map Rust target triples to Zig target triples when Zig can cross-compile them.
fn zig_target(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-unknown-linux-gnu" => Some("x86_64-linux-gnu"),
        "aarch64-unknown-linux-gnu" => Some("aarch64-linux-gnu"),
        _ => None,
    }
}

/// Return the path where cargo writes the release binary for a target.
fn target_binary_path(target: &str) -> PathBuf {
    PathBuf::from("target")
        .join(target)
        .join("release")
        .join(binary_name(target))
}

/// Return the final distribution artifact path for a target.
fn dist_binary_path(target: &str) -> PathBuf {
    dist_dir().join(format!("umbra-{target}{}", binary_suffix(target)))
}

/// Return the target-specific Umbra binary name.
fn binary_name(target: &str) -> String {
    format!("umbra{}", binary_suffix(target))
}

/// Return the executable suffix required by the target platform.
fn binary_suffix(target: &str) -> &'static str {
    if target.contains("windows") {
        ".exe"
    } else {
        ""
    }
}

/// Return the directory where distribution artifacts are collected.
fn dist_dir() -> PathBuf {
    PathBuf::from("target").join("dist")
}

/// Return the directory where generated linker wrapper scripts live.
fn linker_dir() -> PathBuf {
    PathBuf::from("target").join("xtask-linkers")
}

/// Convert a repository-relative path into an absolute path for cargo env vars.
fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    env::current_dir()
        .map_err(|error| format!("failed to read current directory: {error}"))
        .map(|cwd| cwd.join(path))
}

/// Run a fully configured command and convert a failing status into an error.
fn run_command(command: &mut Command) -> Result<(), String> {
    eprintln!("+ {:?}", command);
    let status = command
        .status()
        .map_err(|error| format!("failed to run {:?}: {error}", command))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{:?} exited with {status}", command))
    }
}

/// Run a simple command and return a process-like exit code.
fn run(cmd: &str, args: &[&str]) -> i32 {
    eprintln!("+ {cmd} {}", args.join(" "));
    Command::new(cmd)
        .args(args)
        .status()
        .map_or(1, |s| s.code().unwrap_or(1))
}

/// Print top-level xtask usage.
fn print_usage() {
    eprintln!("usage: cargo xtask <coverage|ci|deny|dist|fingerprint-check|fuzz>");
}

/// Print distribution task usage and host-specific notes.
fn print_dist_usage() {
    eprintln!("usage: cargo xtask dist [--target <triple>[,<triple>...]] [<triple>...]");
    eprintln!("default targets: {}", default_dist_targets().join(", "));
    eprintln!("Linux cross targets on macOS require zig in PATH.");
    eprintln!("Windows targets should run on a Windows runner: cargo xtask dist --target x86_64-pc-windows-msvc");
}

/// Return the default release targets supported by the current host.
fn default_dist_targets() -> &'static [&'static str] {
    if cfg!(target_os = "macos") {
        MACOS_DIST_TARGETS
    } else if cfg!(target_os = "linux") {
        LINUX_DIST_TARGETS
    } else if cfg!(target_os = "windows") {
        WINDOWS_DIST_TARGETS
    } else {
        &[]
    }
}
