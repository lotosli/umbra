//! xtask — 开发/CI 辅助任务运行器（仅依赖 std，通过 shell 调用 cargo 工具）。
//!
//! 用法：`cargo xtask <coverage|ci|deny|dist|fingerprint-check|fuzz>`
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
            eprintln!("fuzz: 使用 `cargo +nightly fuzz run <target>`（见 fuzz/ 与 AGENTS.md）");
            0
        }
        other => {
            eprintln!("未知任务: {other:?}");
            print_usage();
            2
        }
    };
    exit(code);
}

/// 90% 行覆盖率闸门（需 cargo-llvm-cov + cargo-nextest）。
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

/// 本地复现 CI 闸门：fmt → clippy → deny → fingerprint-check → coverage(≥90%)。
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
        eprintln!("无法创建 dist 目录: {error}");
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
                    return Err(format!("{arg} 需要一个 target triple"));
                };
                push_targets(&mut targets, value);
            }
            value if value.starts_with("--") => {
                return Err(format!("未知 dist 参数: {value}"));
            }
            value => push_targets(&mut targets, value),
        }
    }

    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(target.clone()));
    Ok(targets)
}

fn push_targets(targets: &mut Vec<String>, value: &str) {
    targets.extend(
        value
            .split(',')
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .map(ToString::to_string),
    );
}

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
            "复制 {} 到 {} 失败: {error}",
            source.display(),
            destination.display()
        )
    })?;
    eprintln!("built {}", destination.display());
    Ok(())
}

fn ensure_rust_target(target: &str) -> Result<(), String> {
    let output = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output()
        .map_err(|error| format!("无法运行 rustup target list --installed: {error}"))?;
    if !output.status.success() {
        return Err("rustup target list --installed 失败".to_string());
    }

    let installed = String::from_utf8_lossy(&output.stdout);
    if installed.lines().any(|line| line.trim() == target) {
        return Ok(());
    }

    let mut command = Command::new("rustup");
    command.args(["target", "add", target]);
    run_command(&mut command)
}

fn ensure_zig_cc_wrapper(target: &str, zig_target: &str) -> Result<PathBuf, String> {
    ensure_tool("zig")?;
    let path = linker_dir().join(script_name(&format!("zig-cc-{target}")));
    let body = zig_cc_script(zig_target);
    write_executable_script(&path, &body)?;
    absolute_path(&path)
}

fn ensure_zig_ar_wrapper(target: &str) -> Result<PathBuf, String> {
    ensure_tool("zig")?;
    let path = linker_dir().join(script_name(&format!("zig-ar-{target}")));
    let body = shell_script("exec zig ar \"$@\"");
    write_executable_script(&path, &body)?;
    absolute_path(&path)
}

fn ensure_tool(tool: &str) -> Result<(), String> {
    let status = Command::new(tool)
        .arg("version")
        .status()
        .map_err(|error| format!("无法运行 {tool}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{tool} version 返回失败状态"))
    }
}

fn validate_dist_target(target: &str) -> Result<(), String> {
    if target.contains("windows") && !cfg!(windows) && !mingw_toolchain_available() {
        return Err(format!(
            "{target} 需要 Windows runner/MSVC，或本机安装 MinGW-w64 工具链；当前 macOS 环境已验证 macOS/Linux targets。"
        ));
    }
    Ok(())
}

fn mingw_toolchain_available() -> bool {
    tool_available("x86_64-w64-mingw32-gcc") || tool_available("x86_64-w64-mingw32-clang")
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .status()
        .is_ok_and(|status| status.success())
}

fn write_executable_script(path: &Path, body: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("无法解析脚本目录: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("无法创建 {}: {error}", parent.display()))?;
    fs::write(path, body).map_err(|error| format!("无法写入 {}: {error}", path.display()))?;
    make_executable(path)
}

#[cfg(unix)]
fn make_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| format!("无法读取 {} 权限: {error}", path.display()))?
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("无法设置 {} 为可执行: {error}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn shell_script(command: &str) -> String {
    if cfg!(windows) {
        format!("@echo off\r\n{command} %*\r\n")
    } else {
        format!("#!/bin/sh\n{command}\n")
    }
}

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

fn script_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.cmd")
    } else {
        stem.to_string()
    }
}

fn zig_target(target: &str) -> Option<&'static str> {
    match target {
        "x86_64-unknown-linux-gnu" => Some("x86_64-linux-gnu"),
        "aarch64-unknown-linux-gnu" => Some("aarch64-linux-gnu"),
        _ => None,
    }
}

fn target_binary_path(target: &str) -> PathBuf {
    PathBuf::from("target")
        .join(target)
        .join("release")
        .join(binary_name(target))
}

fn dist_binary_path(target: &str) -> PathBuf {
    dist_dir().join(format!("umbra-{target}{}", binary_suffix(target)))
}

fn binary_name(target: &str) -> String {
    format!("umbra{}", binary_suffix(target))
}

fn binary_suffix(target: &str) -> &'static str {
    if target.contains("windows") {
        ".exe"
    } else {
        ""
    }
}

fn dist_dir() -> PathBuf {
    PathBuf::from("target").join("dist")
}

fn linker_dir() -> PathBuf {
    PathBuf::from("target").join("xtask-linkers")
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    env::current_dir()
        .map_err(|error| format!("无法读取当前目录: {error}"))
        .map(|cwd| cwd.join(path))
}

fn run_command(command: &mut Command) -> Result<(), String> {
    eprintln!("+ {:?}", command);
    let status = command
        .status()
        .map_err(|error| format!("无法运行 {:?}: {error}", command))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{:?} exited with {status}", command))
    }
}

fn run(cmd: &str, args: &[&str]) -> i32 {
    eprintln!("+ {cmd} {}", args.join(" "));
    Command::new(cmd)
        .args(args)
        .status()
        .map_or(1, |s| s.code().unwrap_or(1))
}

fn print_usage() {
    eprintln!("用法: cargo xtask <coverage|ci|deny|dist|fingerprint-check|fuzz>");
}

fn print_dist_usage() {
    eprintln!("用法: cargo xtask dist [--target <triple>[,<triple>...]] [<triple>...]");
    eprintln!("默认 targets: {}", default_dist_targets().join(", "));
    eprintln!("macOS 上的 Linux 交叉目标需要系统 PATH 中存在 zig。");
    eprintln!("Windows 目标建议在 Windows runner 上运行: cargo xtask dist --target x86_64-pc-windows-msvc");
}

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
