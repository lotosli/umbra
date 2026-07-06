//! xtask — 开发/CI 辅助任务运行器（仅依赖 std，通过 shell 调用 cargo 工具）。
//!
//! 用法：`cargo xtask <coverage|ci|deny|fingerprint-check|fuzz>`
use std::process::{exit, Command};

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();
    let code = match task.as_str() {
        "coverage" => coverage(),
        "ci" => ci(),
        "deny" => run("cargo", &["deny", "check"]),
        "fingerprint-check" => {
            eprintln!(
                "fingerprint-check: 见组件 J 与 skill `umbra-fingerprint-check`（实现后接入）"
            );
            0
        }
        "fuzz" => {
            eprintln!("fuzz: 使用 `cargo +nightly fuzz run <target>`（见 fuzz/ 与 AGENTS.md）");
            0
        }
        other => {
            eprintln!("未知任务: {other:?}");
            eprintln!("用法: cargo xtask <coverage|ci|deny|fingerprint-check|fuzz>");
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
            "--ignore-filename-regex",
            "(^|/)(xtask|fuzz)/|crates/umbra/src/main\\.rs",
            "--fail-under-lines",
            "90",
        ],
    )
}

/// 本地复现 CI 闸门：fmt → clippy → deny → coverage(≥90%)。
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
    ];
    for (cmd, args) in steps {
        let code = run(cmd, args);
        if code != 0 {
            return code;
        }
    }
    coverage()
}

fn run(cmd: &str, args: &[&str]) -> i32 {
    eprintln!("+ {cmd} {}", args.join(" "));
    Command::new(cmd)
        .args(args)
        .status()
        .map_or(1, |s| s.code().unwrap_or(1))
}
