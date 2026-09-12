//! Binary-level CLI tests.

use std::{collections::HashMap, process::Command};

use base64::{engine::general_purpose::STANDARD, Engine as _};

#[test]
fn scenario_help_lists_subcommands() {
    let output = Command::new(env!("CARGO_BIN_EXE_umbra"))
        .arg("--help")
        .output()
        .expect("run help");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(stdout.contains("server"));
    assert!(stdout.contains("client"));
    assert!(stdout.contains("keygen"));
}

#[test]
fn scenario_keygen_prints_parseable_keys() {
    let output = Command::new(env!("CARGO_BIN_EXE_umbra"))
        .arg("keygen")
        .output()
        .expect("run keygen");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("keygen output is UTF-8");
    let values = parse_key_values(&stdout);
    assert_eq!(decode(values["x25519_private"]).len(), 32);
    assert_eq!(decode(values["x25519_public"]).len(), 32);
    assert_eq!(decode(values["mldsa_seed"]).len(), 32);
    assert_eq!(decode(values["mldsa_verify"]).len(), 1952);
}

#[test]
fn scenario_invalid_transport_exits_nonzero() {
    let public_key = b64(1);
    let mldsa_verify = b64(2);
    let output = Command::new(env!("CARGO_BIN_EXE_umbra"))
        .args([
            "client",
            "--server",
            "198.51.100.10:443",
            "--transport",
            "invalid",
            "--public-key",
            public_key.as_str(),
            "--short-id",
            "aa",
            "--server-name",
            "server.example",
            "--fingerprint",
            "chrome-latest",
            "--mldsa-verify",
            mldsa_verify.as_str(),
            "--spider-path",
            "/",
            "--socks-listen",
            "127.0.0.1:1081",
            "--mux",
            "true",
            "--padding-scheme",
            "none",
            "--tcp-evasion",
            "off",
        ])
        .output()
        .expect("run invalid client");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(stderr.contains("unsupported transport"));
}

#[test]
fn scenario_config_errors_omit_secret_values_from_cli_stderr() {
    const SECRET: &str = "SYNTHETIC_PRIVATE_KEY_SEED_SHORT_ID";
    for (command, fields) in [
        ("server", ["private_key", "mldsa_seed", "short_ids"]),
        ("client", ["public_key", "mldsa_verify", "short_id"]),
    ] {
        for field in fields {
            for (case, value) in [
                ("syntax", format!("[\"{SECRET}\" trailing]")),
                ("type", format!("[[\"{SECRET}\", \"cafebabedeadbeef\"]]")),
            ] {
                let path = std::env::temp_dir().join(format!(
                    "umbra-cli-redaction-{}-{command}-{field}-{case}.toml",
                    std::process::id()
                ));
                std::fs::write(&path, format!("# synthetic fixture\n{field} = {value}"))
                    .expect("write synthetic config");
                let output = Command::new(env!("CARGO_BIN_EXE_umbra"))
                    .args([command, "--config"])
                    .arg(&path)
                    .output();
                std::fs::remove_file(&path).expect("remove synthetic config");
                let output = output.expect("run invalid config");
                assert!(!output.status.success());
                assert!(output.stdout.is_empty());
                let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
                assert!(stderr.contains("configuration parse failed"));
                assert!(stderr.contains("line 2, column "));
                for value in [SECRET, "cafebabedeadbeef", "synthetic fixture", "trailing"] {
                    assert!(!stderr.contains(value), "stderr disclosed a config value");
                }
            }
        }
    }
}

fn parse_key_values(output: &str) -> HashMap<&str, &str> {
    output
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect()
}

fn decode(input: &str) -> Vec<u8> {
    STANDARD.decode(input).expect("valid base64")
}

fn b64(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}
