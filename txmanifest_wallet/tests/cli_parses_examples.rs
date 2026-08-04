//! Every CLI subcommand that reads a manifest must parse it the same way `run` does.
//!
//! Each entry point has to go through [`Manifest::from_json_str`], not a bare
//! `serde_json::from_str`: the model is `deny_unknown_fields`, so a command that
//! skips the `$comment` / `$schema` stripping rejects every manifest in this repo
//! with `unknown field '$schema'`. That is exactly what happened to `validate`,
//! `describe` and `prepare` — the library tests all passed because none of them
//! ran the binary.
//!
//! These tests therefore shell the real binary and assert only on the *parse*
//! step, so they stay green regardless of what a manifest validates to or whether
//! a wallet is present.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The marker `main.rs` wraps every manifest read in. Its presence in stderr means
/// deserialization failed, whatever the command went on to do.
const PARSE_FAILURE: &str = "Cannot parse manifest file";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Every `examples/*/txmanifest.json`, sorted for stable failure output.
fn example_manifests() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(workspace_root().join("examples"))
        .expect("examples/ should exist")
        .filter_map(|entry| {
            let path = entry.ok()?.path().join("txmanifest.json");
            path.is_file().then_some(path)
        })
        .collect();
    found.sort();
    found
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tx-manifest-wallet"))
        .args(args)
        .output()
        .expect("the CLI binary should be runnable")
}

/// Run `args` against every example and collect the ones whose manifest failed to
/// parse. Anything else the command reports is ignored — this is a parse guard.
fn parse_failures(build_args: impl Fn(&str) -> Vec<String>) -> Vec<String> {
    let mut failures = Vec::new();
    for path in example_manifests() {
        let manifest = path.to_string_lossy().to_string();
        let owned = build_args(&manifest);
        let args: Vec<&str> = owned.iter().map(String::as_str).collect();
        let output = run_cli(&args);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains(PARSE_FAILURE) {
            let name = path
                .parent()
                .and_then(Path::file_name)
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            failures.push(format!("  {name}: {}", stderr.trim()));
        }
    }
    failures
}

fn assert_all_parsed(command: &str, failures: Vec<String>) {
    assert!(
        failures.is_empty(),
        "`{command}` failed to parse {} example manifest(s):\n{}\n\n\
         Use `Manifest::from_json_str`, not `serde_json::from_str`.",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn validate_parses_every_example() {
    let failures = parse_failures(|m| vec!["validate".into(), m.into()]);
    assert_all_parsed("validate", failures);
}

#[test]
fn describe_parses_every_example() {
    // stdout is a pipe here, so `describe` takes its non-interactive dump path.
    let failures = parse_failures(|m| vec!["describe".into(), m.into()]);
    assert_all_parsed("describe", failures);
}

#[test]
fn prepare_parses_every_example() {
    // `prepare` reads the manifest before it loads a wallet, so it still fails —
    // just not with a parse error. The wallet path is deliberately nonexistent so
    // the test needs no wallet fixture.
    let failures = parse_failures(|m| {
        vec![
            "prepare".into(),
            m.into(),
            "NoSuchAction".into(),
            "--wallet".into(),
            "does-not-exist.json".into(),
        ]
    });
    assert_all_parsed("prepare", failures);
}
