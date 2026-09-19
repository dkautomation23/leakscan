//! End-to-end checks that run the built binary directly - for behaviour that
//! lives at the CLI boundary (files left on disk) and has no single function
//! worth unit testing in isolation.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_leakscan"))
}

#[test]
fn an_existing_json_report_is_left_untouched_without_force() {
    let dir = std::env::temp_dir().join(format!("leakscan-force-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::fs::write(dir.join("hello.txt"), "hello world, nothing sensitive here\n").expect("write fixture file");
    let report = dir.join("report.json");
    std::fs::write(&report, "sentinel - do not overwrite me").expect("write sentinel");

    let output = bin().arg(&dir).args(["--json"]).arg(&report).output().expect("run leakscan");

    let contents = std::fs::read_to_string(&report).expect("report file should still exist");
    assert_eq!(contents, "sentinel - do not overwrite me", "an existing --json file must not be overwritten without --force");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--force"), "refusal should explain how to force the overwrite, got: {stderr}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn force_overwrites_an_existing_json_report() {
    let dir = std::env::temp_dir().join(format!("leakscan-force-test-yes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    std::fs::write(dir.join("hello.txt"), "hello world, nothing sensitive here\n").expect("write fixture file");
    let report = dir.join("report.json");
    std::fs::write(&report, "sentinel - do not overwrite me").expect("write sentinel");

    let status = bin().arg(&dir).args(["--json"]).arg(&report).arg("--force").status().expect("run leakscan");
    assert!(status.success());

    let contents = std::fs::read_to_string(&report).expect("report file should still exist");
    assert!(contents.contains("files_scanned"), "the real report should have been written over the sentinel: {contents:?}");

    std::fs::remove_dir_all(&dir).ok();
}
