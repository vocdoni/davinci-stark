use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=WASM_BUILD_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let commit = std::env::var("WASM_BUILD_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(read_git_commit)
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=WASM_BUILD_COMMIT={commit}");
}

fn read_git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8(output.stdout).ok()?;
    let commit = commit.trim();
    if commit.is_empty() {
        None
    } else {
        Some(commit.to_string())
    }
}
