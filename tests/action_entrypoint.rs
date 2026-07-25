use std::process::Command;

#[test]
fn action_rejects_an_invalid_release_version_before_downloading() {
    let output = Command::new("bash")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/action/entrypoint.sh"))
        .env("INPUT_VERSION", "v0.12.0/../../untrusted")
        .output()
        .expect("run action entrypoint");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("Invalid foxguard release version"),
        "unexpected action output: {}",
        String::from_utf8_lossy(&output.stdout),
    );
}
