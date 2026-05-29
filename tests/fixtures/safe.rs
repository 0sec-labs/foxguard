// Rust safe fixture — should not trigger built-in Rust rules.
//
// This file also exercises the false-positive guards added for the Rust
// rules: every construct below intentionally *looks* like a flagged pattern
// (mentions reqwest, contains "ed25519"/"transmute"/"md5"/"Path::new" as
// substrings, uses format!/Command) but must produce ZERO findings.

// A bare `use md5;` import is dead code, not a vulnerability: the weak-hash
// rule must only flag md5/sha1 at the call site, never the import.
#[allow(unused_imports)]
use md5;

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::process::Command;

// A SCREAMING_SNAKE_CASE constant binary name is a compile-time constant, so
// `Command::new(GIT_BINARY)` cannot carry attacker input.
const GIT_BINARY: &str = "git";

// Mentioning ed25519 in a constant name must not trip the PQ-crypto rule,
// which only matches the algorithm as a leading word of a call-path segment.
const MAX_ED25519_KEY_SIZE: usize = 32;

fn command_is_static() {
    let _ = Command::new("git").arg("--version").spawn();
}

fn command_uses_const() {
    let _ = Command::new(GIT_BINARY).arg("status").spawn();
}

// A user helper whose name merely contains "transmute" is not std::mem::transmute.
fn my_transmute_wrapper(value: u32) -> u32 {
    value.swap_bytes()
}

fn call_transmute_wrapper() {
    let _ = my_transmute_wrapper(42);
}

// A path-validation helper whose name contains "path_new" is not Path::new.
fn validate_path_new(input: &str) -> bool {
    !input.contains("..")
}

fn use_validate(input: &str) -> bool {
    validate_path_new(input)
}

fn parameterized_query(db: &Database, user_id: i64) {
    db.execute("SELECT * FROM users WHERE id = $1", &[user_id]);
}

// A format! with no interpolation placeholder is a constant string and cannot
// be a SQL injection vector.
fn static_query(db: &Database) {
    db.execute(format!("SELECT 1 FROM static_table"));
}

fn strong_hash(data: &[u8]) {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let _digest = hasher.finalize();
}

fn configured_secret() {
    let api_key = std::env::var("API_KEY").unwrap_or_default();
    println!("{}", api_key.len());
}

fn tls_defaults() {
    let _client = reqwest::Client::builder().build();
}

async fn static_url() {
    let _ = reqwest::get("https://api.example.com/health").await;
}

// A `.get(...)` on an unrelated type (e.g. a HashMap) must not be flagged as
// SSRF just because this file also mentions reqwest above.
fn map_get(map: &HashMap<String, String>, key: &str) -> Option<String> {
    map.get(key).cloned()
}

fn static_path() {
    let _ = std::path::Path::new("config/settings.toml");
}

fn avoid_unwrap(value: Option<i32>) -> i32 {
    value.unwrap_or_default()
}
