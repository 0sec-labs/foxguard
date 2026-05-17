// Rust safe fixture — should not trigger built-in Rust rules.

use sha2::{Digest, Sha256};
use std::process::Command;

fn command_is_static() {
    let _ = Command::new("git").arg("--version").spawn();
}

fn parameterized_query(db: &Database, user_id: i64) {
    db.execute("SELECT * FROM users WHERE id = $1", &[user_id]);
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

fn static_path() {
    let _ = std::path::Path::new("config/settings.toml");
}

fn avoid_unwrap(value: Option<i32>) -> i32 {
    value.unwrap_or_default()
}
