// Rust test fixture — intentionally vulnerable code for foxguard detection tests

use std::process::Command;

// rs/unsafe-block
fn unsafe_usage() {
    unsafe {
        let ptr = 0x1234 as *const i32;
        println!("{}", *ptr);
    }
}

// rs/transmute-usage
fn transmute_usage() {
    let x: u32 = unsafe { std::mem::transmute(1.0f32) };
}

// rs/no-command-injection
fn command_injection(user_input: &str) {
    Command::new(user_input).spawn().unwrap();
}

// rs/no-sql-injection
fn sql_injection(user_input: &str) {
    db.execute(format!("SELECT * FROM users WHERE id = {}", user_input));
}

// rs/no-weak-hash
fn weak_hash(data: &[u8]) {
    let _ = md5::compute(data);
    let _ = sha1::Sha1::from(data).digest();
}

// rs/no-hardcoded-secret
fn secrets() {
    let api_key = "sk-live-abcdef123456789";
    let password = "supersecret123";
    let secret_token = "ghp_xxxxxxxxxxxxxxxxxxxx";
}

// rs/tls-verify-disabled
fn tls_disabled() {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build();
}

// rs/no-ssrf
async fn ssrf(url: &str) {
    let _ = reqwest::get(url).await;
}

// rs/no-path-traversal
fn path_traversal(path: &str) {
    let _ = std::path::Path::new(path);
    let _ = std::path::PathBuf::from(path);
}

// rs/no-unwrap-in-lib
fn unwrap_usage() {
    let x: Option<i32> = Some(1);
    x.unwrap();
    x.expect("should exist");
}

// rs/pq-vulnerable-crypto
use rsa::RsaPrivateKey;
use p256::ecdsa::SigningKey;
use ed25519_dalek::SigningKey as Ed25519Key;

fn pq_vulnerable() {
    let key = rsa::RsaPrivateKey::new(&mut rng, 2048);
    let sk = p256::ecdsa::SigningKey::random(&mut rng);
    let ed_key = ed25519_dalek::SigningKey::generate(&mut rng);
}
