use std::sync::OnceLock;

use regex::Regex;

use crate::impl_rule;
use crate::rules::common::make_finding_from_offsets;
use crate::{Language, Severity};

/// Strip `#`-comment lines from config source, preserving byte offsets by
/// replacing comment content with spaces. This lets regex matches still
/// report correct positions.
fn strip_comments(source: &str) -> String {
    let mut out: Vec<u8> = source.as_bytes().to_vec();
    for line in source.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            let offset = line.as_ptr() as usize - source.as_ptr() as usize;
            for b in &mut out[offset..offset + line.len()] {
                *b = b' ';
            }
        }
    }
    // SAFETY: we only replaced ASCII bytes with ASCII spaces.
    String::from_utf8(out).expect("strip_comments produced invalid UTF-8")
}

// ─── Static regex helpers (compiled once) ────────────────────────────────────

fn nginx_protocols_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ssl_protocols\s+[^;]+;")
            .expect("static nginx protocols regex should compile")
    })
}

fn nginx_ciphers_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ssl_ciphers\s+[^;]+;").expect("static nginx ciphers regex should compile")
    })
}

fn apache_protocol_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)SSLProtocol\s+.+").expect("static Apache protocol regex should compile")
    })
}

fn apache_cipher_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)SSLCipherSuite\s+.+").expect("static Apache cipher regex should compile")
    })
}

fn haproxy_options_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ssl-default-bind-options\s+.+")
            .expect("static HAProxy options regex should compile")
    })
}

fn haproxy_ciphers_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ssl-default-bind-ciphers\s+.+")
            .expect("static HAProxy ciphers regex should compile")
    })
}

fn haproxy_ciphersuites_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ssl-default-bind-ciphersuites\s+.+")
            .expect("static HAProxy ciphersuites regex should compile")
    })
}

fn dockerfile_insecure_env_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?im)^(?:ENV|ARG)\s+.*(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|PYTHONHTTPSVERIFY\s*=\s*0|GIT_SSL_NO_VERIFY\s*=\s*(?:true|1)|CURL_CA_BUNDLE\s*=\s*(?:''|""|$)|REQUESTS_CA_BUNDLE\s*=\s*(?:''|""|$)|SSL_CERT_FILE\s*=\s*/dev/null)"#
        ).expect("static Dockerfile insecure env regex should compile")
    })
}

fn dockerfile_run_insecure_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?im)^RUN\s+.*(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|PYTHONHTTPSVERIFY\s*=\s*0|GIT_SSL_NO_VERIFY\s*=\s*(?:true|1)|curl\s+.*--insecure|curl\s+.*-k[\s|&;]|wget\s+.*--no-check-certificate)"#
        ).expect("static Dockerfile insecure RUN regex should compile")
    })
}

// ─── Rule 1: nginx PQ-vulnerable TLS ─────────────────────────────────────────

pub struct NginxPqVulnerableTls;

impl_rule! {
    NginxPqVulnerableTls,
    id = "config/nginx-pq-vulnerable-tls",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Nginx TLS configuration uses quantum-vulnerable protocols or ciphers",
    language = Language::NginxConf,
    // CNSA 2.0 class: web browsers/servers/cloud services (exclusive-use 2033)
    // per NSA CNSA 2.0 FAQ v2.1 (Dec 2024), transition timeline table.
    cnsa2_deadline = "2033",
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();
        let cleaned = strip_comments(source);

        // Detect ssl_protocols without TLSv1.3
        for m in nginx_protocols_re().find_iter(&cleaned) {
            let directive = m.as_str();
            if !directive.contains("TLSv1.3") {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "ssl_protocols lacks TLSv1.3 — required for post-quantum key exchange (X25519MLKEM768)",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        // Detect ssl_ciphers without PQ-safe suites
        for m in nginx_ciphers_re().find_iter(&cleaned) {
            let directive = m.as_str().to_uppercase();
            if !directive.contains("MLKEM") && !directive.contains("X25519MLKEM") {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "ssl_ciphers uses only classical key exchange — consider enabling PQ-safe cipher suites via oqs-provider",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        findings
    }
}

// ─── Rule 2: Apache PQ-vulnerable TLS ────────────────────────────────────────

pub struct ApachePqVulnerableTls;

impl_rule! {
    ApachePqVulnerableTls,
    id = "config/apache-pq-vulnerable-tls",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Apache TLS configuration uses quantum-vulnerable protocols or ciphers",
    language = Language::ApacheConf,
    // CNSA 2.0 class: web browsers/servers/cloud services (exclusive-use 2033)
    // per NSA CNSA 2.0 FAQ v2.1 (Dec 2024), transition timeline table.
    cnsa2_deadline = "2033",
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();
        let cleaned = strip_comments(source);

        // Detect SSLProtocol without TLSv1.3.
        // `SSLProtocol all` on modern Apache (2.4.30+) includes TLSv1.3,
        // so only flag when standalone `all` is absent AND TLSv1.3 isn't explicit.
        for m in apache_protocol_re().find_iter(&cleaned) {
            let directive = m.as_str();
            let upper = directive.to_uppercase();
            let has_all = upper.split_whitespace().any(|t| t == "ALL");
            let has_tls13 = directive.contains("TLSv1.3");
            if !has_all && !has_tls13 {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "SSLProtocol lacks TLSv1.3 — required for post-quantum key exchange",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        // Detect SSLCipherSuite without PQ-safe suites
        for m in apache_cipher_re().find_iter(&cleaned) {
            let directive = m.as_str().to_uppercase();
            if !directive.contains("MLKEM") && !directive.contains("X25519MLKEM") {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "SSLCipherSuite uses only classical key exchange — consider enabling PQ-safe cipher suites",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        findings
    }
}

// ─── Rule 3: HAProxy PQ-vulnerable TLS ───────────────────────────────────────

pub struct HAProxyPqVulnerableTls;

impl_rule! {
    HAProxyPqVulnerableTls,
    id = "config/haproxy-pq-vulnerable-tls",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "HAProxy TLS configuration uses quantum-vulnerable protocols or ciphers",
    language = Language::HAProxyConf,
    // CNSA 2.0 class: web browsers/servers/cloud services (exclusive-use 2033)
    // per NSA CNSA 2.0 FAQ v2.1 (Dec 2024). HAProxy typically fronts web
    // traffic, so its TLS stack is governed by the web-server milestone
    // rather than the router/VPN milestone.
    cnsa2_deadline = "2033",
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();
        let cleaned = strip_comments(source);

        // Detect ssl-default-bind-options without TLSv1.3
        for m in haproxy_options_re().find_iter(&cleaned) {
            let directive = m.as_str();
            if !directive.contains("ssl-min-ver TLSv1.3")
                && !directive.contains("min-ver TLSv1.3")
            {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "ssl-default-bind-options does not enforce TLSv1.3 minimum — required for post-quantum key exchange",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        // Detect ssl-default-bind-ciphers without PQ suites
        for m in haproxy_ciphers_re().find_iter(&cleaned) {
            let directive = m.as_str().to_uppercase();
            if !directive.contains("MLKEM") && !directive.contains("X25519MLKEM") {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "ssl-default-bind-ciphers uses only classical key exchange — consider enabling PQ-safe cipher suites",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        // Also check ssl-default-bind-ciphersuites (TLS 1.3 cipher config)
        for m in haproxy_ciphersuites_re().find_iter(&cleaned) {
            let directive = m.as_str().to_uppercase();
            if !directive.contains("MLKEM") && !directive.contains("X25519MLKEM") {
                findings.push(make_finding_from_offsets(
                    _self.id(),
                    _self.severity(),
                    _self.cwe(),
                    "ssl-default-bind-ciphersuites uses only classical key exchange — consider enabling PQ-safe cipher suites",
                    source,
                    m.start(),
                    m.end(),
                ));
            }
        }

        findings
    }
}

// ─── Rules: PQ-ready TLS (informational) ─────────────────────────────────────
//
// Positive counterparts to the `*-pq-vulnerable-tls` rules above: they fire
// when a TLS config already negotiates a hybrid post-quantum key exchange
// (e.g. `ssl_ecdh_curve X25519MLKEM768;`). Findings are informational
// (`Severity::Low`, tagged `PQ-READY`) and declare no CNSA deadline — a server
// offering PQ key exchange is ahead on migration, not misconfigured.

pub struct NginxPqReadyTls;

impl_rule! {
    NginxPqReadyTls,
    id = "config/nginx-pq-ready-tls",
    severity = Severity::Low,
    cwe = None,
    description = "Nginx TLS configuration negotiates a post-quantum / hybrid key exchange (X25519MLKEM768)",
    language = Language::NginxConf,
    fn check(_self, source, _tree) {
        crate::rules::pq::pq_ready_findings(_self.id(), &strip_comments(source))
    }
}

pub struct ApachePqReadyTls;

impl_rule! {
    ApachePqReadyTls,
    id = "config/apache-pq-ready-tls",
    severity = Severity::Low,
    cwe = None,
    description = "Apache TLS configuration negotiates a post-quantum / hybrid key exchange (X25519MLKEM768)",
    language = Language::ApacheConf,
    fn check(_self, source, _tree) {
        crate::rules::pq::pq_ready_findings(_self.id(), &strip_comments(source))
    }
}

pub struct HAProxyPqReadyTls;

impl_rule! {
    HAProxyPqReadyTls,
    id = "config/haproxy-pq-ready-tls",
    severity = Severity::Low,
    cwe = None,
    description = "HAProxy TLS configuration negotiates a post-quantum / hybrid key exchange (X25519MLKEM768)",
    language = Language::HAProxyConf,
    fn check(_self, source, _tree) {
        crate::rules::pq::pq_ready_findings(_self.id(), &strip_comments(source))
    }
}

// ─── Rule 4: Dockerfile insecure TLS environment ─────────────────────────────

pub struct DockerfileInsecureTlsEnv;

impl_rule! {
    DockerfileInsecureTlsEnv,
    id = "config/dockerfile-insecure-tls-env",
    severity = Severity::High,
    cwe = Some("CWE-295"),
    description = "Dockerfile disables TLS certificate verification via environment variable or insecure command",
    language = Language::Dockerfile,
    // CNSA 2.0 class: containers are a cloud-services deployment surface;
    // the TLS configuration this rule flags is the same PKI/TLS stack that
    // governs browsers and web servers. Per NSA CNSA 2.0 FAQ v2.1
    // (Dec 2024), cloud services must exclusively use CNSA 2.0 by 2033.
    cnsa2_deadline = "2033",
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();
        let cleaned = strip_comments(source);

        // ENV/ARG lines that disable TLS verification
        for m in dockerfile_insecure_env_re().find_iter(&cleaned) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "Dockerfile disables TLS verification — containers will accept any certificate, enabling MITM attacks",
                source,
                m.start(),
                m.end(),
            ));
        }

        // RUN lines that disable TLS verification
        for m in dockerfile_run_insecure_re().find_iter(&cleaned) {
            findings.push(make_finding_from_offsets(
                _self.id(),
                _self.severity(),
                _self.cwe(),
                "Dockerfile RUN command disables TLS verification — containers will accept any certificate, enabling MITM attacks",
                source,
                m.start(),
                m.end(),
            ));
        }

        findings
    }
}
