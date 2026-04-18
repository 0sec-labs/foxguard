use regex::Regex;

use crate::impl_rule;
use crate::rules::common::make_finding_from_offsets;
use crate::{Language, Severity};

// ─── Rule 1: nginx PQ-vulnerable TLS ─────────────────────────────────────────

pub struct NginxPqVulnerableTls;

impl_rule! {
    NginxPqVulnerableTls,
    id = "config/nginx-pq-vulnerable-tls",
    severity = Severity::Medium,
    cwe = Some("CWE-327"),
    description = "Nginx TLS configuration uses quantum-vulnerable protocols or ciphers",
    language = Language::NginxConf,
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();

        // Detect ssl_protocols without TLSv1.3
        let protocols_re = Regex::new(r"(?i)ssl_protocols\s+[^;]+;").unwrap();
        for m in protocols_re.find_iter(source) {
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
        let ciphers_re = Regex::new(r"(?i)ssl_ciphers\s+[^;]+;").unwrap();
        for m in ciphers_re.find_iter(source) {
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
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();

        // Detect SSLProtocol without TLSv1.3
        let protocol_re = Regex::new(r"(?i)SSLProtocol\s+.+").unwrap();
        for m in protocol_re.find_iter(source) {
            let directive = m.as_str();
            if !directive.contains("TLSv1.3") {
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
        let cipher_re = Regex::new(r"(?i)SSLCipherSuite\s+.+").unwrap();
        for m in cipher_re.find_iter(source) {
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
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();

        // Detect ssl-default-bind-options without TLSv1.3
        let options_re = Regex::new(r"(?i)ssl-default-bind-options\s+.+").unwrap();
        for m in options_re.find_iter(source) {
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
        let ciphers_re = Regex::new(r"(?i)ssl-default-bind-ciphers\s+.+").unwrap();
        for m in ciphers_re.find_iter(source) {
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

        findings
    }
}

// ─── Rule 4: Dockerfile insecure TLS environment ─────────────────────────────

pub struct DockerfileInsecureTlsEnv;

impl_rule! {
    DockerfileInsecureTlsEnv,
    id = "config/dockerfile-insecure-tls-env",
    severity = Severity::High,
    cwe = Some("CWE-295"),
    description = "Dockerfile disables TLS certificate verification via environment variable",
    language = Language::Dockerfile,
    fn check(_self, source, _tree) {
        let mut findings = Vec::new();

        let insecure_env_re = Regex::new(
            r#"(?im)^(?:ENV|ARG)\s+.*(?:NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|PYTHONHTTPSVERIFY\s*=\s*0|GIT_SSL_NO_VERIFY\s*=\s*(?:true|1)|CURL_CA_BUNDLE\s*=\s*(?:''|""|$)|REQUESTS_CA_BUNDLE\s*=\s*(?:''|""|$)|SSL_CERT_FILE\s*=\s*/dev/null)"#
        ).unwrap();

        for m in insecure_env_re.find_iter(source) {
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

        findings
    }
}
