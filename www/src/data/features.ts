export interface Feature {
  icon: string;
  title: string;
  desc: string;
}

export const features: Feature[] = [
  {
    icon: 'taint',
    title: 'Cross-file taint tracking',
    desc: 'Trace untrusted input across file boundaries. Source in one file, sink in another — the engine connects them.',
  },
  {
    icon: 'diff',
    title: 'Branch diffing',
    desc: 'foxguard diff main shows only new findings your branch introduces. No noise from existing code.',
  },
  {
    icon: 'pr',
    title: 'PR review comments',
    desc: '--github-pr posts findings as inline review comments directly on pull requests.',
  },
  {
    icon: 'fix',
    title: 'Fix suggestions',
    desc: 'Every taint finding includes a concrete fix with safe code patterns. --explain shows full dataflow traces.',
  },
  {
    icon: 'secret',
    title: 'Secrets scanning',
    desc: 'Detect leaked credentials and private keys with redacted output in the same tool.',
  },
  {
    icon: 'yaml',
    title: 'Semgrep YAML bridge',
    desc: 'Load existing Semgrep/OpenGrep rules with --rules. Loads ~98% of the public Semgrep/OpenGrep registry, parity-tested in CI.',
  },
];

export interface FrameworkGroup {
  title: string;
  desc: string;
  badges: string[];
}

export const frameworkGroups: FrameworkGroup[] = [
  {
    title: 'Express / Node',
    desc: 'Session secrets, cookie flags, JWT hardening, reflected response writes.',
    badges: ['session', 'cookies', 'jwt', 'xss'],
  },
  {
    title: 'Flask / Django',
    desc: 'Secret keys, debug mode, CSRF protection, session cookie flags, and Django host/redirect hardening.',
    badges: ['secret keys', 'csrf', 'session', 'debug'],
  },
  {
    title: 'Gin / net/http',
    desc: 'Trusted proxies, missing timeouts, SSRF, TLS verification bypass.',
    badges: ['proxies', 'timeouts', 'ssrf', 'tls'],
  },
  {
    title: 'Rails / Ruby',
    desc: 'Mass assignment, CSRF bypass, unsafe deserialization, XSS escaping.',
    badges: ['params', 'csrf', 'marshal', 'xss'],
  },
  {
    title: 'Spring / Java',
    desc: 'SQL injection, XXE, deserialization, CSRF config, CORS policy.',
    badges: ['sql', 'xxe', 'csrf', 'cors'],
  },
  {
    title: 'PHP / Laravel',
    desc: 'Eval, file inclusion, unserialize, command injection, extract.',
    badges: ['eval', 'include', 'unserialize', 'ssrf'],
  },
  {
    title: 'Rust',
    desc: 'Unsafe blocks, transmute, command injection, TLS verification.',
    badges: ['unsafe', 'transmute', 'tls', 'unwrap'],
  },
  {
    title: 'C# / .NET',
    desc: 'SQL injection, deserialization, XXE, LDAP injection, CORS.',
    badges: ['sql', 'xxe', 'ldap', 'cors'],
  },
  {
    title: 'Kotlin / Ktor',
    desc: 'SQL injection, command injection, SSRF, deserialization, JWT, taint tracking with Ktor + Spring Boot sources.',
    badges: ['sql', 'cmd', 'ssrf', 'taint'],
  },
  {
    title: 'Swift / iOS',
    desc: 'Keychain security, transport security, JS injection, TLS.',
    badges: ['keychain', 'tls', 'transport', 'webview'],
  },
];

export interface CompatFeature {
  label: string;
  supported: boolean;
}

export const compatFeatures: CompatFeature[] = [
  { label: 'pattern', supported: true },
  { label: 'pattern-regex', supported: true },
  { label: 'pattern-either', supported: true },
  { label: 'pattern-not', supported: true },
  { label: 'pattern-not-regex', supported: true },
  { label: 'pattern-inside', supported: true },
  { label: 'pattern-not-inside', supported: true },
  { label: 'patterns (AND)', supported: true },
  { label: 'metavariable-regex', supported: true },
  { label: 'paths.include/exclude', supported: true },
  { label: 'Full Semgrep syntax', supported: false },
];
