export interface Rule {
  id: string;
  cwe: string;
  desc: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface RuleGroup {
  name: string;
  slug: string;
  rules: Rule[];
}

const jsRules: Rule[] = [
  { id: 'js/no-eval', cwe: 'CWE-95', desc: 'Use of eval() allows arbitrary code execution', severity: 'critical' },
  { id: 'js/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'js/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation or template literal', severity: 'critical' },
  { id: 'js/no-xss-innerhtml', cwe: 'CWE-79', desc: 'Assignment to innerHTML may lead to XSS', severity: 'high' },
  { id: 'js/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via exec/spawn with dynamic input', severity: 'critical' },
  { id: 'js/no-document-write', cwe: 'CWE-79', desc: 'document.write() with dynamic content enables XSS', severity: 'high' },
  { id: 'js/no-open-redirect', cwe: 'CWE-601', desc: 'Open redirect via user-controlled URL', severity: 'medium' },
  { id: 'js/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'js/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via unsanitized user input', severity: 'high' },
  { id: 'js/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via dynamic outbound request URL', severity: 'high' },
  { id: 'js/no-prototype-pollution', cwe: 'CWE-1321', desc: 'Prototype pollution via object merge', severity: 'high' },
  { id: 'js/no-unsafe-regex', cwe: 'CWE-1333', desc: 'ReDoS-vulnerable regular expression', severity: 'medium' },
  { id: 'js/no-cors-star', cwe: 'CWE-942', desc: 'Permissive CORS policy (Access-Control-Allow-Origin: *)', severity: 'medium' },
  { id: 'js/express-no-hardcoded-session-secret', cwe: 'CWE-798', desc: 'Hardcoded session secret in express-session config', severity: 'high' },
  { id: 'js/express-cookie-no-secure', cwe: 'CWE-614', desc: 'Cookie config missing secure flag', severity: 'medium' },
  { id: 'js/express-cookie-no-httponly', cwe: 'CWE-1004', desc: 'Cookie config missing httpOnly flag', severity: 'medium' },
  { id: 'js/express-cookie-no-samesite', cwe: 'CWE-352', desc: 'Cookie config missing a safe sameSite setting', severity: 'medium' },
  { id: 'js/express-session-saveuninitialized-true', cwe: 'CWE-359', desc: 'express-session configured with saveUninitialized: true', severity: 'medium' },
  { id: 'js/express-session-resave-true', cwe: 'CWE-384', desc: 'express-session configured with resave: true', severity: 'medium' },
  { id: 'js/express-direct-response-write', cwe: 'CWE-79', desc: 'XSS via res.send/res.write with user input', severity: 'high' },
  { id: 'js/jwt-hardcoded-secret', cwe: 'CWE-798', desc: 'JWT signing or verification with a hardcoded secret', severity: 'high' },
  { id: 'js/jwt-none-algorithm', cwe: 'CWE-347', desc: 'JWT configured to use the none algorithm', severity: 'high' },
  { id: 'js/jwt-ignore-expiration', cwe: 'CWE-613', desc: 'JWT verification configured to ignore token expiration', severity: 'high' },
  { id: 'js/jwt-decode-without-verify', cwe: 'CWE-347', desc: 'JWT decoded without signature verification', severity: 'high' },
  { id: 'js/jwt-verify-missing-algorithms', cwe: 'CWE-347', desc: 'JWT verification without an explicit algorithms allowlist', severity: 'high' },
  { id: 'js/no-unsafe-format-string', cwe: 'CWE-134', desc: 'Template literal with variables in logging function may enable log injection', severity: 'medium' },
  { id: 'js/taint-xss-innerhtml', cwe: 'CWE-79', desc: 'Untrusted input reaches innerHTML or document.write sink', severity: 'high' },
];

const pyRules: Rule[] = [
  { id: 'py/no-eval', cwe: 'CWE-95', desc: 'Use of eval()/exec() allows arbitrary code execution', severity: 'critical' },
  { id: 'py/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'py/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string formatting', severity: 'critical' },
  { id: 'py/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via os.system/subprocess', severity: 'critical' },
  { id: 'py/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via unsanitized user input', severity: 'high' },
  { id: 'py/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via dynamic outbound request URL', severity: 'high' },
  { id: 'py/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'py/no-pickle', cwe: 'CWE-502', desc: 'Deserialization of untrusted data via pickle', severity: 'high' },
  { id: 'py/taint-pickle-deserialization', cwe: 'CWE-502', desc: 'Untrusted input reaches pickle deserialization (intraprocedural taint)', severity: 'critical' },
  { id: 'py/taint-eval', cwe: 'CWE-95', desc: 'Untrusted input reaches eval/exec (intraprocedural taint)', severity: 'critical' },
  { id: 'py/taint-command-injection', cwe: 'CWE-78', desc: 'Untrusted input reaches OS command execution (intraprocedural taint)', severity: 'critical' },
  { id: 'py/taint-ssrf', cwe: 'CWE-918', desc: 'Untrusted input reaches outbound HTTP call (intraprocedural taint)', severity: 'high' },
  { id: 'py/taint-yaml-load', cwe: 'CWE-502', desc: 'Untrusted input reaches unsafe YAML loader (intraprocedural taint)', severity: 'critical' },
  { id: 'py/taint-sql-injection', cwe: 'CWE-89', desc: 'Untrusted input reaches SQL execute sink (intraprocedural taint)', severity: 'critical' },
  { id: 'py/no-yaml-load', cwe: 'CWE-502', desc: 'Unsafe yaml.load() without SafeLoader', severity: 'high' },
  { id: 'py/no-debug-true', cwe: 'CWE-489', desc: 'DEBUG=True left enabled in production config', severity: 'medium' },
  { id: 'py/no-open-redirect', cwe: 'CWE-601', desc: 'Open redirect via user-controlled URL', severity: 'medium' },
  { id: 'py/no-cors-star', cwe: 'CWE-942', desc: 'Permissive CORS policy (CORS_ALLOW_ALL_ORIGINS)', severity: 'medium' },
  { id: 'py/flask-debug-mode', cwe: 'CWE-489', desc: 'Flask app.run(debug=True) exposes debugger in production', severity: 'high' },
  { id: 'py/django-secret-key-hardcoded', cwe: 'CWE-798', desc: 'Django SECRET_KEY hardcoded in source', severity: 'high' },
  { id: 'py/flask-secret-key-hardcoded', cwe: 'CWE-798', desc: 'Flask SECRET_KEY hardcoded in source', severity: 'high' },
  { id: 'py/session-cookie-secure-disabled', cwe: 'CWE-614', desc: 'SESSION_COOKIE_SECURE disabled in source', severity: 'medium' },
  { id: 'py/session-cookie-httponly-disabled', cwe: 'CWE-1004', desc: 'SESSION_COOKIE_HTTPONLY disabled in source', severity: 'medium' },
  { id: 'py/session-cookie-samesite-disabled', cwe: 'CWE-352', desc: 'SESSION_COOKIE_SAMESITE disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-secure-disabled', cwe: 'CWE-614', desc: 'CSRF_COOKIE_SECURE disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-httponly-disabled', cwe: 'CWE-1004', desc: 'CSRF_COOKIE_HTTPONLY disabled in source', severity: 'medium' },
  { id: 'py/csrf-cookie-samesite-disabled', cwe: 'CWE-352', desc: 'CSRF_COOKIE_SAMESITE disabled in source', severity: 'medium' },
  { id: 'py/csrf-exempt', cwe: 'CWE-352', desc: 'View marked csrf_exempt', severity: 'high' },
  { id: 'py/wtf-csrf-disabled', cwe: 'CWE-352', desc: 'Flask-WTF CSRF protection disabled in source', severity: 'high' },
  { id: 'py/wtf-csrf-check-default-disabled', cwe: 'CWE-352', desc: 'Flask-WTF default CSRF checks disabled in source', severity: 'high' },
  { id: 'py/django-allowed-hosts-wildcard', cwe: 'CWE-346', desc: 'Django ALLOWED_HOSTS allows all hosts', severity: 'medium' },
  { id: 'py/secure-ssl-redirect-disabled', cwe: 'CWE-319', desc: 'Django SECURE_SSL_REDIRECT disabled in source', severity: 'medium' },
];

const goRules: Rule[] = [
  { id: 'go/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation or fmt.Sprintf', severity: 'critical' },
  { id: 'go/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via exec.Command with dynamic input', severity: 'critical' },
  { id: 'go/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'go/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (MD5/SHA1)', severity: 'medium' },
  { id: 'go/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via http.Get/http.Post with variable URL', severity: 'high' },
  { id: 'go/insecure-tls-skip-verify', cwe: 'CWE-295', desc: 'TLS verification disabled with InsecureSkipVerify', severity: 'high' },
  { id: 'go/gin-no-trusted-proxies', cwe: 'CWE-346', desc: 'Gin engine without SetTrustedProxies', severity: 'medium' },
  { id: 'go/net-http-no-timeout', cwe: 'CWE-400', desc: 'http.ListenAndServe without timeout config', severity: 'medium' },
];

const rubyRules: Rule[] = [
  { id: 'rb/no-eval', cwe: 'CWE-94', desc: 'Use of eval/instance_eval/class_eval allows arbitrary code execution', severity: 'critical' },
  { id: 'rb/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via system/exec/spawn or backtick execution', severity: 'critical' },
  { id: 'rb/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string interpolation in ActiveRecord queries', severity: 'critical' },
  { id: 'rb/no-mass-assignment', cwe: 'CWE-915', desc: 'permit! allows all parameters through without filtering', severity: 'high' },
  { id: 'rb/no-unsafe-deserialization', cwe: 'CWE-502', desc: 'Marshal.load or YAML.load on untrusted data enables RCE', severity: 'critical' },
  { id: 'rb/no-open-redirect', cwe: 'CWE-601', desc: 'redirect_to with user-controlled input', severity: 'high' },
  { id: 'rb/no-csrf-skip', cwe: 'CWE-352', desc: 'skip_before_action :verify_authenticity_token disables CSRF', severity: 'high' },
  { id: 'rb/no-html-safe', cwe: 'CWE-79', desc: 'html_safe or raw() on user input disables XSS auto-escaping', severity: 'high' },
  { id: 'rb/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'rb/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak cryptographic hash (Digest::MD5/SHA1)', severity: 'medium' },
];

const javaRules: Rule[] = [
  { id: 'java/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation in query methods', severity: 'critical' },
  { id: 'java/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via Runtime.exec or ProcessBuilder', severity: 'critical' },
  { id: 'java/no-unsafe-deserialization', cwe: 'CWE-502', desc: 'Unsafe deserialization via ObjectInputStream or YAML.load', severity: 'critical' },
  { id: 'java/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via new URL() or RestTemplate with dynamic URL', severity: 'high' },
  { id: 'java/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via new File/FileInputStream with dynamic path', severity: 'high' },
  { id: 'java/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak crypto algorithm (DES, MD5, SHA-1, ECB)', severity: 'medium' },
  { id: 'java/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'java/no-xxe', cwe: 'CWE-611', desc: 'XML parser without external entity protection', severity: 'high' },
  { id: 'java/spring-csrf-disabled', cwe: 'CWE-352', desc: 'Spring Security CSRF protection disabled', severity: 'high' },
  { id: 'java/spring-cors-permissive', cwe: 'CWE-942', desc: 'CORS configured with wildcard origin', severity: 'medium' },
];

const phpRules: Rule[] = [
  { id: 'php/no-eval', cwe: 'CWE-95', desc: 'Use of eval() allows arbitrary code execution', severity: 'critical' },
  { id: 'php/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via exec/system/passthru/shell_exec', severity: 'critical' },
  { id: 'php/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via interpolated or concatenated query strings', severity: 'critical' },
  { id: 'php/no-unserialize', cwe: 'CWE-502', desc: 'unserialize() on untrusted data enables object injection', severity: 'critical' },
  { id: 'php/no-file-inclusion', cwe: 'CWE-98', desc: 'Dynamic file inclusion via include/require with variable path', severity: 'critical' },
  { id: 'php/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak hash function (md5/sha1)', severity: 'medium' },
  { id: 'php/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'php/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via file_get_contents/curl_init with dynamic URL', severity: 'high' },
  { id: 'php/no-extract', cwe: 'CWE-621', desc: 'extract() creates arbitrary variables from user input', severity: 'high' },
  { id: 'php/no-preg-eval', cwe: 'CWE-95', desc: 'preg_replace with /e modifier executes matched string as PHP', severity: 'critical' },
];

const rustRules: Rule[] = [
  { id: 'rs/unsafe-block', cwe: 'CWE-676', desc: 'Unsafe block bypasses Rust safety guarantees', severity: 'medium' },
  { id: 'rs/transmute-usage', cwe: 'CWE-843', desc: 'std::mem::transmute reinterprets types unsafely', severity: 'high' },
  { id: 'rs/no-command-injection', cwe: 'CWE-78', desc: 'Command::new with non-literal argument', severity: 'critical' },
  { id: 'rs/no-sql-injection', cwe: 'CWE-89', desc: 'format! macro in SQL query argument', severity: 'critical' },
  { id: 'rs/no-weak-hash', cwe: 'CWE-328', desc: 'Use of MD5 or SHA1 hash', severity: 'medium' },
  { id: 'rs/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'rs/tls-verify-disabled', cwe: 'CWE-295', desc: 'TLS certificate verification disabled', severity: 'high' },
  { id: 'rs/no-ssrf', cwe: 'CWE-918', desc: 'reqwest request with non-literal URL', severity: 'high' },
  { id: 'rs/no-path-traversal', cwe: 'CWE-22', desc: 'Path::new/PathBuf::from with non-literal argument', severity: 'high' },
  { id: 'rs/no-unwrap-in-lib', cwe: 'CWE-248', desc: 'unwrap()/expect() may panic at runtime', severity: 'medium' },
];

const csharpRules: Rule[] = [
  { id: 'cs/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string concatenation in query methods', severity: 'critical' },
  { id: 'cs/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via Process.Start with dynamic input', severity: 'critical' },
  { id: 'cs/no-unsafe-deserialization', cwe: 'CWE-502', desc: 'Unsafe deserialization via BinaryFormatter or JavaScriptSerializer', severity: 'critical' },
  { id: 'cs/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via HttpClient or WebRequest with dynamic URL', severity: 'high' },
  { id: 'cs/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via File/StreamReader with dynamic path', severity: 'high' },
  { id: 'cs/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak crypto (MD5, SHA1, DES, RC2)', severity: 'medium' },
  { id: 'cs/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'cs/no-xxe', cwe: 'CWE-611', desc: 'XML parser without external entity protection', severity: 'high' },
  { id: 'cs/no-ldap-injection', cwe: 'CWE-90', desc: 'LDAP injection via string concatenation in filter', severity: 'high' },
  { id: 'cs/no-cors-star', cwe: 'CWE-942', desc: 'CORS configured with AllowAnyOrigin', severity: 'medium' },
];

const swiftRules: Rule[] = [
  { id: 'swift/no-hardcoded-secret', cwe: 'CWE-798', desc: 'Hardcoded secret or credential detected', severity: 'high' },
  { id: 'swift/no-command-injection', cwe: 'CWE-78', desc: 'Command injection via Process with dynamic arguments', severity: 'critical' },
  { id: 'swift/no-weak-crypto', cwe: 'CWE-327', desc: 'Use of weak hash (CC_MD5, CC_SHA1)', severity: 'medium' },
  { id: 'swift/no-insecure-transport', cwe: 'CWE-319', desc: 'HTTP URL detected (insecure transport)', severity: 'high' },
  { id: 'swift/no-eval-js', cwe: 'CWE-95', desc: 'JavaScript injection via evaluateJavaScript with dynamic input', severity: 'critical' },
  { id: 'swift/no-sql-injection', cwe: 'CWE-89', desc: 'SQL injection via string interpolation', severity: 'critical' },
  { id: 'swift/no-insecure-keychain', cwe: 'CWE-311', desc: 'Keychain item accessible when device is unlocked', severity: 'high' },
  { id: 'swift/no-tls-disabled', cwe: 'CWE-295', desc: 'TLS certificate validation disabled', severity: 'high' },
  { id: 'swift/no-path-traversal', cwe: 'CWE-22', desc: 'Path traversal via FileManager with dynamic path', severity: 'high' },
  { id: 'swift/no-ssrf', cwe: 'CWE-918', desc: 'SSRF via URLSession with dynamic URL', severity: 'high' },
];

export const ruleGroups: RuleGroup[] = [
  { name: 'JavaScript / TypeScript', slug: 'js', rules: jsRules },
  { name: 'Python', slug: 'py', rules: pyRules },
  { name: 'Go', slug: 'go', rules: goRules },
  { name: 'Ruby', slug: 'rb', rules: rubyRules },
  { name: 'Java', slug: 'java', rules: javaRules },
  { name: 'PHP', slug: 'php', rules: phpRules },
  { name: 'Rust', slug: 'rs', rules: rustRules },
  { name: 'C#', slug: 'cs', rules: csharpRules },
  { name: 'Swift', slug: 'swift', rules: swiftRules },
];

export const totalRules = ruleGroups.reduce((sum, g) => sum + g.rules.length, 0);
export const productLanguageCount = 10;
