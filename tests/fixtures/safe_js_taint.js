// Negative fixture for js/taint-xss-innerhtml. None of these handlers
// have a provable flow from an untrusted source into innerHTML/
// document.write. The taint rule must stay silent. The conservative
// js/no-xss-innerhtml may still fire on the innerHTML assignments —
// that's the intended division of labor.

// Literal content is not tainted.
function staticHtml() {
    document.getElementById("x").innerHTML = "<p>static</p>";
}

// Reassignment with a clean literal kills prior taint.
function reassigned(req) {
    let data = req.body.data;
    data = "clean";
    document.write(data);
}

// `request` is a local variable here, not a parameter — not tainted.
function localNamedRequest() {
    const request = "safe";
    document.write(request);
}

// Cross-function: source in one function doesn't taint another.
function getData(req) {
    return req.body;
}

function consumer() {
    const x = "trusted";
    document.write(x);
}

// Same-file interprocedural v1: helper returns a literal, caller passes
// its result to a sink. Summary is clean, taint rule must not fire.
function cleanLiteralHelper() {
    return "static-helper";
}

function interproceduralCleanHelper() {
    document.write(cleanLiteralHelper());
}

// Method call on a literal receiver is not tainted (issue #27).
function literalMethodCall() {
    document.getElementById("x").innerHTML = "literal".toUpperCase();
}

// ─── Negative cases for LDAP false positives (issue #133) ───────────
// String.prototype.search() must NOT fire js/taint-ldap-injection.
function stringSearch(req) {
    const pattern = req.body.pattern;
    "hello world".search(pattern);
}

// Function.prototype.bind() must NOT fire js/taint-ldap-injection.
function functionBind(req) {
    const ctx = req.body.context;
    handler.bind(ctx);
}

// ─── Negative case for NoSQL false positives (issue #136) ───────────
// Array.prototype.find() must NOT fire js/taint-nosql-injection.
function arrayFind(req) {
    const tainted = req.body.value;
    [1, 2, 3].find(x => x === tainted);
}

// ─── Sanitizer tests (issue #139) ──────────────────────────────────
// Each handler flows tainted input through a sanitizer before reaching
// the sink. The taint rule must NOT fire.

// XSS sanitizers
function sanitizedXssDomPurify(req) {
    const dirty = req.body.html;
    const clean = DOMPurify.sanitize(dirty);
    document.getElementById("x").innerHTML = clean;
}

function sanitizedXssSanitizeHtml(req) {
    const dirty = req.body.html;
    const clean = sanitizeHtml(dirty);
    document.getElementById("x").innerHTML = clean;
}

function sanitizedXssXssPackage(req) {
    const dirty = req.body.html;
    const clean = xss(dirty);
    document.getElementById("x").innerHTML = clean;
}

function sanitizedXssEncodeURIComponent(req) {
    const dirty = req.body.html;
    const clean = encodeURIComponent(dirty);
    document.getElementById("x").innerHTML = clean;
}

// SQL injection sanitizers
function sanitizedSqlEscape(req) {
    const name = req.body.name;
    const safe = connection.escape(name);
    connection.query("SELECT * FROM users WHERE name = " + safe);
}

function sanitizedSqlEscapeLiteral(req) {
    const name = req.body.name;
    const safe = client.escapeLiteral(name);
    client.query("SELECT * FROM users WHERE name = " + safe);
}

// Command injection sanitizers
function sanitizedCmdShellescape(req) {
    const cmd = req.body.cmd;
    const safe = shellescape(cmd);
    child_process.exec(safe);
}

function sanitizedCmdEscapeShellArg(req) {
    const cmd = req.body.cmd;
    const safe = escapeShellArg(cmd);
    child_process.exec(safe);
}
