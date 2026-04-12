// Multi-file Express fixture (issue #48). Companion to django_shop/.
//
// routes.js holds request sources; services.js holds dangerous sinks.
// Cross-file taint analysis (issue #46) resolves require("./services")
// to services.js and fires when tainted arguments reach sinks defined
// in the imported module.
//
// Hand-counted expected taint findings:
//   js/taint-sql-injection        : 2  (in-file /user + cross-file /search → runQuery)
//   js/taint-command-injection    : 1  (in-file /exec handler)
//   js/taint-eval                 : 2  (in-file /eval + cross-file /import → evalExpression)

const express = require("express");
const child_process = require("child_process");
const services = require("./services");

const app = express();
const db = { query(_q) { return []; } };

// ─── In-file flow — should fire today ────────────────────────────────
app.get("/user", (req, res) => {
    // js/taint-sql-injection — source and sink in the same function
    const name = req.query.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
    res.send("ok");
});

// ─── In-file flow — command injection ────────────────────────────────
app.get("/exec", (req, res) => {
    // js/taint-command-injection — source and sink in the same function
    const cmd = req.query.cmd;
    child_process.exec(cmd);
    res.send("ok");
});

// ─── In-file flow — eval injection ──────────────────────────────────
app.get("/eval", (req, res) => {
    // js/taint-eval — source and sink in the same function
    const expr = req.query.expr;
    eval(expr);
    res.send("ok");
});

// ─── Cross-file flows — fire via cross-file taint summaries (#46) ────
app.get("/search", (req, res) => {
    // Cross-file: source in routes.js, sink in services.js.
    const name = req.query.name;
    const rows = services.runQuery(name);
    res.json({ rows });
});

app.post("/import", (req, res) => {
    // Cross-file: tainted body into services.evalExpression.
    const expr = req.body.expr;
    res.send(String(services.evalExpression(expr)));
});

// ─── NEAR-MISS — must not fire ───────────────────────────────────────
app.get("/healthz", (_req, res) => {
    // literal, no source
    res.send("<div>ok</div>");
});

app.get("/static-query", (req, res) => {
    // tainted read and discarded; sink receives a literal
    const _ignored = req.query.name;
    void _ignored;
    db.query("SELECT * FROM users WHERE name = 'admin'");
    res.send("ok");
});

module.exports = app;
