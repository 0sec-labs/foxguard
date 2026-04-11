// Multi-file Express fixture (issue #48). Companion to django_shop/.
//
// routes.js holds request sources; services.js holds dangerous sinks.
// The current taint engine is intraprocedural + same-file interprocedural,
// so cross-file flows from routes → services do NOT fire yet. This
// fixture pins that limit so the day issue #46 (cross-file summaries)
// lands, the expected counts in tests/realistic_fixtures.rs for this
// fixture need to be updated to include the new cross-file findings.
//
// Hand-counted expected findings under the current engine:
//   js/taint-xss-innerhtml : 1  (in-file, /render)

const express = require("express");
const services = require("./services");

const app = express();

// ─── In-file flow — should fire today ────────────────────────────────
app.get("/render", (req, res) => {
    // js/taint-xss-innerhtml — source and sink in the same function
    const html = req.query.html;
    res.send(`<div>${html}</div>`);
});

// ─── Cross-file flows — should fire after #46 lands ──────────────────
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

app.get("/static-render", (req, res) => {
    // tainted read and discarded; sink receives a literal
    const _ignored = req.query.html;
    void _ignored;
    res.send("<div>static</div>");
});

module.exports = app;
