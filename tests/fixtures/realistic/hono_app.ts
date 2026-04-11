// Realistic Hono app fixture (issue #35). Uses `c.req.query`,
// `c.req.param` and friends through helpers into XSS sinks.
//
// Hand-counted expected taint findings:
//   js/taint-xss-innerhtml : 3

import { Hono } from "hono";

const app = new Hono();

// ─── Helpers ───────────────────────────────────────────────────────────
function readQuery(c: any, key: string) {
    return c.req.query(key);
}

// ─── Routes ────────────────────────────────────────────────────────────
app.get("/greet", (c) => {
    // js/taint-xss-innerhtml — helper returns tainted query value
    const name = readQuery(c, "name");
    const el = document.getElementById("greet");
    if (el) el.innerHTML = `<p>Hello ${name}</p>`;
    return c.text("ok");
});

app.get("/user/:id", (c) => {
    // js/taint-xss-innerhtml — c.req.param
    const id = c.req.param("id");
    document.write(`<div>User ${id}</div>`);
    return c.text("ok");
});

app.get("/search", (c) => {
    // js/taint-xss-innerhtml — alias chain from c.req.query
    const raw = c.req.query("q");
    const term = raw;
    const el = document.getElementById("results");
    if (el) el.innerHTML = term;
    return c.text("ok");
});

// ─── NEAR MISS — must not fire ─────────────────────────────────────────
app.get("/health", (c) => {
    // NEAR MISS — literal argument
    const el = document.getElementById("h");
    if (el) el.innerHTML = "ok";
    return c.text("ok");
});

app.get("/noop", (c) => {
    // NEAR MISS — tainted value read but never reaches a sink
    const _q = c.req.query("q");
    document.write("<h1>noop</h1>");
    return c.text("ok");
});

export default app;
