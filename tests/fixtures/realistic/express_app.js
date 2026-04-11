// Realistic Express app fixture (issue #35). Mixes req.body, req.query
// and req.params flowing into XSS sinks (innerHTML, document.write),
// exercises helper functions, and includes NEAR-MISS cases.
//
// Hand-counted expected taint findings:
//   js/taint-xss-innerhtml : 5

const express = require("express");
const app = express();
app.use(express.json());

// ─── Helpers ───────────────────────────────────────────────────────────
function extractName(req) {
    return req.body.name;
}

function getSearchTerm(req) {
    return req.query.q;
}

// ─── Routes ────────────────────────────────────────────────────────────
app.post("/profile", function (req, res) {
    // js/taint-xss-innerhtml — helper returns tainted body field
    const name = extractName(req);
    document.getElementById("profile").innerHTML = name;
    res.send("ok");
});

app.get("/search", function (req, res) {
    // js/taint-xss-innerhtml — helper + template literal
    const term = getSearchTerm(req);
    document.getElementById("results").innerHTML = `<h2>Results for ${term}</h2>`;
    res.send("ok");
});

app.get("/user/:id", function (req, res) {
    // js/taint-xss-innerhtml — req.params
    const id = req.params.id;
    document.write(`<div>User ${id}</div>`);
    res.send("ok");
});

app.post("/comment", function (req, res) {
    // js/taint-xss-innerhtml — req.body subscript
    const text = req.body["text"];
    document.getElementById("comments").innerHTML = text;
    res.send("ok");
});

app.get("/about", function (req, res) {
    // js/taint-xss-innerhtml — req.query alias chain
    const raw = req.query.bio;
    const bio = raw;
    document.write(bio);
    res.send("ok");
});

// ─── NEAR MISS — must not fire ─────────────────────────────────────────
app.get("/health", function (req, res) {
    // NEAR MISS — literal argument
    document.getElementById("h").innerHTML = "ok";
    res.send("ok");
});

app.get("/static", function (req, res) {
    // NEAR MISS — tainted read but discarded, sink gets a literal
    const _ignored = req.query.q;
    document.write("<h1>Hello</h1>");
    res.send("ok");
});

app.get("/safe", function (req, res) {
    // NEAR MISS — tainted value reassigned to a literal before sink
    let msg = req.query.msg;
    msg = "welcome";
    document.getElementById("m").innerHTML = msg;
    res.send("ok");
});

app.listen(3000);
