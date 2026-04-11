// Taint-tracking fixture for issue #18: every handler shows a different
// shape of untrusted Express input reaching an innerHTML/outerHTML sink
// or a document.write call. Each handler should produce exactly one
// js/taint-xss-innerhtml finding. The conservative js/no-xss-innerhtml
// and js/no-document-write rules coexist — two rules encode two
// different questions.

// ─── Direct: source flows into sink as the raw argument ───────────────
function direct(req) {
    document.getElementById("x").innerHTML = req.body;
}

// ─── One-hop: source assigned to a local, local flows into sink ───────
function oneHop(req) {
    const name = req.query.name;
    document.getElementById("x").innerHTML = name;
}

// ─── Express handler pattern: req is implicit via ParamName ───────────
app.get("/", function(req, res) {
    document.write(req.body.title);
});

// ─── Template literal with interpolation ──────────────────────────────
function templateLit(req) {
    const el = document.getElementById("x");
    el.innerHTML = `<p>${req.body.name}</p>`;
}

// ─── Alias chain ──────────────────────────────────────────────────────
function aliased(req) {
    const data = req.body.data;
    const moreData = data;
    document.write(moreData);
}

// ─── Subscript on a tainted root ──────────────────────────────────────
function subscripted(req) {
    document.write(req.body["payload"]);
}
