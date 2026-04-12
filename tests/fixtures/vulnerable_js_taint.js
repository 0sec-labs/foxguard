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

// ─── Same-file helper return propagation (issue #19, v1) ─────────────
// Function-declaration helper: pass 1 summarizes its return as tainted,
// pass 2 lets the caller's local pick up that taint.
function getUserInputFromGlobal() {
    return req.body.payload;
}

function interproceduralDirect() {
    const data = getUserInputFromGlobal();
    document.write(data);
}

// ─── Arrow-function helper assigned to a const ───────────────────────
const getInputArrow = () => req.body.arrow;

function interproceduralArrow() {
    document.write(getInputArrow());
}

// ─── Method call on a tainted root (issue #27) ────────────────────────
// `req.body.toString()` — receiver is a source, method-call result
// carries the taint into the innerHTML sink.
function methodCallOnTaintedRoot(req) {
    document.getElementById("x").innerHTML = req.body.toString();
}

// ─── Spread element: [...source] propagates taint (issue #119) ───────
function spreadTaint(req) {
    const arr = [...req.body];
    document.getElementById("x").innerHTML = arr[0];
}

// ─── js/taint-log-injection ──────────────────────────────────────────
function logInjection(req) {
    const userInput = req.body.username;
    console.log(userInput);
}

// ─── js/taint-xxe ───────────────────────────────────────────────────
function xxeInjection(req) {
    const xmlData = req.body.xml;
    const parser = new DOMParser();
    parser.parseFromString(xmlData, "text/xml");
}

// ─── js/taint-nosql-injection ───────────────────────────────────────
function nosqlInjection(req) {
    const filter = req.body.filter;
    db.collection("users").find(filter);
}

// ─── js/taint-ldap-injection ───────────────────────────────────────
function ldapSearchInjection(req) {
    const filter = req.body.filter;
    client.search(filter);
}
