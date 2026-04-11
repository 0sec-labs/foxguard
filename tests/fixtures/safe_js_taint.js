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
