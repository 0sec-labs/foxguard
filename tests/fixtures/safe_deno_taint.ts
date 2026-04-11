// Safe Deno counterpart — no tainted flows should reach any sink.

function literalOnly() {
    // Literal, no taint.
    const el = document.getElementById("msg");
    if (el) el.innerHTML = "<h1>Hello</h1>";
}

function reassigned() {
    // Reassignment kills taint before the sink.
    let arg = Deno.args[0];
    arg = "static";
    const el = document.getElementById("arg");
    if (el) el.innerHTML = arg;
}

// Cross-function: intraprocedural engine does not thread taint across
// this call boundary.
function render(value) {
    const el = document.getElementById("x");
    if (el) el.innerHTML = value;
}

function caller() {
    render("static literal");
}

literalOnly();
reassigned();
caller();
