// Deno CLI script. `Deno.args` matches the Deno `Attribute` source,
// and `Deno.env.get(...)` matches the `Call` source. The intraprocedural
// taint engine only analyzes function bodies, so the sinks below live
// inside explicit functions — top-level Deno scripts should wrap their
// logic the same way to benefit from taint tracking.

function renderArg() {
    const userArg = Deno.args[0];
    const el = document.getElementById("msg");
    if (el) el.innerHTML = userArg; // js/taint-xss-innerhtml
}

function renderHost() {
    const host = Deno.env.get("REMOTE_HOST");
    const el = document.getElementById("host");
    if (el) el.innerHTML = host; // js/taint-xss-innerhtml
}

renderArg();
renderHost();
