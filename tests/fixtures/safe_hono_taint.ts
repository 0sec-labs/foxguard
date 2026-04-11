// Safe Hono counterpart — no tainted flows should reach any sink.
import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => {
    // Literal, no taint.
    document.write("<h1>Hello</h1>");
    return c.text("ok");
});

app.get("/reassign", (c) => {
    // Reassignment kills taint before the sink.
    let name = c.req.query("name");
    name = "static";
    const el = document.getElementById("out");
    if (el) el.innerHTML = name;
    return c.text("ok");
});

// Cross-function: intraprocedural engine does not thread taint across
// this call boundary.
function render(value) {
    const el = document.getElementById("x");
    if (el) el.innerHTML = value;
}

app.get("/iso", (c) => {
    render("static literal");
    return c.text("ok");
});
