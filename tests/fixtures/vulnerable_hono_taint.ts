// Hono handler. `c` is intentionally not a `ParamName` source (it
// collides with generic one-letter locals), so taint is picked up
// through explicit `Call` matchers on `c.req.*` method sources and
// the `Attribute` matcher on `c.req`.
import { Hono } from "hono";

const app = new Hono();

app.get("/", (c) => {
    const name = c.req.query("name");
    document.write(`<h1>${name}</h1>`); // js/taint-xss-innerhtml
    return c.text("ok");
});

app.get("/param", (c) => {
    const id = c.req.param("id");
    const el = document.getElementById("out");
    if (el) el.innerHTML = id; // js/taint-xss-innerhtml
    return c.text("ok");
});
