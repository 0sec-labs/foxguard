// Safe JavaScript file — no vulnerabilities

const crypto = require("crypto");
const fs = require("fs");

// Safe: parameterized query
function getUser(db, id) {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
}

// Safe: textContent instead of innerHTML
function setContent(el, text) {
    el.textContent = text;
}

// Safe: strong hash
function hashData(data) {
    return crypto.createHash("sha256").update(data).digest("hex");
}

// Safe: static file path
function readConfig() {
    return fs.readFileSync("/etc/app/config.json");
}

// Safe: no hardcoded secrets
const config = {
    apiUrl: "https://api.example.com",
    timeout: 5000,
};

// Safe: specific CORS origin
const corsOptions = { origin: "https://example.com" };

// Safe: secure cookie flags
const cookieOptions = { cookie: { secure: true, httpOnly: true, sameSite: "lax" } };
const sessionLifecycle = { saveUninitialized: false };

// Safe: JWT secret from environment
const token = jwt.sign({ sub: "123" }, process.env.JWT_SECRET);
const verified = jwt.verify(token, publicKey, { algorithms: ["HS256"] });
const verifiedExpiry = jwt.verify(token, publicKey, { algorithms: ["HS256"], ignoreExpiration: false });
const verifiedStrict = jwt.verify(token, publicKey, { algorithms: ["RS256"], ignoreExpiration: false });
const parsedHeader = JSON.parse(Buffer.from(token.split(".")[0], "base64").toString("utf8"));

// Safe: static outbound request
fetch("https://api.example.com/health");

// Safe: static response file path
res.sendFile("/srv/app/public/logo.svg");

// Safe: safe regex
const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

// Safe: const-bound URL passed to fetch (no dynamic/user input)
const url = "https://api.example.com";
fetch(url);

// Safe: const-bound redirect destination
const dest = "/home";
res.redirect(dest);

// Safe: static innerHTML assignment
function renderStatic(el) {
    el.innerHTML = "<b>static</b>";
}

// Safe: sanitized HTML via DOMPurify
function renderSanitized(el, raw) {
    el.innerHTML = DOMPurify.sanitize(raw);
}

// Safe: plain object literal, not a session() configuration
const mockData = { secret: "not-a-session-secret-here" };

// Safe: logging a local variable (not user-controlled input)
function logStatus(status) {
    console.log(`status is ${status}`);
}

// Safe: simple non-catastrophic regex with alternation (no nested quantifiers)
const protocolRegex = /^(http|https)$/;

module.exports = { getUser, setContent, hashData, readConfig, cookieOptions, sessionLifecycle, token, verified, verifiedExpiry, verifiedStrict, parsedHeader, renderStatic, renderSanitized, mockData, logStatus };
