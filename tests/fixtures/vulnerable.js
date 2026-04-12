// Vulnerable JavaScript file — triggers the built-in JS rules

const crypto = require("crypto");
const fs = require("fs");
const { exec } = require("child_process");

// 1. js/no-eval (Critical)
const userInput = "alert(1)";
eval(userInput);

// 2. js/no-hardcoded-secret (High)
const apiKey = "sk-live-abcdef123456";

// 3. js/no-sql-injection — string concat (Critical)
const userId = "1";
const query1 = "SELECT * FROM users WHERE id = " + userId;

// 4. js/no-sql-injection — template literal (Critical)
const query2 = `SELECT * FROM users WHERE id = ${userId}`;

// 5. js/no-xss-innerhtml (High)
const el = document.getElementById("app");
el.innerHTML = userInput;

// 6. js/no-command-injection (Critical)
exec(userInput);

// 7. js/no-document-write (High)
document.write("<h1>Hello</h1>");

// 8. js/no-open-redirect (Medium)
window.location.href = userInput;

// 9. js/no-weak-crypto (Medium)
const hash = crypto.createHash("md5");

// 10. js/no-path-traversal (High)
fs.readFileSync(`/data/${userInput}`);

// 11. js/no-ssrf (High)
fetch(userInput);

// 12. js/no-path-traversal (High) through response file send
res.sendFile(userInput);

// 13. js/no-prototype-pollution (High)
const obj = {};
const a = "__proto__";
const b = "polluted";
obj[a][b] = "pwned";

// 14. js/no-unsafe-regex (Medium)
const re = /(a+)+$/;

// 15. js/no-cors-star (Medium)
const cors = { origin: "*" };

// 16. js/express-no-hardcoded-session-secret (High)
const sessionConfig = { secret: "keyboard-cat-secret" };

// 17. js/express-cookie-no-secure (Medium)
const cookieOpts = { cookie: { maxAge: 86400 } };

// 18. js/express-cookie-no-httponly (Medium)
const cookieOpts2 = { cookie: { secure: true } };

// 19. js/express-cookie-no-samesite (Medium)
const cookieOpts3 = { cookie: { secure: true, httpOnly: true } };

// 20. js/express-session-saveuninitialized-true (Medium)
const sessionLifecycle = { saveUninitialized: true };

// 21. js/jwt-hardcoded-secret (High)
const token = jwt.sign({ sub: userId }, "hardcoded-jwt-secret");

// 22. js/jwt-none-algorithm (High)
const insecureToken = jwt.verify(token, publicKey, { algorithms: ["none"] });

// 23. js/jwt-ignore-expiration (High)
const expiredToken = jwt.verify(token, publicKey, { ignoreExpiration: true });

// 24. js/jwt-decode-without-verify (High)
const decodedOnly = jwt.decode(token);

// 25. js/jwt-verify-missing-algorithms (High)
const weakVerify = jwt.verify(token, publicKey);

// 26. js/express-direct-response-write (High)
function handler(req, res) {
  res.send(req.query.name);
}

// 27. js/no-unsafe-deserialization — node-serialize (Critical)
const obj = serialize.unserialize(userInput);

// 28. js/no-unsafe-deserialization — yaml.load without safe schema (Critical)
const data = yaml.load(userInput);
