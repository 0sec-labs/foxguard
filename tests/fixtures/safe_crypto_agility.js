// Safe patterns that js/hardcoded-crypto-algorithm should NOT fire on.
const crypto = require("crypto");

// Safe: algorithm comes from config, not a literal
const algo = config.get("hash_algorithm");
crypto.createHash(algo).update(data).digest("hex");

// Safe: template literal with interpolation
crypto.createHash(`${process.env.HASH_ALGO}`).update(data).digest("hex");

// Safe: weak algorithms are owned by js/no-weak-crypto, not this rule
crypto.createHash("md5").update(data).digest("hex");
crypto.createHash("sha1").update(data).digest("hex");
