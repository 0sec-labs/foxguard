# Safe patterns that py/hardcoded-crypto-algorithm should NOT fire on.
import hashlib

# Safe: algorithm comes from config, not a literal
algo = config.get("hash_algorithm")
hashlib.new(algo, data)

# Safe: f-string (dynamic) — not a plain string literal
hashlib.new(f"{os.environ['HASH_ALGO']}", data)

# Safe: weak algorithms are owned by py/no-weak-crypto, not this rule
hashlib.new("md5", data)
hashlib.new("sha1", data)
