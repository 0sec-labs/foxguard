# Benign names that contain secret-keyword *substrings* or low-signal
# secret keywords with non-secret values. None of these should be flagged
# by `py/no-hardcoded-secret` after the word-boundary + value-gate fix.
import os

# Substring false positives: these identifiers merely *contain* a keyword.
author = "Pallets"
authors = "Armin Ronacher"
authored_by = "core team"
authenticated = True
authentication_scheme = "Bearer"
authorization_header = "X-Custom"
tokenizer = "bert-base-uncased"
tokenize_input = "whitespace"
secretarial_note = "filed"

# Low-signal keywords (auth / token) whose values are clearly not secrets
# (URL / path / value-with-spaces -> rejected by looks_like_secret_value).
auth = "/login"
auth_url = "https://example.com/oauth"
token = "see docs for the token format"

# Env-sourced "secret" names — the value is not a hardcoded literal.
password = os.environ.get("PW", "")
api_key = os.getenv("API_KEY")
secret_key = os.environ["SECRET_KEY"]
credentials = os.environ.get("CREDS")
