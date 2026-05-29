# Benign names containing secret-keyword substrings, or low-signal
# keywords with env-sourced values. None should be flagged by
# rb/no-hardcoded-secret after the word-boundary + value-gate fix.

# Substring false positives.
author = "Pallets"
authors = "core team"
authenticated = "yes"
authorization_scheme = "Bearer"
tokenizer = "bert-base-uncased"
secretarial_note = "filed"

# Low-signal + secret-named values, all env-sourced (not literals).
auth = ENV["AUTH"]
token = ENV["TOKEN"]
password = ENV["PW"]
api_key = ENV["API_KEY"]
secret_key = ENV.fetch("SECRET_KEY", nil)
