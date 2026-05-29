// Benign names containing secret-keyword substrings, or low-signal
// keywords with env-sourced values. None should be flagged by
// js/no-hardcoded-secret after the word-boundary + value-gate fix.

// Substring false positives.
const author = "Pallets";
const authors = "core team";
const authenticated = "yes";
const authorizationScheme = "Bearer";
const tokenizer = "bert-base-uncased";
const secretarialNote = "filed";

// Low-signal keyword values that are clearly not secrets.
const auth = "/login";
const authUrl = "https://example.com/oauth";
const token = "see docs for the token format";

// Env-sourced secret-named values (not hardcoded literals).
const password = process.env.PW;
const apiKey = process.env.API_KEY;
const secretKey = process.env.SECRET_KEY;

module.exports = {
  author,
  authors,
  authenticated,
  authorizationScheme,
  tokenizer,
  secretarialNote,
  auth,
  authUrl,
  token,
  password,
  apiKey,
  secretKey,
};
