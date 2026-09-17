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

// Noncredential metadata: evidence comes from the value and its consumer,
// not just the presence of MODEL/NAME/REDACTED in an identifier.
const TOKEN_PLAN_ROUTING_MODEL = "vendor-v4-flash-0731";
function providerForModel(model) {
  const normalized = model.toLowerCase();
  return normalized === TOKEN_PLAN_ROUTING_MODEL;
}
const CREDENTIAL_NAME = "password|secret|api[_-]?key";
const credentialPattern = new RegExp(`(?:^|[^A-Za-z])(?:${CREDENTIAL_NAME})$`, "i");
const REDACTED_SECRET = "<REDACTED-SECRET>";
function redactValue(value) {
  return value.replace(credentialPattern, REDACTED_SECRET);
}
