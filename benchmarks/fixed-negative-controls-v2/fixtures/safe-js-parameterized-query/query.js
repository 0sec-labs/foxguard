export async function accountByEmail(database, email) {
  return database.query("SELECT id FROM accounts WHERE email = $1", [email]);
}
