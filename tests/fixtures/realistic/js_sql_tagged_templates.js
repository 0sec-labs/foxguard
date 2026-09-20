// Parameterizing tags: `${}` becomes a bound parameter, not interpolated text.
// None of these may be reported by js/no-sql-injection.
import { sql } from "drizzle-orm";
import postgres from "postgres";

export async function listByOrg(db, orgId) {
  return db.execute(sql`SELECT * FROM customer_integrations WHERE org_id = ${orgId}`);
}

export function scopeFragment(orgId, repositoryId) {
  return sql`(EXISTS (SELECT 1 FROM scan_credit_admissions a WHERE a.org_id=${orgId} AND a.repository_id=${repositoryId}))`;
}

export async function viaPostgresJs(sql, orgId) {
  return sql`SELECT * FROM findings WHERE org_id = ${orgId}`;
}

// An unrecognised tag is NOT assumed safe: the rule cannot know whether an
// arbitrary identifier binds parameters, so this is still reported.
export async function unknownTag(conn, orgId) {
  return conn`SELECT * FROM findings WHERE org_id = ${orgId}`;
}

export async function viaPrisma(prisma, email) {
  return prisma.$queryRaw`SELECT id FROM users WHERE email = ${email}`;
}

// Escape hatches interpolate for real and MUST still be reported.
export async function unsafeRaw(db, orderBy) {
  return db.execute(sql.raw(`SELECT * FROM findings ORDER BY ${orderBy}`));
}

// Plain interpolation, no tag: still a sink.
export async function untagged(db, userId) {
  return db.query(`SELECT * FROM users WHERE id = ${userId}`);
}

// Concatenation: still a sink.
export async function concatenated(db, userId) {
  return db.query("SELECT * FROM users WHERE id = " + userId);
}
