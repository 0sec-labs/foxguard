// Multi-file Next.js App Router fixture (issue #48).
//
// route.ts holds request sources (Next.js App Router Request/searchParams);
// actions.ts holds the dangerous sinks. Same deal as django_shop/ and
// express_api/: cross-file flows do not fire under the current engine
// and will fire after issue #46 (cross-file summaries) lands.
//
// Hand-counted expected findings under the current engine:
//   js/taint-sql-injection : 1  (in-file GET handler)

import { NextRequest, NextResponse } from "next/server";
import { runQuery, evalExpression } from "./actions";

const db = { query(_q: string): unknown[] { return []; } };

// ─── In-file flow — should fire today ────────────────────────────────
export async function GET(request: NextRequest) {
    // js/taint-sql-injection — source and sink in the same function.
    // Uses the canonical Next.js App Router source: request.nextUrl.
    const name = request.nextUrl.searchParams.get("name") ?? "";
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
    return NextResponse.json({ ok: true });
}

// ─── Cross-file flow — should fire after #46 ─────────────────────────
export async function POST(request: NextRequest) {
    const body = await request.json();
    // Cross-file: source in route.ts, sink in actions.ts.
    const rows = runQuery(body.name);
    const result = evalExpression(body.expr);
    return NextResponse.json({ rows, result });
}

// ─── NEAR-MISS — must not fire ───────────────────────────────────────
export async function HEAD(_request: NextRequest) {
    // no source, no sink
    return new NextResponse(null, { status: 200 });
}
