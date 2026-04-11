// Multi-file Next.js App Router fixture (issue #48).
//
// route.ts holds request sources (Next.js App Router Request/searchParams);
// actions.ts holds the dangerous sinks. Same deal as django_shop/ and
// express_api/: cross-file flows do not fire under the current engine
// and will fire after issue #46 (cross-file summaries) lands.
//
// Hand-counted expected findings under the current engine:
//   js/taint-xss-innerhtml : 1  (in-file render handler)

import { NextRequest, NextResponse } from "next/server";
import { runQuery, evalExpression } from "./actions";

// ─── In-file flow — should fire today ────────────────────────────────
export async function GET(request: NextRequest) {
    // js/taint-xss-innerhtml — source and sink in the same function
    const { searchParams } = new URL(request.url);
    const html = searchParams.get("html") ?? "";
    return new NextResponse(`<div>${html}</div>`, {
        headers: { "content-type": "text/html" },
    });
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
