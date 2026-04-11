// Realistic Next.js App Router fixture (issue #35). Uses
// `NextRequest.nextUrl.searchParams` and related attribute chains
// through helpers and into XSS sinks.
//
// Hand-counted expected taint findings:
//   js/taint-xss-innerhtml : 3

import { NextRequest, NextResponse } from "next/server";

// ─── Helpers ───────────────────────────────────────────────────────────
function readName(request: NextRequest) {
    return request.nextUrl.searchParams;
}

// ─── Route handlers ────────────────────────────────────────────────────
export async function GET(request: NextRequest) {
    // js/taint-xss-innerhtml — helper returns tainted searchParams
    const params = readName(request);
    const el = document.getElementById("greeting");
    if (el) el.innerHTML = params;
    return NextResponse.json({ ok: true });
}

export async function POST(request: NextRequest) {
    // js/taint-xss-innerhtml — direct nextUrl attribute into document.write
    const target = request.nextUrl;
    document.write(`<h2>Redirecting to ${target}</h2>`);
    return NextResponse.json({ ok: true });
}

export async function PUT(request: NextRequest) {
    // js/taint-xss-innerhtml — searchParams alias chain
    const q = request.nextUrl.searchParams;
    const term = q;
    const el = document.getElementById("out");
    if (el) el.innerHTML = term;
    return NextResponse.json({ ok: true });
}

// ─── NEAR MISS — must not fire ─────────────────────────────────────────
export async function DELETE(request: NextRequest) {
    // NEAR MISS — literal argument; tainted value read but never used
    const _seen = request.nextUrl.searchParams;
    const el = document.getElementById("gone");
    if (el) el.innerHTML = "deleted";
    return NextResponse.json({ ok: true });
}

export async function PATCH() {
    // NEAR MISS — no source involvement at all
    document.write("<h1>Patched</h1>");
    return NextResponse.json({ ok: true });
}
