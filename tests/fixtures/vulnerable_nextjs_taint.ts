// Next.js App Router handler. `request` is seeded as a source by the
// `ParamName` matcher, and its `nextUrl` / `cookies` attribute chains
// propagate taint through to DOM sinks. Method-call sources like
// `request.headers.get(...)` depend on issue #27 and are intentionally
// not exercised here.
import { NextRequest } from "next/server";

export async function GET(request: NextRequest) {
    // Pure attribute chain — propagates taint via member-expression
    // propagation because `request` is ParamName-seeded.
    const params = request.nextUrl.searchParams;
    const el = document.getElementById("greeting");
    if (el) el.innerHTML = params; // js/taint-xss-innerhtml
}

export async function POST(request: NextRequest) {
    // `request.nextUrl` matches the Next.js Attribute matcher directly.
    const target = request.nextUrl;
    document.write(`<h1>${target}</h1>`); // js/taint-xss-innerhtml
}
