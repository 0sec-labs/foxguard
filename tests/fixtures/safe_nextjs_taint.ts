// Safe Next.js counterpart — no tainted flows should reach any sink.
import { NextRequest } from "next/server";

export async function GET(_request: NextRequest) {
    // Literal, no taint.
    const el = document.getElementById("greeting");
    if (el) el.innerHTML = "<h1>Hello</h1>";
}

export async function POST(request: NextRequest) {
    // Reassignment kills taint: `target` is tainted on the first line,
    // then replaced with a static literal before reaching the sink.
    let target = request.nextUrl;
    target = "/static";
    document.write(`<h1>${target}</h1>`);
}

// Cross-function isolation: `helper` has no tainted input in its own
// scope (intraprocedural engine), so the sink call here must not fire.
function helper(name) {
    const el = document.getElementById("out");
    if (el) el.innerHTML = name;
}

export async function PUT(_request: NextRequest) {
    helper("static literal");
}
