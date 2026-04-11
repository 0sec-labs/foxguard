// Query/eval helpers for the next_app fixture.
//
// These helpers each take a parameter that is tainted when called
// from route.ts. Cross-file taint flow does not fire under the
// current engine; issue #46 will fix that.

const db = {
    exec(_q: string): unknown[] {
        return [];
    },
};

export function runQuery(name: string): unknown[] {
    // Would become a taint SQL injection finding after #46.
    return db.exec("SELECT * FROM users WHERE name = '" + name + "'");
}

export function evalExpression(expr: string): unknown {
    // Would become a taint eval finding after #46.
    // eslint-disable-next-line no-eval
    return eval(expr);
}
