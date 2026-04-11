// Query/eval helpers for the express_api fixture.
//
// These helpers each take a parameter that is tainted when called
// from routes.js. Once the cross-file taint engine from issue #46
// lands, callers in routes.js should produce taint findings that
// propagate through these functions.

const db = {
    exec(_q) {
        return [];
    },
};

function runQuery(name) {
    // Would become a taint SQL injection finding after #46 when
    // called from routes.search with a tainted name.
    return db.exec("SELECT * FROM users WHERE name = '" + name + "'");
}

function evalExpression(expr) {
    // Would become a taint eval finding after #46 when called from
    // routes.import with a tainted expression.
    // eslint-disable-next-line no-eval
    return eval(expr);
}

module.exports = { runQuery, evalExpression };
