// Query/eval helpers for the express_api fixture.
//
// These helpers each take a parameter that is tainted when called
// from routes.js. The cross-file taint engine (issue #46) extracts
// summaries showing that `name` in `runQuery` reaches a SQL sink and
// `expr` in `evalExpression` reaches an eval sink.

const db = {
    query(_q) {
        return [];
    },
};

function runQuery(name) {
    // Cross-file: js/taint-sql-injection fires when this is called
    // with a tainted argument from routes.js /search handler.
    return db.query("SELECT * FROM users WHERE name = '" + name + "'");
}

function evalExpression(expr) {
    // Cross-file: js/taint-eval fires when this is called
    // with a tainted argument from routes.js /import handler.
    // eslint-disable-next-line no-eval
    return eval(expr);
}

module.exports = { runQuery, evalExpression };
