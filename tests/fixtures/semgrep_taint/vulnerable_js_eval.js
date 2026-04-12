// Test fixture for the JS Semgrep taint YAML bridge.
// Each function should produce exactly one finding: req.query/body/params → eval().

// 1. Direct: req.query flows into eval
function directQuery(req, res) {
    eval(req.query);
}

// 2. One-hop: req.body assigned to local, local flows into eval
function oneHopBody(req, res) {
    const data = req.body;
    eval(data);
}

// 3. req.params through an intermediate
function paramsViaLocal(req, res) {
    const id = req.params;
    const payload = id;
    eval(payload);
}
