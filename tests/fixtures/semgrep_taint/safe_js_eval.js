// Safe fixture: no taint should flow from req.query/body/params into eval().

function safeHandler(req, res) {
    const safe = "hello world";
    eval(safe);
}

function noEval(req, res) {
    console.log(req.query);
}
