# Taint fixture for FastAPI/Starlette request sources (issue #29).
# Uses attribute sources (`query_params`, `path_params`) that work
# today via subscript propagation. The method-call sources
# (`await request.json()`, etc.) also work when the call result is
# assigned and used directly, because the engine matches the `Call`
# shape regardless of `await` wrapping.

import pickle

from fastapi import FastAPI, Request  # noqa: F401

app = FastAPI()


# ─── py/taint-pickle-deserialization via query_params ──────────────
@app.post("/deserialize")
async def deserialize(request: Request):
    raw = request.query_params["data"]
    return pickle.loads(raw)


# ─── py/taint-command-injection via path_params ────────────────────
@app.get("/exec/{name}")
async def run_path(request: Request):
    import os

    cmd = request.path_params["name"]
    os.system(cmd)


# ─── py/taint-eval via handler-param name `req` ────────────────────
@app.get("/eval")
async def evaluator(req: Request):
    expr = req.query_params["expr"]
    return eval(expr)
