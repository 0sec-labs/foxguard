# Realistic FastAPI app fixture (issue #35). Covers Request parameter
# sources and Pydantic model use, with a couple of helpers for
# interprocedural propagation and NEAR MISS cases.
#
# Hand-counted expected taint findings:
#   py/taint-eval                    : 1
#   py/taint-pickle-deserialization  : 1
#   py/taint-ssrf                    : 1

import pickle

import requests
from fastapi import FastAPI, Request
from pydantic import BaseModel

app = FastAPI()


class Job(BaseModel):
    expr: str
    target: str


# ─── Helpers ───────────────────────────────────────────────────────────
def pick_query(req: Request, key: str):
    return req.query_params[key]


# ─── Endpoints ─────────────────────────────────────────────────────────
@app.get("/eval")
async def eval_endpoint(request: Request):
    # py/taint-eval — helper returns tainted query param
    expr = pick_query(request, "expr")
    return {"result": eval(expr)}


@app.post("/restore")
async def restore(request: Request):
    # py/taint-pickle-deserialization
    blob = request.query_params["blob"]
    return pickle.loads(blob)


@app.get("/fetch")
async def fetch(request: Request):
    # py/taint-ssrf
    target = request.query_params["target"]
    return {"content": requests.get(target).text}


# ─── NEAR MISS — must not fire ─────────────────────────────────────────
@app.post("/run")
async def run_job(job: Job):
    # NEAR MISS — Pydantic-validated model field; the engine does not
    # treat non-Request parameters as sources, so this must not fire.
    return {"result": eval(job.expr)}


@app.get("/static")
async def static_eval_endpoint():
    # NEAR MISS — literal argument
    return {"result": eval("2 + 2")}


@app.get("/ok")
async def ok(request: Request):
    # NEAR MISS — read a query param, then discard it and return a literal
    _seen = request.query_params["seen"]  # noqa: F841
    return {"status": "ok"}
