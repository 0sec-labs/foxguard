# Negative FastAPI fixture (issue #29). All sinks get non-tainted
# arguments; `py/taint-*` must stay silent.

import os
import pickle

from fastapi import FastAPI, Request  # noqa: F401

app = FastAPI()


@app.post("/clean-pickle")
async def clean_pickle():
    return pickle.loads(b"static-bytes")


@app.get("/kills-taint")
async def kills_taint(request: Request):
    value = request.query_params["x"]
    value = "trusted-literal"
    os.system(value)


@app.get("/static")
async def static_cmd():
    os.system("ls /tmp")
