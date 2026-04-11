# Realistic Flask app fixture (issue #35). Exercises the intraprocedural
# Python taint engine on an idiomatic multi-route application that mixes
# helpers, multiple sinks, and NEAR-MISS functions that must not fire.
#
# Hand-counted expected taint findings (see tests/realistic_fixtures.rs):
#   py/taint-pickle-deserialization : 1
#   py/taint-eval                   : 1
#   py/taint-command-injection      : 2
#   py/taint-ssrf                   : 1
#   py/taint-yaml-load              : 1
#   py/taint-sql-injection          : 1

import os
import pickle
import sqlite3
import subprocess  # noqa: F401
import yaml

import requests
from flask import Flask, request

app = Flask(__name__)


# ─── Helpers (exercise interprocedural propagation) ────────────────────
def fetch_body():
    """Return the raw request body — a helper that returns tainted data."""
    return request.data


def fetch_arg(name):
    """Typical 'just read a query parameter' helper."""
    return request.args[name]


# ─── Routes ─────────────────────────────────────────────────────────────
@app.route("/import", methods=["POST"])
def import_profile():
    # py/taint-pickle-deserialization — helper returns tainted body
    payload = fetch_body()
    return pickle.loads(payload)


@app.route("/calc")
def calc():
    # py/taint-eval
    expr = request.args["expr"]
    return str(eval(expr))


@app.route("/ping")
def ping():
    # py/taint-command-injection — string concat with tainted operand
    # (exercises the binary `+` propagation path)
    host = request.args.get("host", "localhost")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/run")
def run_cmd():
    # py/taint-command-injection — tainted via helper return
    cmd = fetch_arg("cmd")
    os.system(cmd)
    return "ok"


@app.route("/fetch")
def fetch_url():
    # py/taint-ssrf
    url = request.args["url"]
    return requests.get(url).text


@app.route("/config", methods=["POST"])
def load_config():
    # py/taint-yaml-load
    doc = request.data
    return yaml.load(doc)


@app.route("/user")
def lookup_user():
    # py/taint-sql-injection — tainted name flows into .execute
    name = request.args["name"]
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(name)
    return "ok"


# ─── NEAR MISS — must not fire any py/taint-* rule ─────────────────────
@app.route("/healthz")
def healthz():
    # NEAR MISS — literal argument, no source involvement
    os.system("uptime")
    return "ok"


@app.route("/static-eval")
def static_eval():
    # NEAR MISS — tainted value is discarded; sink receives a literal
    _ignored = request.args["expr"]  # noqa: F841
    return str(eval("1 + 1"))


def unused_tainted_helper():
    # NEAR MISS — helper reads source but caller never passes it to a sink
    data = request.data
    return len(data)
