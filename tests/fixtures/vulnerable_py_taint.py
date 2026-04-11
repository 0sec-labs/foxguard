# Taint-tracking POC fixture: every handler here shows untrusted input
# reaching `pickle.loads` via a different intraprocedural path. Each
# function should produce exactly one `py/taint-pickle-deserialization`
# finding. The file also produces `py/no-pickle` findings from the
# existing conservative rule — that's expected: the two rules coexist
# and the taint rule is the precision upgrade, not a replacement.

import pickle
import pickle as p_alias
from flask import request


# ─── Direct: source flows into sink as the raw argument ────────────────
def direct():
    return pickle.loads(request.data)


# ─── One-hop: source assigned to a local, local flows into sink ────────
def one_hop():
    data = request.form
    return pickle.loads(data)


# ─── Chained: taint survives a chain of assignments ────────────────────
def chained():
    a = request.args
    b = a
    c = b
    return pickle.loads(c)


# ─── Source call: `request.get_json()` is a Call source ────────────────
def get_json_source():
    payload = request.get_json()
    return pickle.loads(payload)


# ─── get_data method call source ───────────────────────────────────────
def get_data_source():
    raw = request.get_data()
    return pickle.loads(raw)


# ─── Parameter source: handler(request) marks `request` as tainted ─────
def param_source(request):
    return pickle.loads(request.data)


# ─── Branch: taint observed in one branch persists (over-approximation)
def through_branch(cond):
    data = b"default"
    if cond:
        data = request.data
    return pickle.loads(data)


# ─── Subscript: `form["key"]` is tainted because `form` is ─────────────
def through_subscript():
    form = request.form
    return pickle.loads(form["payload"])


# ─── Wrapping call: `bytes(x)` preserves taint ─────────────────────────
def through_wrapping():
    return pickle.loads(bytes(request.data))


# ─── Alias: `import pickle as p_alias; p_alias.loads(...)` still sinks
def through_sink_alias():
    data = request.data
    return p_alias.loads(data)


# ─── Nested subscript chain: taint must propagate through every level ──
def nested_subscript_chain():
    return pickle.loads(request.json["data"]["payload"])


# ─── Tuple unpack with element-wise taint from a tuple RHS ─────────────
def tuple_unpack_elementwise():
    a, b = request.args["a"], request.args["b"]
    return pickle.loads(a)


# ─── Tuple unpack with opaque RHS: conservative taint of both targets ──
def tuple_unpack_conservative():
    a, b = request.get_json()
    return pickle.loads(b)


# ─── List unpack: same semantics as tuple unpack ───────────────────────
def list_unpack_elementwise():
    [x, y] = [b"static", request.form["payload"]]
    return pickle.loads(y)


# ─── Same-file helper return propagation (issue #19, v1) ───────────────
# The helper reads an untrusted source and returns it; the caller
# assigns the result to a local and passes it to pickle.loads. Pass 1
# summarizes `get_user_input` as tainted; pass 2 taints `data` in the
# caller via the summary.
def get_user_input():
    return request.data


def interprocedural_direct_return():
    data = get_user_input()
    return pickle.loads(data)


# Caller defined *above* its helper — the two-pass design visits every
# function before analyzing any of them, so definition order does not
# matter within the file.
def interprocedural_late_definition():
    data = late_helper()
    return pickle.loads(data)


def late_helper():
    return request.form["payload"]
# ═══ py/taint-eval ══════════════════════════════════════════════════════
import os  # noqa: E402
import subprocess  # noqa: E402
import yaml  # noqa: E402
import requests  # noqa: E402
import sqlite3  # noqa: E402


def eval_from_request():
    expr = request.args["expr"]
    return eval(expr)


# ═══ py/taint-command-injection ════════════════════════════════════════
def command_injection_from_request():
    cmd = request.form["cmd"]
    os.system(cmd)


# ═══ py/taint-ssrf ══════════════════════════════════════════════════════
def ssrf_from_request():
    url = request.args["url"]
    return requests.get(url)


# ═══ py/taint-yaml-load ════════════════════════════════════════════════
def yaml_load_from_request():
    payload = request.data
    return yaml.load(payload)


# ═══ py/taint-sql-injection ════════════════════════════════════════════
def sql_injection_from_request():
    # Tainted `name` flows directly into `.execute(...)` — that's what
    # the taint rule catches. The explicit f-string query on the next
    # line exists purely so the conservative `py/no-sql-injection` rule
    # also fires on this handler: both rules coexist by design.
    name = request.args["name"]
    _conservative_decoy = f"SELECT * FROM users WHERE name = '{name}'"  # noqa: S608,F841
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(name)


# ═══ Method-call propagation (issue #27) ═══════════════════════════════
# `request.args.get("cmd")` is a method call on a tainted root
# (`request.args`). The method-call rule taints the result conservatively
# and the taint rule must fire on the downstream sink.
def command_injection_from_args_get():
    cmd = request.args.get("cmd")
    os.system(cmd)


def eval_from_args_get():
    expr = request.args.get("expr")
    return eval(expr)


# ═══ F-string interpolation propagation (issue #28) ════════════════════
# An f-string containing an interpolation whose inner expression is a
# tainted method call propagates taint through the string into the sink.
def sql_injection_from_fstring():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {request.args.get('id')}")
