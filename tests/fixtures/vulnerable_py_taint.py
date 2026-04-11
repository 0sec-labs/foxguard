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
