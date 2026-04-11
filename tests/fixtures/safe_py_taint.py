# Negative fixture for the taint POC. Every function here calls
# `pickle.loads` on something, but none of the arguments are reachable
# from an untrusted source within the same function — so
# `py/taint-pickle-deserialization` must NOT fire on this file.
#
# The existing `py/no-pickle` rule WILL fire on every call here because
# it's conservative by design. That's correct and expected. This fixture
# proves the new taint rule doesn't over-fire relative to NoPickle.

import pickle
from flask import request


# Static literal argument — never untrusted.
def static_literal():
    return pickle.loads(b"static-bytes-payload")


# Reassignment with a clean literal kills earlier taint.
def reassignment_kills_taint():
    data = request.data
    data = b"overwritten-with-trusted-bytes"
    return pickle.loads(data)


# `request` is a *local variable* here, not a parameter or import, so
# it is not tainted. The taint rule must not assume any name equal to
# `request` is a source.
def local_named_request_is_not_a_source():
    request = b"some-bytes"  # noqa: F811  local shadow
    return pickle.loads(request)


# Taint from a DIFFERENT function should not leak into this one — the
# engine is intraprocedural and per-function.
def producer():
    return request.data


def consumer_of_different_function():
    data = b"trusted"
    return pickle.loads(data)


# Same-file interprocedural v1: the helper returns a constant literal,
# so its return summary is clean and the caller must not fire.
def clean_literal_helper():
    return b"static-helper-payload"


def interprocedural_clean_helper():
    return pickle.loads(clean_literal_helper())


# A call that happens to be named `loads` but isn't the pickle sink.
class NotPickle:
    def loads(self, x):
        return x


def not_pickle_loads():
    fake = NotPickle()
    return fake.loads(request.data)


# Tuple destructuring with two clean literal elements. Neither target
# should be tainted — element-wise unpack kills any prior taint.
def safe_tuple():
    a, b = b"clean1", b"clean2"
    return pickle.loads(a)


# Element-wise unpack where only the OTHER slot is tainted. The sink
# reads the clean slot, so the taint rule must stay silent.
def safe_tuple_other_slot_tainted():
    a, b = b"clean", request.args["x"]
    return pickle.loads(a)
# ─── Clean calls for every new taint rule ──────────────────────────────
# Each handler below calls a sink with a constant argument. The taint
# rule must stay silent; the conservative `py/no-*` counterpart still
# fires because it's sink-shape-only.

import os  # noqa: E402
import subprocess  # noqa: E402
import yaml  # noqa: E402
import requests  # noqa: E402
import sqlite3  # noqa: E402


def clean_eval():
    return eval("2 + 2")


def clean_command_injection():
    os.system("ls /tmp")
    subprocess.run(["ls", "/tmp"])


def clean_ssrf():
    return requests.get("https://example.com/")


def clean_yaml_load():
    return yaml.load("key: value")


def clean_sql_injection():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT 1")


# ─── Method call on a literal root is not tainted (issue #27) ──────────
def clean_literal_method_call():
    data = "literal".upper()
    return pickle.loads(data)


# ─── F-string with no interpolation is a plain string (issue #28) ──────
def clean_fstring_no_interpolation():
    q = f"hello world"  # noqa: F541
    cur = sqlite3.connect(":memory:").cursor()
    cur.execute(q)
