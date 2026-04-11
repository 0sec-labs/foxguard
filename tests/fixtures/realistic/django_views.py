# Realistic Django views fixture (issue #35). Uses idiomatic
# `request.POST`, `request.GET`, `request.COOKIES`, and `request.META`
# access through small helper functions so interprocedural propagation
# is exercised end-to-end.
#
# Hand-counted expected taint findings:
#   py/taint-command-injection : 2
#   py/taint-sql-injection     : 1
#   py/taint-ssrf              : 1
#   py/taint-pickle-deserialization : 1

import os
import pickle
import sqlite3

import requests
from django.http import HttpResponse


# ─── Helpers ───────────────────────────────────────────────────────────
def extract_post(request, key):
    return request.POST[key]


def read_cookie(request):
    return request.COOKIES["session_blob"]


# ─── Views ─────────────────────────────────────────────────────────────
def delete_file(request):
    # py/taint-command-injection
    name = request.GET["name"]
    os.system(name)
    return HttpResponse("ok")


def run_admin_action(request):
    # py/taint-command-injection — through helper
    cmd = extract_post(request, "cmd")
    os.system(cmd)
    return HttpResponse("ok")


def search_users(request):
    # py/taint-sql-injection
    q = request.GET["q"]
    conn = sqlite3.connect(":memory:")
    conn.cursor().execute(q)
    return HttpResponse("ok")


def proxy_fetch(request):
    # py/taint-ssrf — untrusted target pulled from request META
    url = request.META["HTTP_X_PROXY_TARGET"]
    return HttpResponse(requests.get(url).content)


def import_session(request):
    # py/taint-pickle-deserialization — helper returns tainted cookie
    blob = read_cookie(request)
    return pickle.loads(blob)


# ─── NEAR MISS — must not fire ─────────────────────────────────────────
def healthcheck(request):
    # NEAR MISS — literal sink argument
    os.system("uptime")
    return HttpResponse("ok")


def static_query(request):
    # NEAR MISS — tainted value reassigned to literal before sink
    q = request.GET["q"]  # noqa: F841
    q = "SELECT 1"
    conn = sqlite3.connect(":memory:")
    conn.cursor().execute(q)
    return HttpResponse("ok")


def trusted_fetch(request):
    # NEAR MISS — literal URL
    return HttpResponse(requests.get("https://example.com/status").content)
