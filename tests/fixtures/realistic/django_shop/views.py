# Multi-file Django shop fixture (issue #48).
#
# This exercises the taint engine on a realistic two-file Django app
# where request sources live in views.py and sinks live in queries.py.
#
# The current engine is intraprocedural + same-file interprocedural only,
# so cross-file taint flow from views → queries does NOT fire yet.
# Once issue #46 (cross-file summaries) lands, the expected counts in
# tests/realistic_fixtures.rs for this fixture should be updated.
#
# Today, this file asserts:
#   - in-file flows fire correctly (same-file sinks)
#   - cross-file flows DO NOT fire (documents current limit)
#   - NEAR-MISS handlers do not fire
#
# Hand-counted expected taint findings under the current engine:
#   py/taint-command-injection : 1   (in-file, /ping)
#   py/taint-ssrf              : 1   (in-file, /fetch)
#   py/taint-sql-injection     : 0   (cross-file via queries.run_query — will fire after #46)
#   py/taint-pickle-deserialization : 0 (cross-file via queries.load_blob — will fire after #46)

import os
import pickle

import requests
from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_http_methods

from . import queries


# ─── In-file flows — should fire today ────────────────────────────────
def ping(request):
    # py/taint-command-injection — source and sink in the same function
    host = request.GET.get("host", "localhost")
    os.system("ping -c 1 " + host)
    return HttpResponse("ok")


def fetch_url(request):
    # py/taint-ssrf — same function
    url = request.GET["url"]
    return HttpResponse(requests.get(url).text)


# ─── Cross-file flows — should fire after #46 lands ───────────────────
def search(request):
    # Cross-file: source in views.py, sink in queries.py.
    # Current engine does not follow taint across files, so this
    # fixture pins the expectation to 0 today.
    name = request.GET["name"]
    rows = queries.run_query(name)
    return JsonResponse({"rows": rows})


@require_http_methods(["POST"])
def import_profile(request):
    # Cross-file: tainted body flows into queries.load_blob which
    # calls pickle.loads. Will fire after #46.
    payload = request.body
    return HttpResponse(queries.load_blob(payload))


# ─── NEAR-MISS — must not fire ────────────────────────────────────────
def healthz(request):
    # literal, no source
    os.system("uptime")
    return HttpResponse("ok")


def static_fetch(request):
    # tainted value read and discarded; sink receives a literal
    _ignored = request.GET["url"]  # noqa: F841
    return HttpResponse(requests.get("https://example.com").text)
