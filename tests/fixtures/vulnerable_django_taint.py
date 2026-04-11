# Taint fixture for Django request sources (issue #29). Every handler
# below takes a Django `HttpRequest` and flows an untrusted attribute
# into a taint sink via subscript access. The engine's v1 scope taints
# subscript access on a tainted attribute, so `request.POST["data"]`
# works; `request.POST.get("data")` is method-call-on-tainted-receiver
# and is covered once issue #27 lands.

import os
import pickle
import subprocess  # noqa: F401
import yaml

from django.http import HttpRequest  # noqa: F401


# ─── py/taint-pickle-deserialization via request.POST ──────────────
def view_post(request):
    return pickle.loads(request.POST["data"])


# ─── py/taint-command-injection via request.GET ────────────────────
def view_get(request):
    cmd = request.GET["cmd"]
    os.system(cmd)


# ─── py/taint-eval via request.COOKIES ─────────────────────────────
def view_cookies(request):
    expr = request.COOKIES["expr"]
    return eval(expr)


# ─── py/taint-yaml-load via request.body ───────────────────────────
def view_body(request):
    return yaml.load(request.body)


# ─── py/taint-ssrf via request.META ────────────────────────────────
def view_meta(request):
    import requests

    url = request.META["HTTP_X_TARGET"]
    return requests.get(url)
