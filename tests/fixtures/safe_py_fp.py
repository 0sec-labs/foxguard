# False-positive regression fixture.
#
# Every construct here is benign and must produce ZERO foxguard findings.
# It pins the false-positive reductions for the conservative Python rules:
#   - py/no-open-redirect  (url_for / reverse safe URL builders, const target)
#   - py/no-path-traversal (os.path.join / .joinpath sanitized paths)
#   - py/no-yaml-load      (Loader= keyword parsed via AST)
#   - py/no-ssrf, py/no-command-injection (constant-folded identifiers)
#   - py/no-debug-true, py/flask-debug-mode (under __main__ guard)

import os
import subprocess
from pathlib import Path

import requests
import yaml
from django.urls import reverse
from flask import Flask, redirect, url_for

app = Flask(__name__)

# Module-level constants — folded, never user-controlled.
BASE_URL = "https://api.example.com"
CONFIG_PATH = "/etc/app/config.yml"
CMD = "ls -la /tmp"


# py/no-open-redirect: redirect target built by a safe framework helper.
def login_redirect():
    return redirect(url_for("auth.login"))


def view_redirect():
    return redirect(reverse("dashboard"))


def const_redirect():
    return redirect("/static-home")


# py/no-path-traversal: os.path.join / pathlib result is treated as sanitized.
def read_join(base, name):
    path = os.path.join(base, name)
    with open(path) as f:
        return f.read()


def read_joinpath(base, name):
    p = Path(base).joinpath(name)
    return open(p).read()


def remove_const():
    os.remove("/tmp/fixed-name.txt")


# py/no-yaml-load: explicit safe Loader passed as keyword argument.
def load_yaml_safe(data):
    return yaml.load(data, Loader=yaml.SafeLoader)


def load_yaml_base(data):
    return yaml.load(data, Loader=yaml.BaseLoader)


# py/no-ssrf: request URL is a folded module constant.
def fetch_health():
    return requests.get(BASE_URL)


# py/no-command-injection: command is a folded module constant.
def run_const_cmd():
    return subprocess.run(CMD)


# py/no-debug-true and py/flask-debug-mode: only reachable under __main__,
# i.e. local development entrypoint — not a production configuration.
if __name__ == "__main__":
    DEBUG = True
    app.debug = True
    app.run(debug=True)
