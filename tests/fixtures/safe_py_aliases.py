# Negative fixture for issue #7: aliased imports of the *same* sensitive
# modules used above, but called in ways that should NOT trigger any rule.
# This proves alias resolution doesn't silently widen the match surface.

import pickle as p
import yaml as y
import hashlib as hl
import requests as rq
import urllib.request as ur
import os as osmod
from hashlib import sha256 as strong_hash
from yaml import safe_load as y_safe


# ─── py/no-pickle: serializing (dump/dumps) is not the sink ───────────────
def dump_via_alias(obj):
    return p.dumps(obj)

def dump_via_alias_write(obj, fh):
    return p.dump(obj, fh)


# ─── py/no-yaml-load: SafeLoader explicitly passed ────────────────────────
def yaml_load_safe(data):
    return y.load(data, Loader=y.SafeLoader)

def yaml_load_base(data):
    return y.load(data, Loader=y.BaseLoader)

def yaml_safe_load_from_import(data):
    return y_safe(data)


# ─── py/no-weak-crypto: sha256 through alias is fine ──────────────────────
def strong_hash_alias(data):
    return hl.sha256(data)

def strong_hash_from_import(data):
    return strong_hash(data)


# ─── py/no-ssrf: static URL literal is not flagged ────────────────────────
def health_check_literal():
    return rq.get("https://example.com/health")

def urllib_static():
    return ur.urlopen("https://example.com/robots.txt")


# ─── py/no-command-injection: static string arg is fine ──────────────────
def list_hostname():
    return osmod.system("hostname")


# ─── py/no-path-traversal: static path literal is fine ────────────────────
def read_hostname():
    with open("/etc/hostname") as f:
        return f.read()
