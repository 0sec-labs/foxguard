# Regression fixture for issue #7: Python import alias resolution.
#
# Every call site below used to slip past the Python rules because the rules
# string-matched the callee text against a fixed sink list. With the
# per-file ImportAliases table, each call should now be resolved back to its
# canonical dotted path and flagged.
#
# One finding per call site. Rules covered:
#   py/no-eval, py/no-command-injection, py/no-path-traversal,
#   py/no-ssrf, py/no-weak-crypto, py/no-pickle, py/no-yaml-load.

import pickle as p
import cPickle as pick2
import yaml as y
import hashlib as hl
import requests as rq
import urllib.request as ur
import os as osmod
import subprocess as sp
from pickle import loads as p_loads
from pickle import load
from yaml import load as y_load
from hashlib import md5, sha1
from subprocess import Popen as SpawnProc
from os import system as run_shell


# ─── py/no-pickle ──────────────────────────────────────────────────────────
def bypass_pickle_aliased(data):
    return p.loads(data)                 # import pickle as p

def bypass_pickle_shadowed(data):
    return pick2.loads(data)             # import cPickle as pick2

def bypass_pickle_from_import_alias(data):
    return p_loads(data)                 # from pickle import loads as p_loads

def bypass_pickle_from_import_bare(data):
    return load(data)                    # from pickle import load


# ─── py/no-yaml-load ───────────────────────────────────────────────────────
def bypass_yaml_aliased(data):
    return y.load(data)                  # import yaml as y

def bypass_yaml_from_import_alias(data):
    return y_load(data)                  # from yaml import load as y_load


# ─── py/no-weak-crypto ─────────────────────────────────────────────────────
def bypass_md5_aliased(data):
    return hl.md5(data)                  # import hashlib as hl

def bypass_sha1_aliased(data):
    return hl.sha1(data)                 # import hashlib as hl

def bypass_md5_from_import(data):
    return md5(data)                     # from hashlib import md5

def bypass_sha1_from_import(data):
    return sha1(data)                    # from hashlib import sha1


# ─── py/no-ssrf ────────────────────────────────────────────────────────────
def bypass_ssrf_aliased(user_url):
    return rq.get(user_url)              # import requests as rq

def bypass_ssrf_dotted_alias(user_url):
    return ur.urlopen(user_url)          # import urllib.request as ur


# ─── py/no-command-injection ───────────────────────────────────────────────
def bypass_cmdinj_aliased_module(user_input):
    return osmod.system(user_input)      # import os as osmod

def bypass_cmdinj_from_import_alias(user_input):
    return run_shell(user_input)         # from os import system as run_shell

def bypass_cmdinj_subprocess_aliased(user_input):
    return sp.Popen(user_input)          # import subprocess as sp

def bypass_cmdinj_from_import_popen_alias(user_input):
    return SpawnProc(user_input)         # from subprocess import Popen as SpawnProc


# ─── py/no-path-traversal ──────────────────────────────────────────────────
def bypass_path_traversal_aliased(user_path):
    return osmod.remove(user_path)       # import os as osmod

# Note: `open` is a builtin, so no alias form is interesting for py/no-path-traversal.
# One direct hit just to keep the rule represented.
def direct_open_dynamic(user_path):
    return open(user_path)
