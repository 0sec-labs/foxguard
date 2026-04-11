# Taint fixture for CLI-tool sources (issue #30). Each handler shows
# a different untrusted CLI input reaching a taint sink. These paths
# all work today without issue #27: `sys.argv[1]` is subscript on a
# tainted attribute, `input()` and `os.getenv(...)` are bare calls.

import os
import subprocess
import sys


# ─── py/taint-command-injection via sys.argv ───────────────────────
def cli_argv():
    subprocess.run(sys.argv[1], shell=True)


# ─── py/taint-command-injection via os.getenv ──────────────────────
def cli_env():
    cmd = os.getenv("USER_CMD")
    os.system(cmd)


# ─── py/taint-eval via input() ─────────────────────────────────────
def cli_input():
    user_input = input("enter: ")
    return eval(user_input)


# ─── py/taint-eval via sys.stdin.read() ────────────────────────────
def cli_stdin():
    data = sys.stdin.read()
    return eval(data)


# ─── py/taint-command-injection via os.environ subscript ───────────
def cli_environ_subscript():
    cmd = os.environ["USER_CMD"]
    os.system(cmd)
