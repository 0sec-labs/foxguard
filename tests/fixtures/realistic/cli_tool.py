# Realistic CLI fixture (issue #35). Mixes sys.argv, os.getenv, and
# input() flowing through helper functions into command-injection and
# eval sinks. Exercises interprocedural propagation.
#
# Hand-counted expected taint findings:
#   py/taint-command-injection : 2
#   py/taint-eval              : 2

import os
import subprocess
import sys


# ─── Helpers ───────────────────────────────────────────────────────────
def read_argv():
    """Return the first CLI argument — tainted source through helper."""
    return sys.argv[1]


def env_cmd():
    """Environment variable helper — tainted source."""
    return os.getenv("USER_CMD")


def prompt():
    """Interactive input — tainted source."""
    return input("expr> ")


# ─── CLI entry points ──────────────────────────────────────────────────
def run_from_argv():
    # py/taint-command-injection — helper returns tainted argv[1]
    cmd = read_argv()
    subprocess.run(cmd, shell=True)


def run_from_env():
    # py/taint-command-injection — helper returns tainted env var
    cmd = env_cmd()
    os.system(cmd)


def calc_interactive():
    # py/taint-eval — helper returns tainted input()
    expr = prompt()
    return eval(expr)


def calc_from_stdin():
    # py/taint-eval — direct sys.stdin source
    data = sys.stdin.read()
    return eval(data)


def main():
    if len(sys.argv) < 2:
        return
    action = sys.argv[1]
    if action == "run":
        run_from_argv()
    elif action == "env":
        run_from_env()
    elif action == "calc":
        calc_interactive()
    else:
        calc_from_stdin()


# ─── NEAR MISS — must not fire ─────────────────────────────────────────
def static_run():
    # NEAR MISS — literal command
    subprocess.run("ls -la", shell=True)


def trusted_eval():
    # NEAR MISS — literal expression
    return eval("40 + 2")


def ignore_argv():
    # NEAR MISS — tainted value read but never flows to a sink
    _unused = sys.argv[1]  # noqa: F841
    os.system("whoami")


if __name__ == "__main__":
    main()
