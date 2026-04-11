# Negative CLI fixture (issue #30). Every sink gets a trusted
# argument; `py/taint-*` rules must stay silent.

import os
import subprocess
import sys  # noqa: F401


def static_cmd():
    subprocess.run(["ls", "/tmp"])


def reassignment_kills_taint():
    cmd = os.getenv("USER_CMD")
    cmd = "ls /tmp"
    os.system(cmd)


def clean_eval():
    return eval("1 + 1")


def static_input_unused():
    _ = input("enter: ")  # noqa: F841 no sink reached
    os.system("ls")
