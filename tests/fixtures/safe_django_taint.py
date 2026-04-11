# Negative Django fixture (issue #29). Every handler calls a taint
# sink with a non-tainted argument, so `py/taint-*` rules must stay
# silent. Conservative `py/no-*` rules may still fire — that's the
# intended division of labor.

import os
import pickle
import yaml


def clean_literal_pickle():
    return pickle.loads(b"static-bytes")


def reassignment_kills_taint(request):
    data = request.POST["data"]
    data = b"overwritten"
    return pickle.loads(data)


def clean_command():
    os.system("ls /tmp")


def clean_eval():
    return eval("2 + 2")


def clean_yaml():
    return yaml.load("key: value")
