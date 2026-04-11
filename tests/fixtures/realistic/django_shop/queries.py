# Query/blob helpers for the django_shop fixture.
#
# These functions each take a parameter that is tainted when called
# from views.py, and pass it directly into a dangerous sink. Once the
# cross-file taint engine from issue #46 lands, callers in views.py
# should produce taint findings that propagate through these helpers.
#
# The file itself has no request sources, so running the current
# engine on this file in isolation should produce zero taint findings.

import pickle
import sqlite3


def run_query(name):
    # Would become a py/taint-sql-injection finding after #46 when
    # called from views.search with a tainted name.
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
    return cur.fetchall()


def load_blob(payload):
    # Would become a py/taint-pickle-deserialization finding after #46
    # when called from views.import_profile with the request body.
    return pickle.loads(payload)
