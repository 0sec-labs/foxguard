# Negative fixture for the taint POC. Every function here calls
# `pickle.loads` on something, but none of the arguments are reachable
# from an untrusted source within the same function — so
# `py/taint-pickle-deserialization` must NOT fire on this file.
#
# The existing `py/no-pickle` rule WILL fire on every call here because
# it's conservative by design. That's correct and expected. This fixture
# proves the new taint rule doesn't over-fire relative to NoPickle.

import pickle
from flask import request


# Static literal argument — never untrusted.
def static_literal():
    return pickle.loads(b"static-bytes-payload")


# Reassignment with a clean literal kills earlier taint.
def reassignment_kills_taint():
    data = request.data
    data = b"overwritten-with-trusted-bytes"
    return pickle.loads(data)


# `request` is a *local variable* here, not a parameter or import, so
# it is not tainted. The taint rule must not assume any name equal to
# `request` is a source.
def local_named_request_is_not_a_source():
    request = b"some-bytes"  # noqa: F811  local shadow
    return pickle.loads(request)


# Taint from a DIFFERENT function should not leak into this one — the
# engine is intraprocedural and per-function.
def producer():
    return request.data


def consumer_of_different_function():
    data = b"trusted"
    return pickle.loads(data)


# A call that happens to be named `loads` but isn't the pickle sink.
class NotPickle:
    def loads(self, x):
        return x


def not_pickle_loads():
    fake = NotPickle()
    return fake.loads(request.data)


# Tuple destructuring with two clean literal elements. Neither target
# should be tainted — element-wise unpack kills any prior taint.
def safe_tuple():
    a, b = b"clean1", b"clean2"
    return pickle.loads(a)


# Element-wise unpack where only the OTHER slot is tainted. The sink
# reads the clean slot, so the taint rule must stay silent.
def safe_tuple_other_slot_tainted():
    a, b = b"clean", request.args["x"]
    return pickle.loads(a)
