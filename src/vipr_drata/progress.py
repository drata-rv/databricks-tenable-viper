import contextlib
import sys
import threading
import time

_lock = threading.Lock()
_local = threading.local()
_state = {"start": time.monotonic(), "quiet": False}


def start(quiet=False):
    _state["start"] = time.monotonic()
    _state["quiet"] = quiet


@contextlib.contextmanager
def label(name):
    previous = getattr(_local, "label", None)
    _local.label = name
    try:
        yield
    finally:
        _local.label = previous


def log(message, *args):
    if _state["quiet"]:
        return
    elapsed = int(time.monotonic() - _state["start"])
    tag = getattr(_local, "label", None)
    line = "[%02d:%02d]%s %s" % (elapsed // 60, elapsed % 60, " [%s]" % tag if tag else "", message % args if args else message)
    with _lock:
        print(line, flush=True)


def megabytes(n):
    return "%.2f MB" % (n / 1e6)
