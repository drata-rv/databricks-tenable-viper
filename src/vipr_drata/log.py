import contextlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timezone

_lock = threading.Lock()
_local = threading.local()
_state = {"quiet": False, "file": None}
_BARE = re.compile(r"[A-Za-z0-9_.:/@+,=%\-]+\Z")


def start(quiet=False, path=None):
    _state["quiet"] = quiet
    if _state["file"]:
        _state["file"].close()
        _state["file"] = None
    if path:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        _state["file"] = open(path, "w", encoding="utf-8")


@contextlib.contextmanager
def context(**fields):
    previous = getattr(_local, "fields", {})
    _local.fields = {**previous, **fields}
    try:
        yield
    finally:
        _local.fields = previous


def _value(v):
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float):
        return "%.2f" % v
    if isinstance(v, (list, tuple, set)):
        v = ",".join(str(x) for x in v)
    if isinstance(v, dict):
        v = ",".join("%s:%s" % kv for kv in v.items())
    s = str(v)
    return s if _BARE.match(s) else json.dumps(s, ensure_ascii=False)


def _emit(level, component, event, fields):
    now = datetime.now(timezone.utc)
    merged = {**getattr(_local, "fields", {}), **fields}
    line = "%s.%03dZ %-5s %s %s%s" % (now.strftime("%Y-%m-%dT%H:%M:%S"), now.microsecond // 1000, level, component, event,
                                      "".join(" %s=%s" % (k, _value(v)) for k, v in merged.items()))
    with _lock:
        if _state["file"]:
            _state["file"].write(line + "\n")
            _state["file"].flush()
        if not (level == "INFO" and _state["quiet"]):
            print(line, file=sys.stdout if level == "INFO" else sys.stderr, flush=True)


def info(component, event, **fields):
    _emit("INFO", component, event, fields)


def warn(component, event, **fields):
    _emit("WARN", component, event, fields)


def error(component, event, **fields):
    _emit("ERROR", component, event, fields)


def mb(n):
    return round(n / 1e6, 2)
