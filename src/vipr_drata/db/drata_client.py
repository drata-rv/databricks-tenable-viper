import json
import math
import threading
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import requests

MAX_BODY_BYTES = 4 * 1024 * 1024  # Drata limit 5 MB
RECORD_ERRORS = {400, 413, 422}  # other 4xx are request-level: stop sending
PERMANENT = (requests.exceptions.InvalidHeader, requests.exceptions.InvalidURL,
             requests.exceptions.InvalidSchema, requests.exceptions.MissingSchema)
INTERRUPTED = "interrupted"
MAX_RETRY_AFTER = 120.0
WRAPPER_KEYS = ("data", "results", "items", "records")
SESSION_PREFIX = "vipr-"
STALE_SESSION_AFTER = timedelta(hours=2)


# compact JSON: the size guard in batching.py measures these same bytes
def dumps(body):
    return json.dumps(body, separators=(",", ":"), default=str)


def chunk_records(records, batch_size=100, max_bytes=MAX_BODY_BYTES):
    batch, size = [], 0
    for r in records:
        n = len(dumps(r))
        if batch and (len(batch) >= batch_size or size + n > max_bytes):
            yield batch
            batch, size = [], 0
        batch.append(r)
        size += n
    if batch:
        yield batch


class DrataClient:
    def __init__(self, base_url, api_key, workers=4, batch_size=100,
                 max_errors=3, max_rate_limits=10, backoff=2.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.workers = workers
        self.batch_size = batch_size
        self.max_errors = max_errors
        self.max_rate_limits = max_rate_limits
        self.backoff = backoff
        self._local = threading.local()
        self._fatal = None
        self._unverified = []
        self._stop = threading.Event()

    @property
    def unverified(self):
        return len(self._unverified)

    def _build_session(self):
        s = requests.Session()
        s.headers.update({"Authorization": "Bearer " + self.api_key, "Content-Type": "application/json"})
        return s

    def _session(self):
        if not hasattr(self._local, "s"):
            self._local.s = self._build_session()
        return self._local.s

    def _base(self, connection_id, resource_id):
        return "%s/public/v2/custom-connections/%s/resources/%s" % (self.base_url, connection_id, resource_id)

    @staticmethod
    def _retry_after(resp, default):
        try:
            v = float(resp.headers.get("Retry-After"))
        except (TypeError, ValueError):
            return default
        if not math.isfinite(v) or v < 0:
            return default
        return min(v, MAX_RETRY_AFTER)

    def _sleep(self, seconds):
        self._stop.wait(seconds)

    def _post(self, url, body, force=False):
        ok, err, _ = self._send(url, body, force)
        return ok, err

    def _send(self, url, body, force=False):
        errors = limits = 0
        max_errors = 1 if force else self.max_errors
        max_limits = 1 if force else self.max_rate_limits
        payload = dumps(body)
        while True:
            if self._fatal == INTERRUPTED and not force:
                return False, INTERRUPTED, None
            try:
                resp = self._session().post(url, data=payload, timeout=60)
            except PERMANENT as e:
                self._fatal = "request rejected locally: %s" % type(e).__name__
                return False, self._fatal, None
            except requests.RequestException as e:
                errors += 1
                if errors > max_errors:
                    return False, type(e).__name__, None
                self._sleep(self.backoff * errors)
                continue
            code = resp.status_code
            if code == 429:
                limits += 1
                if limits > max_limits:
                    if not force:  # circuit breaker: stop the remaining batches retrying
                        self._fatal = "rate limited: retries exhausted"
                    return False, "rate limited", None
                self._sleep(self._retry_after(resp, self.backoff * limits))
            elif code >= 500:
                errors += 1
                if errors > max_errors:
                    return False, "HTTP %s" % code, None
                self._sleep(self.backoff * errors)
            elif code >= 400:
                if code not in RECORD_ERRORS:
                    self._fatal = "HTTP %s: %s" % (code, resp.text[:200])
                return False, "HTTP %s: %s" % (code, resp.text[:200]), None
            else:
                return True, None, resp

    def _item_errors(self, resp, batch):
        try:
            data = resp.json()
        except ValueError:
            data = None
        if isinstance(data, dict):
            data = next((data[k] for k in WRAPPER_KEYS if isinstance(data.get(k), list)), data)
        if not isinstance(data, list):
            if len(batch) > 1:
                self._unverified.append(1)
            return []
        out = []
        for rec, item in zip(batch, data):
            status = item.get("statusCode") if isinstance(item, dict) else None
            if status is not None and status not in (200, 201):
                err = item.get("error")
                msg = (err.get("message") if isinstance(err, dict) else err) or ""
                out.append({"id": rec.get("id"), "error": "item status %s: %s" % (status, str(msg)[:200])})
        out += [{"id": rec.get("id"), "error": "no per-item result returned"} for rec in batch[len(data):]]
        return out

    def _push_batch(self, url, batch):
        if self._fatal:
            return 0, [{"id": r.get("id"), "error": "not sent: " + self._fatal} for r in batch]
        ok, err, resp = self._send(url, {"data": batch})
        if ok:
            bad = self._item_errors(resp, batch)
            return len(batch) - len(bad), bad
        if len(batch) > 1 and not self._fatal and any(err.startswith("HTTP %d" % c) for c in RECORD_ERRORS):
            good, failed = 0, []
            for rec in batch:
                if self._fatal:
                    failed.append({"id": rec.get("id"), "error": "not sent: " + self._fatal})
                    continue
                ok1, err1, resp1 = self._send(url, {"data": [rec]})
                bad = self._item_errors(resp1, [rec]) if ok1 else [{"id": rec.get("id"), "error": err1}]
                good += 0 if bad else 1
                failed.extend(bad)
            return good, failed
        return 0, [{"id": r.get("id"), "error": err} for r in batch]

    def _push_all(self, url, records):
        self._fatal = None
        ok, failed = 0, []
        batches = list(chunk_records(records, self.batch_size))
        ex = ThreadPoolExecutor(max_workers=self.workers)
        try:
            for g, f in ex.map(lambda b: self._push_batch(url, b), batches):
                ok += g
                failed.extend(f)
        except BaseException:
            self._fatal = INTERRUPTED
            self._stop.set()
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        ex.shutdown()
        return ok, failed

    def upsert(self, connection_id, resource_id, records):
        return self._push_all(self._base(connection_id, resource_id) + "/records", records)

    def _get(self, url):
        errors = limits = 0
        while True:
            try:
                resp = self._session().get(url, timeout=30)
            except requests.RequestException:
                errors += 1
                if errors > self.max_errors:
                    return None
                self._sleep(self.backoff * errors)
                continue
            code = resp.status_code
            if not isinstance(code, int):
                return None
            if code == 429 or code >= 500:
                limits += 1
                if limits > self.max_rate_limits:
                    return None
                self._sleep(self._retry_after(resp, self.backoff * limits))
                continue
            if code >= 400:
                return None
            try:
                return resp.json()
            except ValueError:
                return None

    @staticmethod
    def _session_age(session_id, now):
        try:
            started = datetime.strptime(session_id[len(SESSION_PREFIX):], "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        return now - started

    def _stale_sessions(self, base, own_id, now=None):
        now = now or datetime.now(timezone.utc)
        # only this tool's own sessions, older than 2 h: never cancel another writer's session
        data = self._get(base + "/sessions?status=IN_PROGRESS")
        if isinstance(data, dict):
            data = next((data[k] for k in WRAPPER_KEYS if isinstance(data.get(k), list)), [])
        if data is None:
            return None
        if not isinstance(data, list):
            return []
        stale = []
        for item in data:
            if isinstance(item, dict) and item.get("status") not in (None, "IN_PROGRESS"):
                continue
            sid = str((item.get("sessionId") or item.get("id")) if isinstance(item, dict) else item or "")
            age = self._session_age(sid, now) if sid.startswith(SESSION_PREFIX) else None
            if sid and sid != own_id and age is not None and age > STALE_SESSION_AFTER:
                stale.append(sid)
        return stale

    def replace_via_session(self, connection_id, resource_id, records, session_id):
        if not records:
            return 0, [{"id": None, "error": "empty snapshot: refusing session replace"}], "skipped"
        base = self._base(connection_id, resource_id)
        actions = base + "/sessions/%s/actions" % session_id
        finished = False
        # complete hard-deletes every record not staged
        try:
            stale = self._stale_sessions(base, session_id)
            for sid in stale or []:
                self._post(base + "/sessions/%s/actions" % sid, {"action": "cancel"}, force=True)
            ok, failed = self._push_all("%s/sessions/%s" % (base, session_id), records)
            action = "complete" if not failed else "cancel"
            done, err = self._post(actions, {"action": action})
            finished = done
            if not done:
                failed.append({"id": None, "error": "session %s failed: %s" % (action, err)})
                if action == "complete":
                    self._post(actions, {"action": "cancel"}, force=True)
                    if stale is None:
                        failed.append({"id": None, "error": "in-progress sessions could not be listed; a session from "
                                                             "another run may be blocking complete"})
            return ok, failed, action
        except BaseException:
            if not finished:
                self._post(actions, {"action": "cancel"}, force=True)
            raise
