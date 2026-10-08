import json
import math
import threading
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import requests

from .. import progress

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
        self._codes = []
        self._sampled = []
        self._stop = threading.Event()

    @property
    def unverified(self):
        return len(self._unverified)

    @property
    def http_counts(self):
        counts = {}
        for code in list(self._codes):
            counts[code] = counts.get(code, 0) + 1
        return dict(sorted(counts.items()))

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
            if self._fatal and not force:
                return False, self._fatal, None
            try:
                resp = self._session().post(url, data=payload, timeout=60)
            except PERMANENT as e:
                self._fatal = "request rejected locally: %s" % type(e).__name__
                return False, self._fatal, None
            except requests.RequestException as e:
                errors += 1
                if errors > max_errors:
                    return False, type(e).__name__, None
                progress.log("%s talking to Drata, retry %d/%d in %.0fs", type(e).__name__, errors, max_errors, self.backoff * errors)
                self._sleep(self.backoff * errors)
                continue
            code = resp.status_code
            self._codes.append(code)
            if code == 429:
                limits += 1
                if limits > max_limits:
                    if not force:  # circuit breaker: stop the remaining batches retrying
                        self._fatal = "rate limited: retries exhausted"
                    return False, "rate limited", None
                wait = self._retry_after(resp, self.backoff * limits)
                progress.log("rate limited (HTTP 429), waiting %.0fs, retry %d/%d", wait, limits, max_limits)
                self._sleep(wait)
            elif code >= 500:
                errors += 1
                if errors > max_errors:
                    return False, "HTTP %s" % code, None
                progress.log("Drata returned HTTP %s, retry %d/%d in %.0fs", code, errors, max_errors, self.backoff * errors)
                self._sleep(self.backoff * errors)
            elif code >= 400:
                if code not in RECORD_ERRORS:
                    self._fatal = "HTTP %s: %s" % (code, resp.text[:200])
                progress.log("Drata rejected a request: HTTP %s %s", code, resp.text[:200])
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
            if not self._sampled:
                self._sampled.append(1)
                progress.log("first Drata response: HTTP %s %s", resp.status_code, str(resp.text)[:200].replace("\n", " "))
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

    def _push_all(self, url, records, what="records"):
        self._fatal = None
        ok, failed = 0, []
        batches = list(chunk_records(records, self.batch_size))
        progress.log("sending %d %s in %d request(s) (%d at a time)", len(records), what, len(batches), self.workers)
        ex = ThreadPoolExecutor(max_workers=self.workers)
        try:
            for n, (batch, (g, f)) in enumerate(zip(batches, ex.map(lambda b: self._push_batch(url, b), batches)), 1):
                ok += g
                failed.extend(f)
                progress.log("request %d/%d: %d record(s) %s, %s -> accepted %d, failed %d (running total %d/%d)",
                             n, len(batches), len(batch), ",".join(str(r.get("id")) for r in batch[:2]) + ("..." if len(batch) > 2 else ""),
                             progress.megabytes(len(dumps({"data": batch}))), g, len(f), ok, len(records))
        except BaseException:
            self._fatal = INTERRUPTED
            self._stop.set()
            ex.shutdown(wait=False, cancel_futures=True)
            raise
        ex.shutdown()
        return ok, failed

    def list_records(self, connection_id, resource_id, limit=100, pages=5):
        url = self._base(connection_id, resource_id) + "/records"
        found, total = [], None
        for page in range(1, pages + 1):
            data = self._get("%s?limit=%d&page=%d" % (url, limit, page))
            if isinstance(data, dict):
                total = next((data[k] for k in ("total", "totalCount", "count") if isinstance(data.get(k), int)), total)
                data = next((data[k] for k in WRAPPER_KEYS if isinstance(data.get(k), list)), None)
            if not isinstance(data, list):
                return (found, total) if found else None
            found += [str(i.get("id") or (i.get("data") or {}).get("id")) for i in data if isinstance(i, dict)]
            if len(data) < limit:
                break
        return found, total

    def upsert(self, connection_id, resource_id, records):
        return self._push_all(self._base(connection_id, resource_id) + "/records", records, "records (upsert)")

    def session_record_count(self, base, session_id):
        data = self._get("%s/records?sessionId=%s&limit=100" % (base, session_id))
        if isinstance(data, dict):
            total = next((data[k] for k in ("total", "totalCount", "count") if isinstance(data.get(k), int)), None)
            data = next((data[k] for k in WRAPPER_KEYS if isinstance(data.get(k), list)), None)
            if isinstance(data, list):
                return total if total is not None else len(data)
            return total
        return len(data) if isinstance(data, list) else None

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
        stage = "%s/sessions/%s" % (base, session_id)
        finished = False
        # complete hard-deletes every record not staged
        try:
            progress.log("session %s: looking for stale in-progress sessions", session_id)
            stale = self._stale_sessions(base, session_id)
            for sid in stale or []:
                progress.log("cancelling stale session %s (older than 2 h)", sid)
                self._post(base + "/sessions/%s/actions" % sid, {"action": "cancel"}, force=True)
            progress.log("session %s: staging 1 probe record to check Drata attaches it to the session", session_id)
            ok, failed = self._push_all(stage, records[:1], "probe record")
            seen = self.session_record_count(base, session_id) if not failed else None
            progress.log("probe: Drata reports %s staged record(s) in the session", "an unknown number of" if seen is None else seen)
            if not failed and seen == 0:
                self._post(actions, {"action": "cancel"}, force=True)
                finished = True
                return 0, [{"id": None, "error": "Drata accepted the staged record but lists none in the session"}], "unusable"
            if not failed and len(records) > 1:
                more_ok, failed = self._push_all(stage, records[1:], "records (staging)")
                ok += more_ok
            staged = self.session_record_count(base, session_id) if not failed else None
            if staged is not None:
                progress.log("session %s: Drata reports %d staged record(s) (we sent %d)", session_id, staged, len(records))
            action = "complete" if not failed else "cancel"
            progress.log("session %s: %s", session_id, "completing (atomic replace of the dataset)" if action == "complete" else "cancelling because staging had failures")
            done, err = self._post(actions, {"action": action})
            finished = done
            if not done:
                failed.append({"id": None, "error": "session %s failed: %s" % (action, err)})
                if action == "complete":
                    progress.log("complete failed (%s); cancelling the session", err)
                    self._post(actions, {"action": "cancel"}, force=True)
                    if err and "no data records" in err:
                        return ok, failed, "unusable"
                    if stale is None:
                        failed.append({"id": None, "error": "in-progress sessions could not be listed; a session from "
                                                             "another run may be blocking complete"})
            else:
                progress.log("session %s: %s done", session_id, action)
            return ok, failed, action
        except BaseException:
            if not finished:
                self._post(actions, {"action": "cancel"}, force=True)
            raise
