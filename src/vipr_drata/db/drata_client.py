"""Drata Custom Connections v2 client.

POST {base}/public/v2/custom-connections/{connection}/resources/{resource}/records  body {"data": [..]}
Records upsert on `id`. Session mode stages a full snapshot then atomically replaces the live
dataset (destructive: anything not in the session is hard-deleted), so it only completes on 0 failures.
Retry budgets: 429 (rate limit) separate from 5xx/network; other 4xx fail fast.
"""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

MAX_BODY_BYTES = 4 * 1024 * 1024  # Drata max JSON is 5 MB


def chunk_records(records, batch_size=100, max_bytes=MAX_BODY_BYTES):
    batch, size = [], 0
    for r in records:
        n = len(json.dumps(r, default=str))
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
            return float(resp.headers.get("Retry-After"))
        except (TypeError, ValueError):
            return default  # may be an HTTP-date; fall back

    def _post(self, url, body):
        errors = limits = 0
        while True:
            try:
                resp = self._session().post(url, json=body, timeout=60)
            except requests.RequestException as e:
                errors += 1
                if errors > self.max_errors:
                    return False, str(e)
                time.sleep(self.backoff * errors)
                continue
            code = resp.status_code
            if code == 429:
                limits += 1
                if limits > self.max_rate_limits:
                    return False, "rate limited"
                time.sleep(self._retry_after(resp, self.backoff * limits))
            elif code >= 500:
                errors += 1
                if errors > self.max_errors:
                    return False, "HTTP %s" % code
                time.sleep(self.backoff * errors)
            elif code >= 400:
                return False, "HTTP %s: %s" % (code, resp.text[:200])
            else:
                return True, None

    def _push_batch(self, url, batch):
        ok, err = self._post(url, {"data": batch})
        if ok:
            return len(batch), []
        if len(batch) > 1 and err.startswith("HTTP 4"):
            # isolate the offending record(s) instead of failing the whole batch
            good, failed = 0, []
            for rec in batch:
                g, e = self._post(url, {"data": rec})
                if g:
                    good += 1
                else:
                    failed.append({"id": rec.get("id"), "error": e})
            return good, failed
        return 0, [{"id": r.get("id"), "error": err} for r in batch]

    def _push_all(self, url, records):
        ok, failed = 0, []
        batches = list(chunk_records(records, self.batch_size))
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for g, f in ex.map(lambda b: self._push_batch(url, b), batches):
                ok += g
                failed.extend(f)
        return ok, failed

    def upsert(self, connection_id, resource_id, records):
        """Direct upsert: live immediately, never deletes stale records."""
        return self._push_all(self._base(connection_id, resource_id) + "/records", records)

    def replace_via_session(self, connection_id, resource_id, records, session_id):
        """Atomic snapshot replace. Completes only if every record staged; otherwise cancels."""
        base = self._base(connection_id, resource_id)
        ok, failed = self._push_all("%s/sessions/%s" % (base, session_id), records)
        action = "complete" if not failed and records else "cancel"
        done, err = self._post("%s/sessions/%s/actions" % (base, session_id), {"action": action})
        if not done:
            failed.append({"id": None, "error": "session %s failed: %s" % (action, err)})
        return ok, failed, action
