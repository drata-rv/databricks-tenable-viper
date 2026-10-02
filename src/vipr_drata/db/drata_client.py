"""Push client: separate retry budgets (429 vs errors), thread-local sessions, upsert on externalId."""
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests


class DrataClient:
    def __init__(self, base_url, api_key, connection_id, push_path, workers=8,
                 max_errors=3, max_rate_limits=10, backoff=2.0):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.connection_id = connection_id
        self.push_path = push_path
        self.workers = workers
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

    def _url(self, resource):
        return self.base_url + self.push_path.format(connection_id=self.connection_id, resource=resource)

    @staticmethod
    def _retry_after(resp, default):
        try:
            return float(resp.headers.get("Retry-After"))
        except (TypeError, ValueError):
            return default  # may be an HTTP-date; fall back

    def push_one(self, resource, record):
        errors = limits = 0
        while True:
            try:
                resp = self._session().put(self._url(resource), json=record, timeout=60)
            except requests.RequestException as e:
                errors += 1
                if errors > self.max_errors:
                    return False, str(e)
                time.sleep(self.backoff * errors)
                continue
            if resp.status_code == 429:
                limits += 1
                if limits > self.max_rate_limits:
                    return False, "rate limited"
                time.sleep(self._retry_after(resp, self.backoff * limits))
            elif resp.status_code >= 500:
                errors += 1
                if errors > self.max_errors:
                    return False, "HTTP %s" % resp.status_code
                time.sleep(self.backoff * errors)
            elif resp.status_code >= 400:
                return False, "HTTP %s: %s" % (resp.status_code, resp.text[:200])
            else:
                return True, None

    def push_all(self, resource, records):
        ok, failed = 0, []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for rec, (good, err) in zip(records, ex.map(lambda r: self.push_one(resource, r), records)):
                if good:
                    ok += 1
                else:
                    failed.append({"externalId": rec.get("externalId"), "error": err})
        return ok, failed
