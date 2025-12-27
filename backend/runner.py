from __future__ import print_function
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import threading
import time

from scanner import scan_host  # your scanner.py must expose scan_host(host, port)


class ScanJob(object):
    def __init__(self, scan_id: str, targets: List[str], max_workers: int = 15):
        self.id = scan_id
        self.targets = targets
        self.max_workers = max_workers

        self.created_at = datetime.utcnow()
        self.status = "running"

        self.total = len(targets)
        self.done = 0
        self.failed = 0
        self.percent = 0

        self.results: List[Dict[str, Any]] = []
        self._lock = threading.Lock()

        self.started_at = time.time()
        self.finished_at = None

    def _inc_done(self, ok: bool):
        with self._lock:
            self.done += 1
            if not ok:
                self.failed += 1
            self.percent = int((float(self.done) / float(self.total)) * 100) if self.total else 100

    def add_result(self, r: Dict[str, Any]):
        with self._lock:
            self.results.append(r)

    def run(self):
        if not self.targets:
            self.status = "completed"
            self.percent = 100
            self.finished_at = time.time()
            return

        def parse_target(t: str):
            t = (t or "").strip()
            if not t:
                return None
            if ":" in t:
                host, port = t.rsplit(":", 1)
                try:
                    return host.strip(), int(port.strip())
                except Exception:
                    return host.strip(), 443
            return t, 443

        parsed = []
        for t in self.targets:
            p = parse_target(t)
            if p:
                parsed.append(p)

        self.total = len(parsed)

        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {}
            for host, port in parsed:
                futures[ex.submit(scan_host, host, port)] = (host, port)

            for fut in as_completed(futures):
                host, port = futures[fut]
                try:
                    r = fut.result()
                    if not isinstance(r, dict):
                        r = {"host": host, "port": port, "error": "scan_host returned non-dict"}
                    ok = not bool(r.get("error"))
                    self.add_result(r)
                    self._inc_done(ok=ok)
                except Exception as e:
                    self.add_result({"host": host, "port": port, "error": str(e)})
                    self._inc_done(ok=False)

        self.status = "completed"
        self.percent = 100
        self.finished_at = time.time()

    def snapshot_progress(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "status": self.status,
                "created_at": self.created_at.isoformat(),
                "total": self.total,
                "done": self.done,
                "failed": self.failed,
                "percent": self.percent,
                "elapsed_seconds": int(time.time() - self.started_at),
            }

    def snapshot_results(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self.results)