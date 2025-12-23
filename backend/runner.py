import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Callable, Optional
from datetime import datetime

from scanner import scan_host


def _parse_target(target: str):
    """
    Parse "host" or "host:port" -> (host, port)
    """
    t = (target or "").strip()
    if not t:
        return None, None
    if ":" in t:
        host, port_str = t.split(":", 1)
        host = host.strip()
        try:
            port = int(port_str.strip())
        except Exception:
            port = 443
        return host, port
    return t, 443


def _scan_one(target: str) -> Dict[str, Any]:
    host, port = _parse_target(target)
    if not host:
        return {"host": "", "port": 0, "error": "empty target", "risk": "unknown"}
    return scan_host(host, port)


def run_scan_job(
    scan_id: str,
    targets: List[str],
    config: Dict[str, Any],
    on_progress: Callable[[int, int], None],
    on_done: Callable[[List[Dict[str, Any]]], None],
    on_failed: Callable[[str], None],
) -> None:
    """
    Run scan in a worker thread with concurrency and progress callbacks.
    """
    # Config defaults
    max_workers = int(config.get("max_workers") or 20)
    if max_workers < 1:
        max_workers = 1
    if max_workers > 200:
        max_workers = 200  # safety

    # Deduplicate & clean
    cleaned = []
    seen = set()
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        if t in seen:
            continue
        seen.add(t)
        cleaned.append(t)

    total = len(cleaned)
    if total == 0:
        on_done([])
        return

    results: List[Dict[str, Any]] = []
    completed = 0

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(_scan_one, t) for t in cleaned]
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"host": "", "port": 0, "error": str(e), "risk": "unknown (scan error)"}

                results.append(res)
                completed += 1
                on_progress(completed, total)

        # Keep results stable-ish: sort by host:port for repeatable outputs
        def _key(r):
            return (r.get("host") or "", int(r.get("port") or 0))
        results.sort(key=_key)

        on_done(results)
    except Exception as e:
        on_failed(str(e))
