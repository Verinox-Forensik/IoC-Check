"""
Orchestriert die Extraktion und den VT-Scan.
Läuft in einem eigenen Thread; kommuniziert via Queue mit der GUI.
Alle Texte werden als Schlüssel (msg_key) gesendet – die GUI übersetzt.
"""
from __future__ import annotations

import threading
import time
from queue import Queue
from typing import Optional

from core.extractor import extract_from_file
from core.virustotal import VTClient
from security.secure_session import SecurityViolation


class Scanner:
    def __init__(
        self,
        api_key:      str,
        file_path:    str,
        scan_ips:     bool = True,
        scan_domains: bool = True,
        rate_limit:   int  = 4,
        event_queue:  Optional[Queue] = None,
    ):
        self.api_key      = api_key
        self.file_path    = file_path
        self.scan_ips     = scan_ips
        self.scan_domains = scan_domains
        self.rate_limit   = max(1, rate_limit)
        self.event_queue  = event_queue or Queue()
        self.results:     list[dict] = []
        self._stop        = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            self._run()
        except Exception as exc:
            self._emit("error", msg_key="log_unexpected", detail=str(exc))
            self._emit("done", results=self.results)

    def _run(self) -> None:
        self._emit("status", msg_key="log_reading")

        try:
            extraction = extract_from_file(self.file_path)
        except Exception as exc:
            self._emit("error", msg_key="log_read_err", detail=str(exc))
            self._emit("done", results=self.results)
            return

        # Immer die rohen Zahlen senden – GUI zeigt Info-Box
        self._emit(
            "extracted",
            ips=len(extraction.ips),
            domains=len(extraction.domains),
        )

        targets: list[tuple[str, str]] = []
        if self.scan_ips:
            targets += [("ip", ip) for ip in extraction.ips]
        if self.scan_domains:
            targets += [("domain", d) for d in extraction.domains]

        if not targets:
            self._emit("error", msg_key="log_no_targets")
            self._emit("done", results=self.results)
            return

        total     = len(targets)
        wait_secs = 60.0 / self.rate_limit
        self._emit("total", total=total)

        client = VTClient(self.api_key, self.event_queue)

        for i, (kind, target) in enumerate(targets, start=1):
            if self._stop.is_set():
                self._emit("status", msg_key="log_aborted")
                break

            self._emit("progress", current=i, total=total, target=target)

            try:
                result = (
                    client.check_ip(target)
                    if kind == "ip"
                    else client.check_domain(target)
                )
            except SecurityViolation as exc:
                self._emit("error", msg_key="log_unexpected", detail=str(exc))
                break

            if result.get("error") == "INVALID_KEY":
                self._emit("error", msg_key="log_invalid_key")
                break

            if result.get("error") == "RATE_LIMIT":
                self._emit("status", msg_key="log_rate_limit")
                self._interruptible_sleep(60)
                result = (
                    client.check_ip(target)
                    if kind == "ip"
                    else client.check_domain(target)
                )

            self.results.append(result)
            self._emit("result", result=result, index=i, total=total)

            if i < total and not self._stop.is_set():
                self._emit("waiting", seconds=wait_secs)
                self._interruptible_sleep(wait_secs)

        self._emit("done", results=self.results)

    def _emit(self, event_type: str, **kwargs) -> None:
        self.event_queue.put({"type": event_type, **kwargs})

    def _interruptible_sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end and not self._stop.is_set():
            time.sleep(0.1)
