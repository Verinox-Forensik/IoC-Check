"""
Gesicherter HTTP-Client mit Allowlist-Durchsetzung und Netzwerk-Transparenz-Log.

Jede ausgehende Verbindung wird gegen ALLOWED_HOSTS geprüft.
Anfragen an nicht autorisierte Domains werden blockiert und im Log protokolliert.
Der API-Key erscheint in keiner Log-Ausgabe.
"""
from __future__ import annotations

from datetime import datetime
from queue import Queue
from typing import Optional
from urllib.parse import urlparse

import requests

ALLOWED_HOSTS: frozenset[str] = frozenset({"www.virustotal.com"})


class SecurityViolation(Exception):
    pass


class SecureSession(requests.Session):
    def __init__(self, api_key: str, log_queue: Optional[Queue] = None):
        super().__init__()
        self._api_key = api_key
        self._log_queue = log_queue

    # ------------------------------------------------------------------
    # Öffentliche Schnittstelle
    # ------------------------------------------------------------------

    def request(self, method: str, url: str, **kwargs):
        host = urlparse(url).hostname or ""
        if host not in ALLOWED_HOSTS:
            self._log("BLOCKED", f"BLOCKIERT: {method} → {host}  (nicht in Allowlist)")
            raise SecurityViolation(
                f"Verbindung zu '{host}' verweigert. "
                f"Erlaubt: {', '.join(sorted(ALLOWED_HOSTS))}"
            )

        self._log("REQUEST", f"→ {method} {url}")
        response = super().request(method, url, **kwargs)
        self._log("RESPONSE", f"← HTTP {response.status_code}  ({url})")
        return response

    # ------------------------------------------------------------------
    # Internes Logging
    # ------------------------------------------------------------------

    def _log(self, level: str, message: str) -> None:
        # API-Key darf niemals in Logs erscheinen
        if self._api_key and self._api_key in message:
            message = message.replace(self._api_key, "[KEY REDACTED]")

        if self._log_queue:
            self._log_queue.put({
                "type":      "network",
                "level":     level,
                "message":   message,
                "timestamp": datetime.now().strftime("%H:%M:%S"),
            })
