"""
Feature 2 – Proxy-Erkennung.

Prüft Umgebungsvariablen und System-Proxy-Einstellungen auf
konfigurierte HTTP/HTTPS-Proxies, die den API-Key exponieren könnten.
"""
from __future__ import annotations

import os
import urllib.request
from typing import Optional

_ENV_VARS = [
    "HTTPS_PROXY", "https_proxy",
    "HTTP_PROXY",  "http_proxy",
    "ALL_PROXY",   "all_proxy",
]


def detect() -> Optional[str]:
    """
    Gibt die Proxy-URL zurück, wenn ein Proxy konfiguriert ist,
    sonst None. HTTPS hat Vorrang (relevanter für API-Key-Schutz).
    """
    # 1. Umgebungsvariablen (explizit gesetzt, höchste Priorität)
    for var in _ENV_VARS:
        val = os.environ.get(var, "").strip()
        if val:
            return val

    # 2. System-Proxy (macOS/Windows Systemeinstellungen, PAC-Dateien)
    try:
        system = urllib.request.getproxies()
        return system.get("https") or system.get("http") or None
    except Exception:
        return None
