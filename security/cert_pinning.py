"""
Feature 1 – TLS-Zertifikat-Pinning (Trust On First Use / TOFU).

Beim ersten Verbindungsaufbau wird der SHA-256-Fingerprint des
DER-codierten Zertifikats gespeichert. Jede spätere Abweichung
wird erkannt und dem Nutzer zur Bestätigung angezeigt.

Keine zusätzliche Bibliothek nötig (nur stdlib ssl + hashlib).
"""
from __future__ import annotations

import hashlib
import json
import socket
import ssl
from pathlib import Path
from typing import Optional

_PIN_FILE = Path.home() / ".vt_analyzer_pins.json"
_TIMEOUT  = 10  # Sekunden


# ── Fingerprint-Berechnung ────────────────────────────────────────────────

def _fetch_cert_sha256(hostname: str, port: int = 443) -> str:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            der = tls.getpeercert(binary_form=True)
            return hashlib.sha256(der).hexdigest()


# ── Pin-Speicher ──────────────────────────────────────────────────────────

def _load_pins() -> dict[str, str]:
    if _PIN_FILE.exists():
        try:
            return json.loads(_PIN_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_pin(hostname: str, fingerprint: str) -> None:
    pins = _load_pins()
    pins[hostname] = fingerprint
    _PIN_FILE.write_text(json.dumps(pins, indent=2), encoding="utf-8")
    _PIN_FILE.chmod(0o600)


def accept_pin(hostname: str, fingerprint: str) -> None:
    """Speichert einen neuen oder geänderten Pin (nach Nutzerbestätigung)."""
    _save_pin(hostname, fingerprint)


# ── Öffentliche Prüf-API ──────────────────────────────────────────────────

class PinResult:
    """Ergebnis der Zertifikat-Prüfung."""
    __slots__ = ("ok", "is_first_use", "current", "stored", "error")

    def __init__(
        self,
        ok: bool,
        is_first_use: bool = False,
        current: str = "",
        stored: str = "",
        error: str = "",
    ):
        self.ok          = ok
        self.is_first_use = is_first_use
        self.current     = current
        self.stored      = stored
        self.error       = error


def verify(hostname: str = "www.virustotal.com") -> PinResult:
    """
    Prüft den Zertifikat-Fingerprint gegen den gespeicherten Pin.
    Gibt PinResult zurück – niemals Exception.
    """
    try:
        current = _fetch_cert_sha256(hostname)
    except Exception as exc:
        return PinResult(ok=False, error=str(exc))

    stored = _load_pins().get(hostname)

    if stored is None:
        # Erster Verbindungsaufbau – Pin speichern
        _save_pin(hostname, current)
        return PinResult(ok=True, is_first_use=True, current=current)

    if current == stored:
        return PinResult(ok=True, current=current, stored=stored)

    # Fingerprint hat sich geändert
    return PinResult(ok=False, current=current, stored=stored)
