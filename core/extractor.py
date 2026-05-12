"""
Extrahiert IP-Adressen und Domains aus verschiedenen Dateiformaten mittels Regex.
Feature 5: compute_file_hash() liefert SHA-256 der Eingabedatei für den Auditlog.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import NamedTuple

try:
    import openpyxl
    _XLSX_OK = True
except ImportError:
    _XLSX_OK = False

# ---------------------------------------------------------------------------
# Regex-Muster
# ---------------------------------------------------------------------------

_RE_IP = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

_RE_URL = re.compile(
    r'https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}(?:[/?#][^\s<>"]*)?'
)

_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}\b'
)

_PRIVATE_IP = re.compile(
    r'^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.|0\.|255\.)'
)

_EXCLUDED_DOMAINS = {
    "localhost", "local", "invalid", "example.com", "example.org",
    "example.net", "test.com", "test.org",
}
_EXCLUDED_SUFFIXES = {".local", ".internal", ".lan", ".test"}


# ---------------------------------------------------------------------------
# Datenklasse
# ---------------------------------------------------------------------------

class ExtractionResult(NamedTuple):
    ips:         list[str]
    domains:     list[str]
    source_file: str


# ---------------------------------------------------------------------------
# SHA-256 Datei-Hash (Feature 5)
# ---------------------------------------------------------------------------

def compute_file_hash(path: str) -> str:
    """Berechnet den SHA-256-Hash der Datei in Chunks (speichereffizient)."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Datei lesen
# ---------------------------------------------------------------------------

def _file_to_text(path: Path) -> str:
    ext = path.suffix.lower()

    if ext in (".xlsx", ".xlsm"):
        if not _XLSX_OK:
            raise ImportError(
                "openpyxl wird für Excel-Dateien benötigt: pip install openpyxl"
            )
        wb   = openpyxl.load_workbook(path, read_only=True, data_only=True)
        rows = []
        for ws in wb.worksheets:
            for row in ws.iter_rows(values_only=True):
                rows.append(" ".join(str(c) for c in row if c is not None))
        return "\n".join(rows)

    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Extraktion
# ---------------------------------------------------------------------------

def extract_from_file(path: str) -> ExtractionResult:
    p    = Path(path)
    text = _file_to_text(p)

    # --- IPs ---
    raw_ips = _RE_IP.findall(text)
    ips     = list(dict.fromkeys(
        ip for ip in raw_ips if not _PRIVATE_IP.match(ip)
    ))

    # --- Domains ---
    from_urls = [
        m.group(1)
        for m in (_re_host(url) for url in _RE_URL.findall(text))
        if m
    ]
    bare = _RE_DOMAIN.findall(text)

    seen: dict[str, None] = {}
    for d in from_urls + bare:
        key = d.lower()
        if (
            key not in seen
            and key not in _EXCLUDED_DOMAINS
            and not any(key.endswith(s) for s in _EXCLUDED_SUFFIXES)
            and "." in key
            and not _RE_IP.fullmatch(key)
        ):
            seen[key] = None

    return ExtractionResult(ips=ips, domains=list(seen), source_file=str(p))


def _re_host(url: str):
    return re.match(r'https?://([^/?#\s]+)', url)
