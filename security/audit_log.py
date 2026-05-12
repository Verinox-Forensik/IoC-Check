"""
Feature 6 – Append-only Auditlog mit Hash-Chain.

Jeder Scan erzeugt einen Eintrag, der den SHA-256-Hash des
vorherigen Eintrags enthält. Nachträgliche Manipulationen am Log
lassen sich so erkennen.

Format: JSONL (eine JSON-Zeile pro Eintrag)
Pfad:   ~/.vt_analyzer_audit.jsonl
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

AUDIT_FILE = Path.home() / ".vt_analyzer_audit.jsonl"
_GENESIS   = "0" * 64          # Vorgänger-Hash für den allerersten Eintrag


# ── Interne Hilfsfunktionen ───────────────────────────────────────────────

def _last_hash() -> str:
    if not AUDIT_FILE.exists():
        return _GENESIS
    last = ""
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
    except Exception:
        return _GENESIS
    if not last:
        return _GENESIS
    try:
        return json.loads(last).get("entry_hash", _GENESIS)
    except Exception:
        return _GENESIS


def _hash_entry(entry: dict) -> str:
    canonical = json.dumps(entry, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ── Öffentliche API ────────────────────────────────────────────────────────

def log_scan(
    *,
    file_name:    str,
    file_sha256:  str,
    ips_found:    int,
    domains_found: int,
    verdicts:     dict[str, int],   # {"MALICIOUS": 2, "CLEAN": 10, ...}
    scan_host:    str = "www.virustotal.com",
) -> str:
    """
    Schreibt einen neuen Eintrag in den Auditlog.
    Gibt den SHA-256-Hash des Eintrags zurück.
    """
    entry: dict = {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "file_name":     file_name,
        "file_sha256":   file_sha256,
        "ips_found":     ips_found,
        "domains_found": domains_found,
        "verdicts":      verdicts,
        "scan_host":     scan_host,
        "prev_hash":     _last_hash(),
    }
    entry["entry_hash"] = _hash_entry(entry)

    try:
        with AUDIT_FILE.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        AUDIT_FILE.chmod(0o600)
    except Exception:
        pass

    return entry["entry_hash"]


def verify_chain() -> tuple[bool, int, Optional[str]]:
    """
    Prüft die Integrität der gesamten Hash-Chain.
    Gibt (ok, geprüfte_einträge, fehler_beschreibung) zurück.
    """
    if not AUDIT_FILE.exists():
        return True, 0, None

    entries: list[dict] = []
    try:
        with AUDIT_FILE.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    except Exception as exc:
        return False, 0, str(exc)

    prev = _GENESIS
    for i, entry in enumerate(entries):
        claimed_hash = entry.get("entry_hash", "")
        # Hash ohne entry_hash-Feld berechnen
        check = {k: v for k, v in entry.items() if k != "entry_hash"}
        computed = _hash_entry(check)
        if computed != claimed_hash:
            return False, i, f"Eintrag {i+1}: berechneter Hash stimmt nicht überein."
        if entry.get("prev_hash", "") != prev:
            return False, i, f"Eintrag {i+1}: Vorgänger-Hash stimmt nicht überein."
        prev = claimed_hash

    return True, len(entries), None


def get_log_path() -> Path:
    return AUDIT_FILE
