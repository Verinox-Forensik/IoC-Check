"""
API-Key-Verwaltung mit Timestamp für Rotations-Erinnerung (Feature 7).
Speicherung über OS-Schlüsselbund (Feature 3 Session-Modus: gar nicht speichern).
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import keyring
    import keyring.errors
    _KEYRING_OK = True
except ImportError:
    _KEYRING_OK = False

_SERVICE      = "vt-analyzer"
_KEY_V2       = "virustotal-api-key-v2"   # JSON: {key, saved_at}
_KEY_LEGACY   = "virustotal-api-key"       # alter Plaintext-Key
_FALLBACK     = Path.home() / ".vt_analyzer_key.json"
_ROTATION_DAYS = 90


# ── Intern ────────────────────────────────────────────────────────────────

def _encode(api_key: str) -> str:
    return json.dumps({"key": api_key, "saved_at": datetime.now().isoformat()})


def _decode(raw: str) -> tuple[str, Optional[datetime]]:
    """Gibt (key, saved_at) zurück; saved_at kann None sein (Altformat)."""
    try:
        data = json.loads(raw)
        if isinstance(data, dict) and "key" in data:
            key = data["key"]
            ts  = data.get("saved_at")
            saved_at = datetime.fromisoformat(ts) if ts else None
            return key, saved_at
    except Exception:
        pass
    return raw, None    # Altformat: Plaintext


def _read_raw() -> Optional[str]:
    if _KEYRING_OK:
        try:
            raw = keyring.get_password(_SERVICE, _KEY_V2)
            if raw:
                return raw
            # Altformat migrieren
            old = keyring.get_password(_SERVICE, _KEY_LEGACY)
            if old:
                return old
        except Exception:
            pass
    if _FALLBACK.exists():
        try:
            return _FALLBACK.read_text(encoding="utf-8")
        except Exception:
            pass
    return None


# ── Öffentliche API ────────────────────────────────────────────────────────

def save_key(api_key: str) -> str:
    """Speichert den Key mit Timestamp. Gibt Speichermethode zurück."""
    encoded = _encode(api_key)
    if _KEYRING_OK:
        try:
            keyring.set_password(_SERVICE, _KEY_V2, encoded)
            return "OS-Schlüsselbund"
        except Exception:
            pass
    _FALLBACK.write_text(encoded, encoding="utf-8")
    _FALLBACK.chmod(0o600)
    return "Lokale Datei (600)"


def load_key() -> Optional[str]:
    raw = _read_raw()
    if raw is None:
        return None
    key, _ = _decode(raw)
    return key


def key_age_days() -> Optional[int]:
    """Gibt Alter des Keys in Tagen zurück, oder None falls kein Key/Timestamp."""
    raw = _read_raw()
    if raw is None:
        return None
    _, saved_at = _decode(raw)
    if saved_at is None:
        return None
    return (datetime.now() - saved_at).days


def rotation_needed() -> bool:
    age = key_age_days()
    return age is not None and age >= _ROTATION_DAYS


def delete_key() -> None:
    if _KEYRING_OK:
        try:
            keyring.delete_password(_SERVICE, _KEY_V2)
        except Exception:
            pass
        try:
            keyring.delete_password(_SERVICE, _KEY_LEGACY)
        except Exception:
            pass
    _FALLBACK.unlink(missing_ok=True)


def mask_key(api_key: str) -> str:
    if not api_key:
        return ""
    suffix = api_key[-4:] if len(api_key) >= 4 else api_key
    return f"{'•' * 16}{suffix}"


def storage_info() -> tuple[str, bool]:
    """Gibt (Beschreibung, ist_sicher) zurück."""
    if _KEYRING_OK:
        try:
            keyring.get_password(_SERVICE, "__probe__")
            return ("OS-Schlüsselbund (Keychain / Credential Manager)", True)
        except Exception:
            pass
    return (f"Lokale Datei mit Modus 600\n({_FALLBACK})", False)
