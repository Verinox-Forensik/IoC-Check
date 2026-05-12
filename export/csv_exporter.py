"""
CSV-Export mit optionaler AES-256-Verschlüsselung (Feature 9).
Metadaten (Dateiname, SHA-256, Timestamp) werden als Kommentar-Header eingefügt.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Optional

from core.virustotal import RESULT_FIELDS

try:
    import pyzipper
    _ZIP_OK = True
except ImportError:
    _ZIP_OK = False


def _build_csv_bytes(results: list[dict], file_meta: Optional[dict] = None) -> bytes:
    buf = io.StringIO()

    # Kommentar-Header mit Metadaten (Feature 5)
    if file_meta:
        buf.write(f"# VT-Analyzer Scan Report\n")
        buf.write(f"# Erstellt am:    {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n")
        buf.write(f"# Eingabedatei:   {file_meta.get('file_name', 'N/A')}\n")
        buf.write(f"# SHA-256:        {file_meta.get('file_sha256', 'N/A')}\n")
        buf.write(f"# Einträge:       {len(results)}\n")
        buf.write("# " + "-" * 60 + "\n")

    writer = csv.DictWriter(buf, fieldnames=RESULT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(results)

    return buf.getvalue().encode("utf-8-sig")


def export_to_csv(
    results:   list[dict],
    path:      str,
    file_meta: Optional[dict] = None,
) -> None:
    """Unverschlüsselter CSV-Export."""
    data = _build_csv_bytes(results, file_meta)
    with open(path, "wb") as fh:
        fh.write(data)


def export_to_encrypted_csv(
    results:   list[dict],
    path:      str,
    password:  str,
    file_meta: Optional[dict] = None,
) -> str:
    """
    AES-256-verschlüsselter ZIP-Export.
    Gibt den tatsächlichen Ausgabepfad zurück (endet auf .zip).
    Fällt bei fehlendem pyzipper auf unverschlüsselt zurück.
    """
    data = _build_csv_bytes(results, file_meta)

    if not _ZIP_OK:
        # Graceful Fallback: unverschlüsselt
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    zip_path = path if path.endswith(".zip") else path.replace(".csv", ".zip")

    with pyzipper.AESZipFile(
        zip_path, "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.writestr("results.csv", data)

    return zip_path
