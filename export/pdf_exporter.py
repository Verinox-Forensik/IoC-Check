"""
PDF-Export mit optionalem Passwortschutz (Feature 9) und Datei-Metadaten (Feature 5).
Generiert mit reportlab, verschlüsselt optional mit pypdf.
"""
from __future__ import annotations

import io
from collections import Counter
from datetime import datetime
from typing import Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
    )
    _RL_OK = True
except ImportError:
    _RL_OK = False

try:
    from pypdf import PdfReader, PdfWriter
    _PYPDF_OK = True
except ImportError:
    _PYPDF_OK = False


_VERDICT_BG = {
    "MALICIOUS":  colors.HexColor("#ffcccc") if _RL_OK else None,
    "SUSPICIOUS": colors.HexColor("#fff3cc") if _RL_OK else None,
    "CLEAN":      colors.HexColor("#ccffcc") if _RL_OK else None,
    "ERROR":      colors.HexColor("#eeeeee") if _RL_OK else None,
}
_VERDICT_FG = {
    "MALICIOUS":  colors.HexColor("#cc0000") if _RL_OK else None,
    "SUSPICIOUS": colors.HexColor("#996600") if _RL_OK else None,
    "CLEAN":      colors.HexColor("#006600") if _RL_OK else None,
    "ERROR":      colors.HexColor("#666666") if _RL_OK else None,
}


def _build_pdf_bytes(
    results: list[dict],
    file_meta: Optional[dict] = None,
) -> bytes:
    if not _RL_OK:
        raise ImportError("reportlab wird benötigt: pip install reportlab")

    buf    = io.BytesIO()
    doc    = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.5*cm,  bottomMargin=1.5*cm,
    )
    styles     = getSampleStyleSheet()
    title_sty  = ParagraphStyle("T", parent=styles["Heading1"], fontSize=15, spaceAfter=3)
    sub_sty    = ParagraphStyle("S", parent=styles["Normal"],   fontSize=8, textColor=colors.grey)
    cell_sty   = ParagraphStyle("C", parent=styles["Normal"],   fontSize=7, leading=9)
    footer_sty = ParagraphStyle("F", parent=styles["Normal"],   fontSize=7, textColor=colors.grey)

    story = []

    # ── Header ────────────────────────────────────────────────────────
    story.append(Paragraph("Verinox Forensik – VT-Analyzer Scan Report", title_sty))
    meta_lines = [f"Erstellt: {datetime.now().strftime('%d.%m.%Y %H:%M')}  |  Einträge: {len(results)}"]
    if file_meta:
        meta_lines.append(
            f"Eingabedatei: {file_meta.get('file_name', 'N/A')}  |  "
            f"SHA-256: {file_meta.get('file_sha256', 'N/A')}"
        )
    for line in meta_lines:
        story.append(Paragraph(line, sub_sty))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey, spaceAfter=6))

    # ── Zusammenfassung ───────────────────────────────────────────────
    counts = Counter(r.get("verdict", "ERROR") for r in results)
    sum_data = [["Verdict", "Anzahl"]] + [
        [v, str(counts.get(v, 0))]
        for v in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "ERROR")
    ]
    sum_table = Table(sum_data, colWidths=[5*cm, 2.5*cm])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    story.append(sum_table)
    story.append(Spacer(1, 0.4*cm))

    # ── Haupttabelle ──────────────────────────────────────────────────
    headers  = ["Target", "Typ", "Verdict", "Mal.", "Susp.", "Harm.", "Engines",
                "Registrar", "IP v4", "SSL-Aussteller", "Letzte Analyse"]
    col_keys = ["target", "type", "verdict", "malicious", "suspicious", "harmless",
                "engines_gesamt", "registrar", "ip_v4", "ssl_aussteller", "letzte_analyse"]
    col_w    = [5*cm, 1.4*cm, 2.4*cm, 1.1*cm, 1.1*cm, 1.1*cm, 1.7*cm,
                3.2*cm, 3.2*cm, 3.2*cm, 3.8*cm]

    tdata = [headers]
    for r in results:
        tdata.append([Paragraph(str(r.get(k, "")), cell_sty) for k in col_keys])

    cmds = [
        ("BACKGROUND",     (0, 0), (-1, 0), colors.HexColor("#333333")),
        ("TEXTCOLOR",      (0, 0), (-1, 0), colors.white),
        ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, -1), 7),
        ("VALIGN",         (0, 0), (-1, -1), "TOP"),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9f9f9")]),
    ]
    for i, r in enumerate(results, start=1):
        v = r.get("verdict", "ERROR")
        if _VERDICT_BG.get(v):
            cmds.append(("BACKGROUND", (2, i), (2, i), _VERDICT_BG[v]))
        if _VERDICT_FG.get(v):
            cmds.append(("TEXTCOLOR",  (2, i), (2, i), _VERDICT_FG[v]))

    main_tbl = Table(tdata, colWidths=col_w, repeatRows=1)
    main_tbl.setStyle(TableStyle(cmds))
    story.append(main_tbl)

    # ── Footer ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "Verinox Forensik – VT-Analyzer  |  "
        "Daten stammen ausschließlich von der VirusTotal API v3.  |  "
        "API-Key ist in keinem Export enthalten.",
        footer_sty,
    ))

    doc.build(story)
    return buf.getvalue()


def export_to_pdf(
    results:   list[dict],
    path:      str,
    file_meta: Optional[dict] = None,
    password:  Optional[str]  = None,
) -> None:
    """Exportiert als PDF, optional mit Passwortschutz."""
    pdf_bytes = _build_pdf_bytes(results, file_meta)

    if password and _PYPDF_OK:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.encrypt(password)
        with open(path, "wb") as fh:
            writer.write(fh)
    else:
        with open(path, "wb") as fh:
            fh.write(pdf_bytes)
