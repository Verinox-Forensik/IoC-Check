"""
Sicherheits-Informations-Panel – zeigt alle 11 aktiven Garantien.
Inhalt wird bei Sprachwechsel komplett neu aufgebaut.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import i18n
from security import audit_log
from security.keystore import storage_info


class SecurityPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=14)
        self._content: ttk.Frame | None = None
        self._build()

    def _build(self) -> None:
        if self._content:
            self._content.destroy()
        self._content = ttk.Frame(self)
        self._content.pack(fill="both", expand=True)
        self._populate(self._content)

    def _populate(self, parent: ttk.Frame) -> None:
        storage_desc, is_secure = storage_info()
        storage_icon  = "✅" if is_secure else "⚠️"
        storage_color = "#005500" if is_secure else "#8a5c00"

        # ── Haupttitel ────────────────────────────────────────────────
        ttk.Label(
            parent,
            text=i18n.t("sec_main_title"),
            font=("", 13, "bold"),
        ).pack(anchor="w", pady=(0, 10))

        # ── Garantien in 2 Spalten ────────────────────────────────────
        grid = ttk.Frame(parent)
        grid.pack(fill="x")

        items = i18n.guarantees()
        for idx, (icon_base, title, desc, color) in enumerate(items):
            col = idx % 2
            row = idx // 2

            # Speicher-Kachel: dynamisches Icon + Speicherort
            if idx == 1:
                icon  = storage_icon
                color = storage_color
                desc  = desc + f"\n{storage_desc}"
            else:
                icon = icon_base

            frame = ttk.LabelFrame(grid, text=f"  {icon}  {title}  ", padding=7)
            frame.grid(row=row, column=col, sticky="nsew", padx=(0, 6) if col == 0 else (6, 0), pady=3)
            ttk.Label(frame, text=desc, foreground=color, justify="left").pack(anchor="w")

        grid.columnconfigure(0, weight=1)
        grid.columnconfigure(1, weight=1)

        # ── Auditlog-Status ───────────────────────────────────────────
        log_frame = ttk.LabelFrame(parent, text="  Auditlog  ", padding=8)
        log_frame.pack(fill="x", pady=(10, 0))

        log_path = audit_log.get_log_path()
        ok, count, err = audit_log.verify_chain()

        status_icon  = "✅" if ok else "❌"
        status_color = "#005500" if ok else "#cc0000"
        status_text  = (
            f"{status_icon}  {count} Einträge – Hash-Chain intakt"
            if ok
            else f"{status_icon}  Fehler: {err}"
        )

        ttk.Label(log_frame, text=status_text, foreground=status_color).pack(anchor="w")
        ttk.Label(
            log_frame,
            text=f"Pfad: {log_path}",
            foreground="#555555",
            font=("Courier", 8),
        ).pack(anchor="w")

        # ── Datenfluss ────────────────────────────────────────────────
        flow = ttk.LabelFrame(parent, text=f"  {i18n.t('sec_flow_title')}  ", padding=8)
        flow.pack(fill="x", pady=(6, 0))
        ttk.Label(
            flow,
            text=i18n.t("sec_flow_text"),
            foreground="#005599",
            font=("Courier", 9),
            justify="left",
        ).pack(anchor="w")

        # ── Fußzeile ──────────────────────────────────────────────────
        ttk.Label(
            parent,
            text=i18n.t("sec_audit_lbl"),
            foreground="#666666",
            font=("", 9),
        ).pack(anchor="w", pady=(8, 0))

    def update_language(self) -> None:
        self._build()
