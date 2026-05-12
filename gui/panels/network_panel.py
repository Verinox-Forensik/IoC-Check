"""
Netzwerk-Transparenz-Panel.
Zeigt jeden ausgehenden HTTP-Request live – API-Key niemals sichtbar.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import i18n


_LEVEL_COLORS = {
    "REQUEST":  "#6bcbff",
    "RESPONSE": "#69ff94",
    "BLOCKED":  "#ff6b6b",
    "INFO":     "#e0e0e0",
}


class NetworkPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self._build()

    def _build(self) -> None:
        # ── Kopfzeile ─────────────────────────────────────────────────
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 6))

        self._info_lbl = ttk.Label(
            header,
            text=i18n.t("net_info"),
            foreground="#007700",
            font=("", 10, "bold"),
        )
        self._info_lbl.pack(side="left")

        self._clear_btn = ttk.Button(header, text=i18n.t("net_clear"), command=self.clear)
        self._clear_btn.pack(side="right")

        # ── Allowlist-Box ─────────────────────────────────────────────
        self._allow_frame = ttk.LabelFrame(
            self, text=f"  {i18n.t('net_allowlist')}  ", padding=6
        )
        self._allow_frame.pack(fill="x", pady=(0, 8))

        self._host_lbl = ttk.Label(
            self._allow_frame,
            text=i18n.t("net_host"),
            foreground="#005599",
            font=("Courier", 10),
        )
        self._host_lbl.pack(anchor="w")

        # ── Log-Textfeld ──────────────────────────────────────────────
        txt_frame = ttk.Frame(self)
        txt_frame.pack(fill="both", expand=True)

        self._txt = tk.Text(
            txt_frame,
            state="disabled",
            wrap="none",
            font=("Courier", 10),
            background="#0d1117",
            foreground="#e0e0e0",
            relief="flat",
            borderwidth=0,
        )
        vsb = ttk.Scrollbar(txt_frame, command=self._txt.yview)
        hsb = ttk.Scrollbar(txt_frame, orient="horizontal", command=self._txt.xview)
        self._txt.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._txt.pack(side="left", fill="both", expand=True)

        for level, color in _LEVEL_COLORS.items():
            self._txt.tag_configure(level, foreground=color)

    # ── Öffentliche Methoden ───────────────────────────────────────────────

    def add_log(self, timestamp: str, level: str, message: str) -> None:
        tag = level if level in _LEVEL_COLORS else "INFO"
        self._txt.config(state="normal")
        self._txt.insert("end", f"[{timestamp}]  [{level:<8}]  {message}\n", tag)
        self._txt.see("end")
        self._txt.config(state="disabled")

    def clear(self) -> None:
        self._txt.config(state="normal")
        self._txt.delete("1.0", "end")
        self._txt.config(state="disabled")

    def update_language(self) -> None:
        self._info_lbl.config(text=i18n.t("net_info"))
        self._clear_btn.config(text=i18n.t("net_clear"))
        self._allow_frame.config(text=f"  {i18n.t('net_allowlist')}  ")
        self._host_lbl.config(text=i18n.t("net_host"))
