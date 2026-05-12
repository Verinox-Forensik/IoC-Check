"""
Fortschritts-Panel: prominente Extraktions-Info-Box, Progressbar, ETA, scrollbares Log.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta

import i18n


class ProgressPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=10)
        self._total       = 0
        self._start_time: datetime | None = None
        self._ext_ips     = 0
        self._ext_domains = 0
        self._build()

    def _build(self) -> None:
        # ── Extraktions-Info-Box (initial ausgeblendet) ───────────────
        self._info_outer = ttk.Frame(self)
        # wird per pack_forget versteckt / per pack gezeigt

        self._info_frame = tk.Frame(
            self._info_outer,
            background="#e8f4fd",
            relief="solid",
            borderwidth=1,
        )
        self._info_frame.pack(fill="x", pady=(0, 8))

        # Titelzeile
        title_row = tk.Frame(self._info_frame, background="#e8f4fd")
        title_row.pack(fill="x", padx=12, pady=(8, 4))

        self._ext_title_lbl = tk.Label(
            title_row,
            text=f"📊  {i18n.t('ext_title')}",
            background="#e8f4fd",
            font=("", 11, "bold"),
            foreground="#1a5276",
        )
        self._ext_title_lbl.pack(side="left")

        # Drei Kennzahlen nebeneinander
        stats_row = tk.Frame(self._info_frame, background="#e8f4fd")
        stats_row.pack(fill="x", padx=12, pady=(0, 8))

        self._ext_ips_lbl     = self._stat_label(stats_row, i18n.t("ext_ips"),     "0")
        self._ext_domains_lbl = self._stat_label(stats_row, i18n.t("ext_domains"), "0")
        self._ext_total_lbl   = self._stat_label(stats_row, i18n.t("ext_total"),   "0")

        # ── Statuszeile ───────────────────────────────────────────────
        top = ttk.Frame(self)
        top.pack(fill="x", pady=(0, 6))

        self._status_lbl = ttk.Label(top, text=i18n.t("ready"), anchor="w")
        self._status_lbl.pack(side="left", fill="x", expand=True)

        self._eta_lbl = ttk.Label(top, text="", foreground="#666666")
        self._eta_lbl.pack(side="right")

        # ── Fortschrittsbalken ────────────────────────────────────────
        self._progress_var = tk.DoubleVar(value=0)
        self._bar = ttk.Progressbar(self, variable=self._progress_var, maximum=100)
        self._bar.pack(fill="x", pady=(0, 8))

        # ── Log-Textfeld ──────────────────────────────────────────────
        log_frame = ttk.Frame(self)
        log_frame.pack(fill="both", expand=True)

        self._log = tk.Text(
            log_frame,
            state="disabled",
            wrap="word",
            font=("Courier", 10),
            background="#1a1a2e",
            foreground="#e0e0e0",
            insertbackground="white",
            relief="flat",
            borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(log_frame, command=self._log.yview)
        self._log.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._log.pack(side="left", fill="both", expand=True)

        self._log.tag_configure("error",   foreground="#ff6b6b")
        self._log.tag_configure("success", foreground="#69ff94")
        self._log.tag_configure("warn",    foreground="#ffd93d")
        self._log.tag_configure("info",    foreground="#6bcbff")

    @staticmethod
    def _stat_label(parent, label_text: str, value: str) -> tuple:
        """Erstellt ein Kennzahl-Widget (Label + Wert) und gibt (lbl, val_lbl) zurück."""
        frame = tk.Frame(parent, background="#e8f4fd")
        frame.pack(side="left", padx=(0, 32))

        lbl = tk.Label(frame, text=label_text, background="#e8f4fd",
                       foreground="#555555", font=("", 9))
        lbl.pack(anchor="w")

        val = tk.Label(frame, text=value, background="#e8f4fd",
                       foreground="#1a5276", font=("", 16, "bold"))
        val.pack(anchor="w")
        return lbl, val

    # ── Öffentliche Methoden ───────────────────────────────────────────────

    def reset(self) -> None:
        self._total      = 0
        self._start_time = datetime.now()
        self._progress_var.set(0)
        self._status_lbl.config(text=i18n.t("preparing"))
        self._eta_lbl.config(text="")
        self._info_outer.pack_forget()
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")

    def show_extraction_info(self, ips: int, domains: int) -> None:
        """Zeigt die prominente Info-Box mit Extraktionsergebnissen."""
        self._ext_ips     = ips
        self._ext_domains = domains

        total = ips + domains
        self._ext_ips_lbl[1].config(text=str(ips))
        self._ext_domains_lbl[1].config(text=str(domains))
        self._ext_total_lbl[1].config(
            text=f"{total} {i18n.t('ext_entries')}",
            foreground="#006600" if total > 0 else "#cc0000",
        )
        # Box vor der Statuszeile einblenden (ganz oben im Panel)
        self._info_outer.pack(fill="x", before=self.winfo_children()[1])

    def set_total(self, total: int) -> None:
        self._total      = total
        self._start_time = datetime.now()

    def set_done(self) -> None:
        self._progress_var.set(100)
        self._eta_lbl.config(text=i18n.t("done_lbl"))

    def update_progress(self, current: int, total: int, target: str) -> None:
        pct = (current / total * 100) if total else 0
        self._progress_var.set(pct)
        self._status_lbl.config(text=f"[{current}/{total}]  {target}")

        if self._start_time and current > 1:
            elapsed   = (datetime.now() - self._start_time).total_seconds()
            per_item  = elapsed / (current - 1)
            remaining = per_item * (total - current + 1)
            eta_str   = str(timedelta(seconds=int(remaining)))
            self._eta_lbl.config(text=f"⏱ ~{eta_str} {i18n.t('eta')}")

    def log(self, message: str, error: bool = False) -> None:
        tag = "error" if error else None
        if not error:
            m = message.lower()
            if "malicious" in m or "🚨" in m:   tag = "error"
            elif "suspicious" in m or "⚠" in m: tag = "warn"
            elif "✅" in m or "clean" in m:       tag = "success"
            elif "⏸" in m:                       tag = "info"

        self._log.config(state="normal")
        ts   = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}]  {message}\n"
        self._log.insert("end", line, tag or "")
        self._log.see("end")
        self._log.config(state="disabled")

    def update_language(self) -> None:
        self._status_lbl.config(text=i18n.t("ready"))
        self._ext_title_lbl.config(text=f"📊  {i18n.t('ext_title')}")
        # Kennzahl-Labels aktualisieren
        self._ext_ips_lbl[0].config(text=i18n.t("ext_ips"))
        self._ext_domains_lbl[0].config(text=i18n.t("ext_domains"))
        self._ext_total_lbl[0].config(text=i18n.t("ext_total"))
        # Gesamtwert neu formatieren
        total = self._ext_ips + self._ext_domains
        if total > 0:
            self._ext_total_lbl[1].config(text=f"{total} {i18n.t('ext_entries')}")
