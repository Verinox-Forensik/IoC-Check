"""
Einstellungs-Panel mit:
  - API-Key (Feature 3: Session-Modus)
  - Dateiauswahl (Feature 8: XLSM-Erkennung via Callback)
  - Clipboard-Guard-Anbindung (Feature 4)
  - Inaktivitäts-Timeout-Einstellung (Feature 10)
  - Sprachschalter
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog
from typing import Callable, Optional

import i18n
from security.keystore import mask_key


class SettingsPanel(ttk.LabelFrame):
    def __init__(
        self,
        parent,
        on_scan:          Callable[[str, str, bool, bool, int], None],
        on_stop:          Callable[[], None],
        on_lang:          Callable[[], None],
        on_key_pasted:    Optional[Callable[[], None]] = None,   # Clipboard-Guard
    ):
        super().__init__(parent, text=f"  {i18n.t('cfg_title')}  ", padding=10)
        self._on_scan       = on_scan
        self._on_stop       = on_stop
        self._on_lang       = on_lang
        self._on_key_pasted = on_key_pasted
        self._key_visible   = False
        self._build()

    def _build(self) -> None:
        # ── Zeile 0: API-Key ──────────────────────────────────────────
        self._lbl_key = ttk.Label(self, text=i18n.t("api_key_lbl"))
        self._lbl_key.grid(row=0, column=0, sticky="w", padx=(0, 8))

        self._key_var = tk.StringVar()
        self._key_entry = ttk.Entry(self, textvariable=self._key_var, width=44, show="•")
        self._key_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        # Clipboard-Guard: bei jedem FocusOut arm()
        self._key_entry.bind("<FocusOut>", self._on_key_focus_out)

        self._eye_btn = ttk.Button(
            self, text=i18n.t("show_key"), width=13, command=self._toggle_key
        )
        self._eye_btn.grid(row=0, column=2, padx=(0, 4))

        self._save_lbl = ttk.Label(self, text="", foreground="#007700")
        self._save_lbl.grid(row=0, column=3, sticky="w", padx=(0, 6))

        self._lang_btn = ttk.Button(
            self, text=i18n.t("lang_btn"), width=12, command=self._on_lang
        )
        self._lang_btn.grid(row=0, column=4, sticky="e")

        # ── Zeile 1: Datei ────────────────────────────────────────────
        self._lbl_file = ttk.Label(self, text=i18n.t("file_lbl"))
        self._lbl_file.grid(row=1, column=0, sticky="w", pady=(8, 0))

        self._file_var = tk.StringVar()
        ttk.Entry(self, textvariable=self._file_var, width=44).grid(
            row=1, column=1, sticky="ew", pady=(8, 0), padx=(0, 4)
        )

        self._browse_btn = ttk.Button(self, text=i18n.t("browse"), command=self._browse)
        self._browse_btn.grid(row=1, column=2, pady=(8, 0), padx=(0, 4))

        # ── Zeile 2: Optionen ─────────────────────────────────────────
        opt = ttk.Frame(self)
        opt.grid(row=2, column=0, columnspan=5, sticky="w", pady=(10, 0))

        self._scan_ips     = tk.BooleanVar(value=True)
        self._scan_domains = tk.BooleanVar(value=True)

        self._cb_ips = ttk.Checkbutton(opt, text=i18n.t("scan_ips"), variable=self._scan_ips)
        self._cb_ips.pack(side="left", padx=(0, 14))

        self._cb_domains = ttk.Checkbutton(
            opt, text=i18n.t("scan_domains"), variable=self._scan_domains
        )
        self._cb_domains.pack(side="left", padx=(0, 28))

        self._lbl_rate = ttk.Label(opt, text=i18n.t("rate_lbl"))
        self._lbl_rate.pack(side="left")

        self._rate_var = tk.IntVar(value=4)
        ttk.Spinbox(opt, from_=1, to=500, textvariable=self._rate_var, width=5).pack(
            side="left", padx=(4, 4)
        )

        self._lbl_rate_unit = ttk.Label(opt, text=i18n.t("rate_unit"))
        self._lbl_rate_unit.pack(side="left")

        # ── Zeile 3: Session-Modus + Inaktivitäts-Timeout ────────────
        sec_opt = ttk.Frame(self)
        sec_opt.grid(row=3, column=0, columnspan=5, sticky="w", pady=(6, 0))

        self._session_only = tk.BooleanVar(value=False)
        self._cb_session = ttk.Checkbutton(
            sec_opt, text=i18n.t("session_only"), variable=self._session_only
        )
        self._cb_session.pack(side="left", padx=(0, 28))

        self._lbl_timeout = ttk.Label(sec_opt, text=i18n.t("timeout_lbl"))
        self._lbl_timeout.pack(side="left")

        self._timeout_var = tk.IntVar(value=15)
        ttk.Spinbox(sec_opt, from_=0, to=120, textvariable=self._timeout_var, width=4).pack(
            side="left", padx=(4, 4)
        )

        self._lbl_timeout_unit = ttk.Label(sec_opt, text=i18n.t("timeout_unit"))
        self._lbl_timeout_unit.pack(side="left")

        # ── Zeile 4: Scan-/Stopp-Buttons ─────────────────────────────
        btn = ttk.Frame(self)
        btn.grid(row=4, column=0, columnspan=5, sticky="w", pady=(12, 0))

        self._scan_btn = ttk.Button(
            btn, text=i18n.t("btn_start"), command=self._start, style="Accent.TButton"
        )
        self._scan_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = ttk.Button(
            btn, text=i18n.t("btn_stop"), command=self._on_stop, state="disabled"
        )
        self._stop_btn.pack(side="left")

        self.columnconfigure(1, weight=1)

    # ── Öffentliche Methoden ───────────────────────────────────────────────

    def set_api_key(self, key: str) -> None:
        self._key_var.set(key)
        self._save_lbl.config(text=f"{i18n.t('key_loaded')} ({mask_key(key)})")

    def clear_key(self) -> None:
        self._key_var.set("")
        self._save_lbl.config(text="")

    def get_api_key(self) -> str:
        return self._key_var.get().strip()

    def is_session_only(self) -> bool:
        return self._session_only.get()

    def get_timeout_minutes(self) -> int:
        return max(0, self._timeout_var.get())

    def set_scanning(self, scanning: bool) -> None:
        self._scan_btn.config(state="disabled" if scanning else "normal")
        self._stop_btn.config(state="normal"   if scanning else "disabled")

    def update_language(self) -> None:
        self.config(text=f"  {i18n.t('cfg_title')}  ")
        self._lbl_key.config(text=i18n.t("api_key_lbl"))
        self._lbl_file.config(text=i18n.t("file_lbl"))
        self._browse_btn.config(text=i18n.t("browse"))
        self._cb_ips.config(text=i18n.t("scan_ips"))
        self._cb_domains.config(text=i18n.t("scan_domains"))
        self._lbl_rate.config(text=i18n.t("rate_lbl"))
        self._lbl_rate_unit.config(text=i18n.t("rate_unit"))
        self._cb_session.config(text=i18n.t("session_only"))
        self._lbl_timeout.config(text=i18n.t("timeout_lbl"))
        self._lbl_timeout_unit.config(text=i18n.t("timeout_unit"))
        self._scan_btn.config(text=i18n.t("btn_start"))
        self._stop_btn.config(text=i18n.t("btn_stop"))
        self._lang_btn.config(text=i18n.t("lang_btn"))
        self._eye_btn.config(
            text=i18n.t("hide_key") if self._key_visible else i18n.t("show_key")
        )
        key = self._key_var.get()
        if key:
            self._save_lbl.config(text=f"{i18n.t('key_loaded')} ({mask_key(key)})")

    # ── Interne Callbacks ──────────────────────────────────────────────────

    def _toggle_key(self) -> None:
        self._key_visible = not self._key_visible
        self._key_entry.config(show="" if self._key_visible else "•")
        self._eye_btn.config(
            text=i18n.t("hide_key") if self._key_visible else i18n.t("show_key")
        )

    def _on_key_focus_out(self, _event=None) -> None:
        if self._on_key_pasted and self._key_var.get():
            self._on_key_pasted()

    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title=i18n.t("browse"),
            filetypes=[
                (
                    "Alle unterstützten" if i18n.get_lang() == "de" else "All supported",
                    "*.txt *.csv *.xlsx *.xlsm *.json *.ndjson *.log *.xml *.html *.tsv",
                ),
                ("Alle Dateien" if i18n.get_lang() == "de" else "All files", "*.*"),
            ],
        )
        if path:
            self._file_var.set(path)

    def _start(self) -> None:
        key  = self._key_var.get().strip()
        path = self._file_var.get().strip()
        self._on_scan(
            key, path,
            self._scan_ips.get(), self._scan_domains.get(),
            self._rate_var.get(),
        )
        if key:
            suffix = "key_saved" if not self._session_only.get() else "key_loaded"
            self._save_lbl.config(text=f"{i18n.t(suffix)} ({mask_key(key)})")
