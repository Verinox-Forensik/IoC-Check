"""
Wiederverwendbare modale Dialoge:
  - PasswordDialog     (Feature 9: Export-Verschlüsselung)
  - CertWarningDialog  (Feature 1: TLS-Zertifikat-Warnung)
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

import i18n


class PasswordDialog(tk.Toplevel):
    """
    Fragt nach einem optionalen Exportpasswort.
    Ergebnis: self.password  (None = Abbruch, "" = kein Passwort, sonst Passwort)
    """

    def __init__(self, parent):
        super().__init__(parent)
        self.title(i18n.t("export_pwd_title"))
        self.resizable(False, False)
        self.password: Optional[str] = None   # None = abgebrochen

        self._build()
        self.grab_set()
        self.transient(parent)
        self.wait_window()

    def _build(self) -> None:
        pad = {"padx": 16, "pady": 6}

        ttk.Label(self, text=i18n.t("export_pwd_lbl"), anchor="w").pack(fill="x", **pad)

        self._pw1 = tk.StringVar()
        e1 = ttk.Entry(self, textvariable=self._pw1, show="•", width=36)
        e1.pack(fill="x", padx=16, pady=(0, 4))
        e1.focus_set()

        ttk.Label(self, text=i18n.t("export_pwd_confirm"), anchor="w").pack(fill="x", **pad)

        self._pw2 = tk.StringVar()
        ttk.Entry(self, textvariable=self._pw2, show="•", width=36).pack(
            fill="x", padx=16, pady=(0, 4)
        )

        self._err_lbl = ttk.Label(self, text="", foreground="#cc0000")
        self._err_lbl.pack(padx=16, pady=(0, 4))

        ttk.Label(
            self,
            text="(leer lassen = keine Verschlüsselung)" if i18n.get_lang() == "de"
                 else "(leave blank = no encryption)",
            foreground="#666666",
            font=("", 9),
        ).pack(padx=16, pady=(0, 8))

        btn_frame = ttk.Frame(self)
        btn_frame.pack(padx=16, pady=(0, 12), fill="x")
        ttk.Button(btn_frame, text=i18n.t("export_ok"),
                   command=self._ok, style="Accent.TButton").pack(side="right", padx=(8, 0))
        ttk.Button(btn_frame, text=i18n.t("export_cancel"),
                   command=self._cancel).pack(side="right")

        self.bind("<Return>", lambda _: self._ok())
        self.bind("<Escape>", lambda _: self._cancel())

    def _ok(self) -> None:
        p1 = self._pw1.get()
        p2 = self._pw2.get()
        if p1 != p2:
            self._err_lbl.config(text=i18n.t("export_pwd_mismatch"))
            return
        self.password = p1   # "" = unverschlüsselt
        self.destroy()

    def _cancel(self) -> None:
        self.password = None
        self.destroy()


class CertWarningDialog(tk.Toplevel):
    """
    Zeigt eine Warnung bei geändertem TLS-Zertifikat (Feature 1).
    Ergebnis: self.accepted  (True = neues Zert akzeptiert, False = Abbruch)
    """

    def __init__(self, parent, old_hash: str, new_hash: str):
        super().__init__(parent)
        self.title(i18n.t("cert_warn_title"))
        self.resizable(False, False)
        self.accepted: bool = False

        self._build(old_hash, new_hash)
        self.grab_set()
        self.transient(parent)
        self.wait_window()

    def _build(self, old: str, new: str) -> None:
        # Warnfarbe oben
        header = tk.Frame(self, background="#fff3cc", relief="flat")
        header.pack(fill="x")
        tk.Label(
            header,
            text=i18n.t("cert_warn_title"),
            background="#fff3cc",
            foreground="#8a5c00",
            font=("", 12, "bold"),
            pady=10,
        ).pack()

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)

        msg = i18n.t("cert_warn_msg").format(old=old[:16] + "…", new=new[:16] + "…")
        ttk.Label(body, text=msg, justify="left", wraplength=480).pack(anchor="w")

        # Vollständige Hashes in lesbarer Form
        detail_frame = ttk.LabelFrame(body, text="  Fingerprint (SHA-256)  ", padding=8)
        detail_frame.pack(fill="x", pady=(12, 0))

        for label, val in [("Gespeichert:", old), ("Aktuell:", new)]:
            row = ttk.Frame(detail_frame)
            row.pack(fill="x", pady=2)
            ttk.Label(row, text=label, width=14, anchor="w").pack(side="left")
            ttk.Label(row, text=val, font=("Courier", 8),
                      foreground="#005599").pack(side="left")

        btn = ttk.Frame(self, padding=(16, 0, 16, 12))
        btn.pack(fill="x")
        ttk.Button(btn, text=i18n.t("cert_reject"),
                   command=self._reject).pack(side="right", padx=(8, 0))
        ttk.Button(btn, text=i18n.t("cert_accept"),
                   command=self._accept, style="Accent.TButton").pack(side="right")

        self.bind("<Escape>", lambda _: self._reject())

    def _accept(self) -> None:
        self.accepted = True
        self.destroy()

    def _reject(self) -> None:
        self.accepted = False
        self.destroy()
