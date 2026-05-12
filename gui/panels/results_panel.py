"""
Ergebnis-Panel: gefilterte, farbkodierte Treeview, Detailansicht, Export.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

import i18n


_COL_KEYS = [
    ("target",         220),
    ("type",            55),
    ("verdict",         95),
    ("malicious",       50),
    ("suspicious",      50),
    ("harmless",        50),
    ("engines_gesamt",  60),
    ("letzte_analyse", 145),
]

_VERDICT_COLORS = {
    "MALICIOUS":  ("#ffcccc", "#cc0000"),
    "SUSPICIOUS": ("#fff3cc", "#8a5c00"),
    "CLEAN":      ("#ccf0cc", "#005500"),
    "ERROR":      ("#eeeeee", "#555555"),
}

_COL_I18N = [
    "col_target", "col_type", "col_verdict",
    "col_mal", "col_susp", "col_harm",
    "col_engines", "col_last",
]


class ResultsPanel(ttk.Frame):
    def __init__(
        self,
        parent,
        on_export_csv: Callable,
        on_export_pdf: Callable,
    ):
        super().__init__(parent, padding=10)
        self._on_export_csv = on_export_csv
        self._on_export_pdf = on_export_pdf
        self._all_rows: list[dict] = []
        self._sort_col: str  = ""
        self._sort_rev: bool = False
        self._build()

    def _build(self) -> None:
        # ── Toolbar ───────────────────────────────────────────────────
        tb = ttk.Frame(self)
        tb.pack(fill="x", pady=(0, 6))

        self._lbl_filter = ttk.Label(tb, text=i18n.t("filter_lbl"))
        self._lbl_filter.pack(side="left")

        self._filter_var = tk.StringVar(value=i18n.t("all"))
        self._filter_combo = ttk.Combobox(
            tb, textvariable=self._filter_var, width=14,
            values=self._filter_values(), state="readonly",
        )
        self._filter_combo.pack(side="left", padx=(4, 16))
        self._filter_combo.bind("<<ComboboxSelected>>", lambda _: self._apply_filter())

        self._lbl_search = ttk.Label(tb, text=i18n.t("search_lbl"))
        self._lbl_search.pack(side="left")

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        ttk.Entry(tb, textvariable=self._search_var, width=24).pack(side="left", padx=(4, 0))

        self._count_lbl = ttk.Label(tb, text="0", foreground="#666666")
        self._count_lbl.pack(side="left", padx=(16, 0))

        self._btn_pdf = ttk.Button(tb, text="⬇ PDF", command=self._on_export_pdf)
        self._btn_pdf.pack(side="right", padx=(4, 0))
        self._btn_csv = ttk.Button(tb, text="⬇ CSV", command=self._on_export_csv)
        self._btn_csv.pack(side="right", padx=(4, 0))

        # ── Treeview ──────────────────────────────────────────────────
        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="both", expand=True)

        cols = [k for k, _ in _COL_KEYS]
        self._tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")

        for (key, width), i18n_key in zip(_COL_KEYS, _COL_I18N):
            self._tree.heading(key, text=i18n.t(i18n_key), command=lambda k=key: self._sort(k))
            self._tree.column(key, width=width, minwidth=40, anchor="w")

        for verdict, (bg, fg) in _VERDICT_COLORS.items():
            self._tree.tag_configure(verdict, background=bg, foreground=fg)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal",  command=self._tree.xview)
        self._tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self._tree.pack(side="left", fill="both", expand=True)
        self._tree.bind("<Double-1>", self._on_double_click)

    # ── Öffentliche Methoden ───────────────────────────────────────────────

    def add_result(self, result: dict) -> None:
        self._all_rows.append(result)
        self._apply_filter()

    def clear(self) -> None:
        self._all_rows.clear()
        self._tree.delete(*self._tree.get_children())
        self._count_lbl.config(text="0")

    def update_language(self) -> None:
        self._lbl_filter.config(text=i18n.t("filter_lbl"))
        self._lbl_search.config(text=i18n.t("search_lbl"))

        # Filter-Combobox: "Alle"/"All" in der ersten Position übersetzen
        current_verdict = self._filter_var.get()
        new_values      = self._filter_values()
        self._filter_combo.config(values=new_values)
        if current_verdict in ("Alle", "All"):
            self._filter_var.set(i18n.t("all"))

        # Spaltenköpfe
        for (key, _), i18n_key in zip(_COL_KEYS, _COL_I18N):
            self._tree.heading(key, text=i18n.t(i18n_key))

        # Zähler neu formatieren
        visible = len(self._tree.get_children())
        total   = len(self._all_rows)
        self._count_lbl.config(text=f"{visible} / {total}")

    # ── Interne Methoden ──────────────────────────────────────────────────

    def _filter_values(self) -> list[str]:
        return [i18n.t("all"), "MALICIOUS", "SUSPICIOUS", "CLEAN", "ERROR"]

    def _apply_filter(self) -> None:
        f_verdict = self._filter_var.get()
        search    = self._search_var.get().lower()
        all_val   = i18n.t("all")

        visible = [
            r for r in self._all_rows
            if (f_verdict in (all_val, "Alle", "All") or r.get("verdict") == f_verdict)
            and (not search or search in r.get("target", "").lower())
        ]

        self._tree.delete(*self._tree.get_children())
        for r in visible:
            verdict = r.get("verdict", "ERROR")
            values  = [r.get(k, "") for k, _ in _COL_KEYS]
            self._tree.insert("", "end", iid=r["target"], values=values, tags=(verdict,))

        self._count_lbl.config(text=f"{len(visible)} / {len(self._all_rows)}")

    def _sort(self, col: str) -> None:
        self._sort_rev = (col == self._sort_col) and not self._sort_rev
        self._sort_col = col
        self._all_rows.sort(key=lambda r: str(r.get(col, "")), reverse=self._sort_rev)
        self._apply_filter()

    def _on_double_click(self, _event) -> None:
        sel = self._tree.selection()
        if not sel:
            return
        iid = sel[0]
        row = next((r for r in self._all_rows if r["target"] == iid), None)
        if row:
            _DetailDialog(self, row)


class _DetailDialog(tk.Toplevel):
    def __init__(self, parent, row: dict):
        super().__init__(parent)
        self.title(f"Details: {row['target']}")
        self.resizable(True, True)
        self.geometry("560x480")

        txt = tk.Text(self, wrap="word", font=("Courier", 10), relief="flat", borderwidth=8)
        sb  = ttk.Scrollbar(self, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        txt.pack(fill="both", expand=True)

        txt.tag_configure("key",       foreground="#005599", font=("Courier", 10, "bold"))
        txt.tag_configure("MALICIOUS", foreground="#cc0000")
        txt.tag_configure("SUSPICIOUS",foreground="#8a5c00")
        txt.tag_configure("CLEAN",     foreground="#005500")

        for k, v in row.items():
            txt.insert("end", f"{k:<22}", "key")
            tag = v if v in _VERDICT_COLORS else ""
            txt.insert("end", f"{v}\n", tag)

        txt.config(state="disabled")
        ttk.Button(self, text=i18n.t("close"), command=self.destroy).pack(pady=8)
        self.grab_set()
