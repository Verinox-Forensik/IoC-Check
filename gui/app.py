"""
Hauptfenster – verdrahtet alle Sicherheitsfeatures:
  1. TLS-Zertifikat-Pinning (TOFU)        → _check_cert_pin()
  2. Proxy-Warnung                         → _check_proxy()
  3. Session-Modus                         → settings.is_session_only()
  4. Clipboard-Guard                       → ClipboardGuard
  5. Datei-Hash im Export                  → _file_meta
  6. Auditlog mit Hash-Chain               → audit_log.log_scan()
  7. Key-Rotations-Erinnerung              → _check_key_rotation()
  8. XLSM-Makro-Warnung                   → _check_xlsm()
  9. Export-Verschlüsselung               → PasswordDialog
 10. Inaktivitäts-Timeout                  → _reset_inactivity / _on_timeout
"""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from collections import Counter
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from typing import Optional

import i18n
from core.extractor import compute_file_hash
from core.scanner import Scanner
from export.csv_exporter import export_to_csv, export_to_encrypted_csv
from export.pdf_exporter import export_to_pdf
from gui.dialogs import CertWarningDialog, PasswordDialog
from gui.panels.network_panel import NetworkPanel
from gui.panels.progress_panel import ProgressPanel
from gui.panels.results_panel import ResultsPanel
from gui.panels.security_panel import SecurityPanel
from gui.panels.settings_panel import SettingsPanel
from security import audit_log, cert_pinning, proxy_check
from security.clipboard_guard import ClipboardGuard
from security.keystore import key_age_days, load_key, rotation_needed, save_key


class VTAnalyzerApp:
    def __init__(self, root: tk.Tk):
        self.root          = root
        self._scanner:     Optional[Scanner]          = None
        self._thread:      Optional[threading.Thread] = None
        self._queue:       queue.Queue                = queue.Queue()
        self._result_list: list[dict]                 = []
        self._start_time:  Optional[datetime]         = None
        self._file_meta:   Optional[dict]             = None  # Feature 5
        self._inact_job:   Optional[str]              = None  # Feature 10

        self._setup_window()
        self._setup_style()
        self._build_ui()
        self._setup_clipboard_guard()    # Feature 4
        self._setup_inactivity_timer()  # Feature 10
        self._load_key_and_check()       # Features 3 & 7
        self.root.after(100, self._poll)

    # ── Initialisierung ───────────────────────────────────────────────────

    def _setup_window(self) -> None:
        self.root.title(i18n.t("app_title"))
        self.root.geometry("1150x820")
        self.root.minsize(920, 660)

    def _setup_style(self) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Accent.TButton",
            background="#2563eb", foreground="white",
            font=("", 10, "bold"), padding=6,
        )
        style.map("Accent.TButton",
                  background=[("active", "#1d4ed8"), ("disabled", "#9ca3af")])

    def _build_ui(self) -> None:
        root_frame = ttk.Frame(self.root)
        root_frame.pack(fill="both", expand=True, padx=12, pady=10)

        self._settings = SettingsPanel(
            root_frame,
            on_scan=self._start_scan,
            on_stop=self._stop_scan,
            on_lang=self._toggle_language,
            on_key_pasted=self._on_key_pasted,   # Feature 4
        )
        self._settings.pack(fill="x", pady=(0, 8))
        ttk.Separator(root_frame).pack(fill="x", pady=(0, 8))

        self._nb = ttk.Notebook(root_frame)
        self._nb.pack(fill="both", expand=True)

        self._progress = ProgressPanel(self._nb)
        self._results  = ResultsPanel(
            self._nb,
            on_export_csv=self._export_csv,
            on_export_pdf=self._export_pdf,
        )
        self._network  = NetworkPanel(self._nb)
        self._security = SecurityPanel(self._nb)

        self._nb.add(self._progress, text=i18n.t("tab_progress"))
        self._nb.add(self._results,  text=i18n.t("tab_results"))
        self._nb.add(self._network,  text=i18n.t("tab_network"))
        self._nb.add(self._security, text=i18n.t("tab_security"))

    def _load_key_and_check(self) -> None:
        key = load_key()
        if key:
            self._settings.set_api_key(key)
        # Feature 7: Rotations-Erinnerung
        self.root.after(500, self._check_key_rotation)

    # ── Feature 4: Clipboard-Guard ────────────────────────────────────────

    def _setup_clipboard_guard(self) -> None:
        self._clipboard_guard = ClipboardGuard(self.root, delay_ms=30_000)
        self._clipboard_guard.set_on_cleared(
            lambda: self._progress.log(i18n.t("clipboard_cleared"))
        )

    def _on_key_pasted(self) -> None:
        self._clipboard_guard.arm()

    # ── Feature 10: Inaktivitäts-Timeout ─────────────────────────────────

    def _setup_inactivity_timer(self) -> None:
        for event in ("<Motion>", "<Button>", "<KeyPress>", "<MouseWheel>"):
            self.root.bind(event, self._reset_inactivity, add=True)
        self._reset_inactivity()

    def _reset_inactivity(self, _event=None) -> None:
        if self._inact_job:
            self.root.after_cancel(self._inact_job)
            self._inact_job = None
        minutes = self._settings.get_timeout_minutes()
        if minutes > 0:
            self._inact_job = self.root.after(
                minutes * 60_000, self._on_timeout
            )

    def _on_timeout(self) -> None:
        self._inact_job = None
        if not self._thread or not self._thread.is_alive():
            self._settings.clear_key()
        messagebox.showwarning(
            i18n.t("timeout_fired_title"),
            i18n.t("timeout_fired_msg"),
        )

    # ── Feature 1: Zertifikat-Pinning ─────────────────────────────────────

    def _check_cert_pin(self) -> bool:
        """Gibt True zurück wenn Scan fortgesetzt werden soll."""
        try:
            result = cert_pinning.verify()
        except Exception:
            return True  # Netzwerkfehler → nicht blockieren

        if result.error:
            self._progress.log(
                f"{i18n.t('cert_error')}{result.error}", error=True
            )
            return True  # Fehler beim Pinning → nicht blockieren

        if result.is_first_use:
            messagebox.showinfo(
                i18n.t("cert_first_title"),
                i18n.t("cert_first_msg").format(hash=result.current),
            )
            self._progress.log(f"🔒 {i18n.t('cert_ok')} (TOFU)")
            return True

        if result.ok:
            self._progress.log(f"🔒 {i18n.t('cert_ok')}")
            return True

        # Fingerprint geändert → Dialog
        dlg = CertWarningDialog(self.root, result.stored, result.current)
        if dlg.accepted:
            cert_pinning.accept_pin("www.virustotal.com", result.current)
            self._progress.log("⚠️  Neues Zertifikat akzeptiert und gespeichert.")
            return True
        else:
            self._progress.log("🚫  Scan abgebrochen – Zertifikat nicht akzeptiert.", error=True)
            return False

    # ── Feature 2: Proxy-Warnung ──────────────────────────────────────────

    def _check_proxy(self) -> bool:
        """Gibt True zurück wenn Scan fortgesetzt werden soll."""
        proxy = proxy_check.detect()
        if not proxy:
            return True
        answer = messagebox.askyesno(
            i18n.t("proxy_title"),
            i18n.t("proxy_msg").format(proxy=proxy),
            icon="warning",
        )
        return answer

    # ── Feature 7: Key-Rotation ───────────────────────────────────────────

    def _check_key_rotation(self) -> None:
        if rotation_needed():
            age = key_age_days() or 0
            messagebox.showwarning(
                i18n.t("rotation_title"),
                i18n.t("rotation_msg").format(days=age),
            )

    # ── Feature 8: XLSM-Warnung ───────────────────────────────────────────

    def _check_xlsm(self, file_path: str) -> bool:
        """Gibt True zurück wenn Scan fortgesetzt werden soll."""
        if file_path.lower().endswith(".xlsm"):
            return messagebox.askyesno(
                i18n.t("xlsm_title"),
                i18n.t("xlsm_msg"),
                icon="warning",
            )
        return True

    # ── Sprache ───────────────────────────────────────────────────────────

    def _toggle_language(self) -> None:
        i18n.toggle()
        self.root.title(i18n.t("app_title"))
        for idx, key in enumerate(
            ("tab_progress", "tab_results", "tab_network", "tab_security")
        ):
            self._nb.tab(idx, text=i18n.t(key))
        self._settings.update_language()
        self._progress.update_language()
        self._results.update_language()
        self._network.update_language()
        self._security.update_language()

    # ── Scan-Steuerung ────────────────────────────────────────────────────

    def _start_scan(
        self, api_key: str, file_path: str,
        scan_ips: bool, scan_domains: bool, rate_limit: int,
    ) -> None:
        if not api_key:
            messagebox.showerror(i18n.t("dlg_error"), i18n.t("err_no_key"))
            return
        if not file_path:
            messagebox.showerror(i18n.t("dlg_error"), i18n.t("err_no_file"))
            return
        if not scan_ips and not scan_domains:
            messagebox.showerror(i18n.t("dlg_error"), i18n.t("err_no_type"))
            return

        # Feature 8: XLSM-Warnung
        if not self._check_xlsm(file_path):
            return

        # Feature 2: Proxy-Warnung
        if not self._check_proxy():
            return

        # Feature 1: Zertifikat-Pinning (Netzwerkaufruf, ~1 s)
        self._nb.select(0)
        self._progress.reset()
        if not self._check_cert_pin():
            self._settings.set_scanning(False)
            return

        # Feature 3: Session-Modus – Key nur speichern wenn nicht Session-Only
        if not self._settings.is_session_only():
            save_key(api_key)

        # Feature 5: Datei-Hash berechnen
        try:
            file_hash = compute_file_hash(file_path)
        except Exception:
            file_hash = "N/A"
        self._file_meta = {
            "file_name":   os.path.basename(file_path),
            "file_sha256": file_hash,
        }
        self._progress.log(
            f"{i18n.t('file_hash_lbl')}{file_hash[:16]}…"
        )

        self._queue        = queue.Queue()
        self._result_list  = []
        self._start_time   = datetime.now()

        self._results.clear()
        self._network.clear()
        self._settings.set_scanning(True)

        self._scanner = Scanner(
            api_key      = api_key,
            file_path    = file_path,
            scan_ips     = scan_ips,
            scan_domains = scan_domains,
            rate_limit   = rate_limit,
            event_queue  = self._queue,
        )
        self._thread = threading.Thread(target=self._scanner.run, daemon=True)
        self._thread.start()

    def _stop_scan(self) -> None:
        if self._scanner:
            self._scanner.stop()

    # ── Event-Loop ────────────────────────────────────────────────────────

    def _poll(self) -> None:
        try:
            while True:
                self._handle(self._queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _handle(self, e: dict) -> None:  # noqa: C901
        t = e.get("type")

        if t == "extracted":
            ips, domains = e["ips"], e["domains"]
            self._progress.show_extraction_info(ips, domains)
            self._progress.log(
                f"{i18n.t('ext_ips')} {ips}   |   {i18n.t('ext_domains')} {domains}"
            )

        elif t == "total":
            self._progress.set_total(e["total"])

        elif t == "progress":
            self._progress.update_progress(e["current"], e["total"], e["target"])

        elif t == "waiting":
            secs = e["seconds"]
            msg  = (
                f"  ⏸  Warte {secs:.0f} s (Rate-Limit) …"
                if i18n.get_lang() == "de"
                else f"  ⏸  Waiting {secs:.0f} s (rate limit) …"
            )
            self._progress.log(msg)

        elif t == "result":
            r       = e["result"]
            verdict = r.get("verdict", "ERROR")
            icon    = {"MALICIOUS": "🚨", "SUSPICIOUS": "⚠️", "CLEAN": "✅"}.get(verdict, "❌")
            extras  = (
                f"  (malicious={r['malicious']}, suspicious={r['suspicious']})"
                if verdict in ("MALICIOUS", "SUSPICIOUS") else ""
            )
            self._progress.log(
                f"{icon} [{e['index']}/{e['total']}]  {r['target']}  →  {verdict}{extras}"
            )
            self._results.add_result(r)
            self._result_list.append(r)

        elif t == "network":
            self._network.add_log(e["timestamp"], e["level"], e["message"])

        elif t == "status":
            self._progress.log(self._resolve_msg(e))

        elif t == "error":
            self._progress.log(f"❌  {self._resolve_msg(e)}", error=True)

        elif t == "done":
            self._settings.set_scanning(False)
            count   = len(self._result_list)
            elapsed = ""
            if self._start_time:
                secs    = (datetime.now() - self._start_time).total_seconds()
                elapsed = f" in {int(secs // 60)}m {int(secs % 60)}s"
            msg = (
                f"\n✅  Scan abgeschlossen – {count} Ergebnis(se){elapsed}."
                if i18n.get_lang() == "de"
                else f"\n✅  Scan complete – {count} result(s){elapsed}."
            )
            self._progress.log(msg)
            self._progress.set_done()

            # Feature 6: Auditlog
            self._write_audit_log()

            if count:
                self._nb.select(1)

    @staticmethod
    def _resolve_msg(e: dict) -> str:
        key    = e.get("msg_key", "")
        detail = e.get("detail", "")
        if key:
            return i18n.t(key) + detail
        return e.get("message", "")

    # ── Feature 6: Auditlog ───────────────────────────────────────────────

    def _write_audit_log(self) -> None:
        if not self._file_meta or not self._result_list:
            return
        verdicts = Counter(r.get("verdict", "ERROR") for r in self._result_list)
        try:
            audit_log.log_scan(
                file_name    = self._file_meta.get("file_name", "N/A"),
                file_sha256  = self._file_meta.get("file_sha256", "N/A"),
                ips_found    = sum(1 for r in self._result_list if r.get("type") == "ip"),
                domains_found= sum(1 for r in self._result_list if r.get("type") == "domain"),
                verdicts     = dict(verdicts),
            )
            self._progress.log(
                f"📋 {i18n.t('audit_title')}  "
                f"{i18n.t('audit_path')}{audit_log.get_log_path()}"
            )
        except Exception as exc:
            self._progress.log(f"⚠️  Auditlog-Fehler: {exc}", error=True)

    # ── Feature 9: Export mit Verschlüsselung ─────────────────────────────

    def _export_csv(self) -> None:
        if not self._result_list:
            messagebox.showinfo(i18n.t("dlg_export"), i18n.t("no_results"))
            return

        dlg = PasswordDialog(self.root)
        if dlg.password is None:   # Abbruch
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv"), ("ZIP (verschlüsselt)", "*.zip")],
            initialfile=f"vt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if not path:
            return

        try:
            if dlg.password:
                out = export_to_encrypted_csv(
                    self._result_list, path, dlg.password, self._file_meta
                )
                messagebox.showinfo(
                    i18n.t("dlg_export"),
                    i18n.t("export_encrypted_ok") + out,
                )
            else:
                export_to_csv(self._result_list, path, self._file_meta)
                messagebox.showinfo(i18n.t("dlg_export"), i18n.t("csv_saved") + path)
        except Exception as exc:
            messagebox.showerror(i18n.t("dlg_error"), str(exc))

    def _export_pdf(self) -> None:
        if not self._result_list:
            messagebox.showinfo(i18n.t("dlg_export"), i18n.t("no_results"))
            return

        dlg = PasswordDialog(self.root)
        if dlg.password is None:   # Abbruch
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF", "*.pdf")],
            initialfile=f"vt_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
        )
        if not path:
            return

        try:
            export_to_pdf(
                self._result_list, path,
                file_meta=self._file_meta,
                password=dlg.password or None,
            )
            note = i18n.t("export_encrypted_ok") if dlg.password else i18n.t("pdf_saved")
            messagebox.showinfo(i18n.t("dlg_export"), note + path)
        except Exception as exc:
            messagebox.showerror(i18n.t("dlg_error"), str(exc))
