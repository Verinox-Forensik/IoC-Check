"""
Feature 4 – Clipboard-Guard.

Leert die Zwischenablage automatisch nach einer konfigurierbaren
Verzögerung, nachdem ein sensibler Wert (API-Key) eingefügt wurde.
"""
from __future__ import annotations

import tkinter as tk
from typing import Optional


class ClipboardGuard:
    """
    Instanz gehört dem Hauptfenster und leert die Clipboard
    nach `delay_ms` Millisekunden.

    Verwendung:
        guard = ClipboardGuard(root, delay_ms=30_000)
        guard.arm()          # nach Paste-Aktion aufrufen
        guard.cancel()       # wenn Key-Feld geleert wird
    """

    def __init__(self, root: tk.Tk, delay_ms: int = 30_000):
        self._root     = root
        self._delay_ms = delay_ms
        self._job: Optional[str] = None
        self._on_cleared: Optional[callable] = None

    def set_on_cleared(self, callback) -> None:
        """Callback, der nach dem Löschen aufgerufen wird (z. B. Log-Eintrag)."""
        self._on_cleared = callback

    def arm(self) -> None:
        """Startet (oder verlängert) den Countdown zum Löschen."""
        self.cancel()
        self._job = self._root.after(self._delay_ms, self._clear)

    def cancel(self) -> None:
        """Bricht den Countdown ab."""
        if self._job:
            self._root.after_cancel(self._job)
            self._job = None

    def _clear(self) -> None:
        try:
            self._root.clipboard_clear()
            self._root.clipboard_append("")
        except tk.TclError:
            pass
        self._job = None
        if self._on_cleared:
            self._on_cleared()
