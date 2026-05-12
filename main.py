"""
VT-Analyzer – Einstiegspunkt.
Führe aus: python main.py
"""
import sys
import tkinter as tk


def main() -> None:
    root = tk.Tk()

    # Damit relative Imports (core/, gui/, …) funktionieren,
    # muss das Verzeichnis dieses Skripts im Suchpfad liegen.
    import os
    sys.path.insert(0, os.path.dirname(__file__))

    from gui.app import VTAnalyzerApp
    VTAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
