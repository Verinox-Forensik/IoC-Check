"""
Internationalisierung: Deutsch / English
Verwendung:  from i18n import t, set_lang, get_lang
"""
from __future__ import annotations

_lang: str = "de"

_T: dict[str, dict[str, str]] = {
    # ------------------------------------------------------------------ #
    "de": {
        # Fenster / App
        "app_title":            "Verinox Forensik – Forensik Tool",
        "lang_btn":             "🌐 English",

        # Tabs
        "tab_progress":         "  Fortschritt  ",
        "tab_results":          "  Ergebnisse   ",
        "tab_network":          "  Netzwerk-Log ",
        "tab_security":         "  🔒 Sicherheit ",

        # Settings-Panel
        "cfg_title":            "Konfiguration",
        "api_key_lbl":          "VirusTotal API-Key:",
        "show_key":             "👁 Anzeigen",
        "hide_key":             "🙈 Verbergen",
        "file_lbl":             "Eingabedatei:",
        "browse":               "📂 Durchsuchen",
        "scan_ips":             "IP-Adressen scannen",
        "scan_domains":         "Domains / URLs scannen",
        "rate_lbl":             "Rate-Limit:",
        "rate_unit":            "Anfragen / Minute",
        "btn_start":            "▶  Scan starten",
        "btn_stop":             "■  Stopp",
        "key_loaded":           "✓ Geladen",
        "key_saved":            "✓ Gespeichert",
        "session_only":         "Key nicht speichern (nur diese Sitzung)",
        "timeout_lbl":          "Inaktivitäts-Timeout:",
        "timeout_unit":         "Minuten  (0 = deaktiviert)",

        # Progress-Panel
        "ready":                "Bereit.",
        "preparing":            "Scan wird vorbereitet …",
        "done_lbl":             "Abgeschlossen",
        "eta":                  "verbleibend",

        # Extraction-Info-Box
        "ext_title":            "Extraktion abgeschlossen",
        "ext_ips":              "IP-Adressen gefunden:",
        "ext_domains":          "Domains / URLs gefunden:",
        "ext_total":            "Gesamt zu scannen:",
        "ext_entries":          "Einträge",
        "ext_none":             "Keine verwertbaren Einträge gefunden.",

        # Ergebnis-Panel
        "filter_lbl":           "Filter:",
        "all":                  "Alle",
        "search_lbl":           "Suche:",
        "col_target":           "Ziel",
        "col_type":             "Typ",
        "col_verdict":          "Verdict",
        "col_mal":              "Mal.",
        "col_susp":             "Susp.",
        "col_harm":             "Harm.",
        "col_engines":          "Engines",
        "col_last":             "Letzte Analyse",
        "close":                "Schließen",

        # Netzwerk-Panel
        "net_info":             "Alle Netzwerkanfragen dieser Sitzung – API-Key wird niemals angezeigt",
        "net_clear":            "Löschen",
        "net_allowlist":        "Erlaubte Ziel-Hosts (Allowlist)",
        "net_host":             "🔒  www.virustotal.com   (einzige erlaubte Domain — alle anderen werden blockiert)",

        # Sicherheits-Panel
        "sec_main_title":       "🔒  Sicherheitsmodell – Transparenz für den Nutzer",
        "sec_flow_title":       "Datenfluss",
        "sec_flow_text":        (
            "  Ihre Datei  →  Extraktion (lokal, kein Netzwerk)  →  "
            "VirusTotal API (TLS/HTTPS)  →  Ergebnisse (lokal)\n\n"
            "  Kein Drittanbieter sieht Ihre Daten. "
            "Der API-Key geht nur an virustotal.com."
        ),
        "sec_audit_lbl":        "Der Quellcode dieser Anwendung ist vollständig einsehbar und auditierbar.",

        # Meldungen / Dialoge
        "err_no_key":           "Bitte einen VirusTotal API-Key eingeben.",
        "err_no_file":          "Bitte eine Eingabedatei auswählen.",
        "err_no_type":          "Bitte mindestens IPs oder Domains aktivieren.",
        "no_results":           "Keine Ergebnisse vorhanden.",
        "csv_saved":            "CSV gespeichert:\n",
        "pdf_saved":            "PDF gespeichert:\n",
        "dlg_export":           "Export",
        "dlg_error":            "Fehler",

        # Log-Nachrichten (vom Scanner)
        "log_reading":          "Datei wird eingelesen …",
        "log_no_targets":       "Keine IPs oder Domains in der Datei gefunden.",
        "log_aborted":          "Scan wurde abgebrochen.",
        "log_rate_limit":       "Rate-Limit erreicht – warte 60 s …",
        "log_invalid_key":      "Ungültiger API-Key – Scan abgebrochen.",
        "log_read_err":         "Fehler beim Einlesen: ",
        "log_unexpected":       "Unerwarteter Fehler: ",

        # ── NEU: Feature 1 – TLS-Zertifikat-Pinning ──────────────────
        "cert_first_title":     "Zertifikat gespeichert (TOFU)",
        "cert_first_msg":       (
            "Erster Verbindungsaufbau mit VirusTotal.\n"
            "Zertifikat-Fingerprint wurde lokal gespeichert (Trust On First Use):\n\n"
            "{hash}\n\n"
            "Dieser Fingerprint wird bei jedem Scan geprüft."
        ),
        "cert_ok":              "✅ Zertifikat verifiziert",
        "cert_warn_title":      "⚠️  Zertifikat-Warnung",
        "cert_warn_msg":        (
            "Das VirusTotal-Zertifikat hat sich geändert!\n\n"
            "Gespeichert: {old}\n"
            "Aktuell:        {new}\n\n"
            "Mögliche Ursachen:\n"
            "  • Reguläre Zertifikatserneuerung durch VirusTotal\n"
            "  • Man-in-the-Middle-Angriff (MITM)\n"
            "  • Unternehmens-Proxy mit TLS-Inspektion\n\n"
            "Neues Zertifikat akzeptieren?"
        ),
        "cert_accept":          "Akzeptieren & speichern",
        "cert_reject":          "Abbrechen",
        "cert_error":           "Zertifikat konnte nicht geprüft werden: ",

        # ── NEU: Feature 2 – Proxy-Warnung ────────────────────────────
        "proxy_title":          "⚠️  HTTP-Proxy erkannt",
        "proxy_msg":            (
            "Ein HTTP/HTTPS-Proxy ist konfiguriert:\n\n"
            "  {proxy}\n\n"
            "Ihr API-Key wird über diesen Proxy übermittelt.\n"
            "Stellen Sie sicher, dass Sie dem Proxy-Betreiber vertrauen.\n\n"
            "Trotzdem fortfahren?"
        ),
        "proxy_continue":       "Fortfahren",
        "proxy_abort":          "Abbrechen",

        # ── NEU: Feature 3 – Session-only-Modus (Label bereits oben) ──

        # ── NEU: Feature 4 – Clipboard-Guard ──────────────────────────
        "clipboard_cleared":    "🔒 Zwischenablage automatisch geleert.",

        # ── NEU: Feature 5 & 6 – Datei-Hash + Auditlog ────────────────
        "audit_title":          "Scan im Auditlog protokolliert",
        "audit_path":           "Pfad: ",
        "file_hash_lbl":        "SHA-256 Eingabedatei: ",

        # ── NEU: Feature 7 – Key-Rotation ─────────────────────────────
        "rotation_title":       "API-Key-Rotation empfohlen",
        "rotation_msg":         (
            "Ihr API-Key ist {days} Tage alt.\n\n"
            "Best Practice: Credentials alle 90 Tage rotieren.\n"
            "Bitte erneuern Sie Ihren Key unter:\n"
            "virustotal.com → Profil → API Key"
        ),

        # ── NEU: Feature 8 – XLSM-Warnung ─────────────────────────────
        "xlsm_title":           "⚠️  Makro-Datei erkannt",
        "xlsm_msg":             (
            "Die ausgewählte Datei enthält Makros (.xlsm).\n\n"
            "Makros werden von VT-Analyzer NICHT ausgeführt.\n"
            "Die Datei könnte jedoch manipulierten Text-Inhalt enthalten,\n"
            "der auf schädliche Domains oder IPs verweist.\n\n"
            "Mit dem Einlesen fortfahren?"
        ),

        # ── NEU: Feature 9 – Export-Verschlüsselung ───────────────────
        "export_pwd_title":     "Export-Verschlüsselung (optional)",
        "export_pwd_lbl":       "Passwort (leer lassen = keine Verschlüsselung):",
        "export_pwd_confirm":   "Passwort bestätigen:",
        "export_pwd_mismatch":  "Passwörter stimmen nicht überein.",
        "export_encrypted_ok":  "Verschlüsselter Export gespeichert:\n",
        "export_ok":            "OK",
        "export_cancel":        "Abbrechen",

        # ── NEU: Feature 10 – Inaktivitäts-Timeout ────────────────────
        "timeout_fired_title":  "Sitzung gesperrt",
        "timeout_fired_msg":    (
            "Inaktivitäts-Timeout erreicht.\n"
            "Der API-Key wurde aus dem Eingabefeld entfernt.\n\n"
            "Bitte Key erneut eingeben, um fortzufahren."
        ),

        # Sprachumschalter
        "lang_btn":             "🌐 English",
    },

    # ------------------------------------------------------------------ #
    "en": {
        # Window / App
        "app_title":            "Verinox Forensik – Forensic Tool",
        "lang_btn":             "🌐 Deutsch",

        # Tabs
        "tab_progress":         "  Progress     ",
        "tab_results":          "  Results      ",
        "tab_network":          "  Network Log  ",
        "tab_security":         "  🔒 Security  ",

        # Settings panel
        "cfg_title":            "Configuration",
        "api_key_lbl":          "VirusTotal API Key:",
        "show_key":             "👁 Show",
        "hide_key":             "🙈 Hide",
        "file_lbl":             "Input File:",
        "browse":               "📂 Browse",
        "scan_ips":             "Scan IP Addresses",
        "scan_domains":         "Scan Domains / URLs",
        "rate_lbl":             "Rate Limit:",
        "rate_unit":            "Requests / Minute",
        "btn_start":            "▶  Start Scan",
        "btn_stop":             "■  Stop",
        "key_loaded":           "✓ Loaded",
        "key_saved":            "✓ Saved",
        "session_only":         "Do not save key (this session only)",
        "timeout_lbl":          "Inactivity Timeout:",
        "timeout_unit":         "minutes  (0 = disabled)",

        # Progress panel
        "ready":                "Ready.",
        "preparing":            "Preparing scan …",
        "done_lbl":             "Completed",
        "eta":                  "remaining",

        # Extraction info box
        "ext_title":            "Extraction complete",
        "ext_ips":              "IP addresses found:",
        "ext_domains":          "Domains / URLs found:",
        "ext_total":            "Total to scan:",
        "ext_entries":          "entries",
        "ext_none":             "No usable entries found in file.",

        # Results panel
        "filter_lbl":           "Filter:",
        "all":                  "All",
        "search_lbl":           "Search:",
        "col_target":           "Target",
        "col_type":             "Type",
        "col_verdict":          "Verdict",
        "col_mal":              "Mal.",
        "col_susp":             "Susp.",
        "col_harm":             "Harm.",
        "col_engines":          "Engines",
        "col_last":             "Last Analysis",
        "close":                "Close",

        # Network panel
        "net_info":             "All network requests this session – API key is never shown",
        "net_clear":            "Clear",
        "net_allowlist":        "Allowed Target Hosts (Allowlist)",
        "net_host":             "🔒  www.virustotal.com   (only allowed domain — all others are blocked)",

        # Security panel
        "sec_main_title":       "🔒  Security Model – Transparency for the User",
        "sec_flow_title":       "Data Flow",
        "sec_flow_text":        (
            "  Your file  →  Extraction (local, no network)  →  "
            "VirusTotal API (TLS/HTTPS)  →  Results (local)\n\n"
            "  No third party sees your data. "
            "The API key only goes to virustotal.com."
        ),
        "sec_audit_lbl":        "The source code of this application is fully auditable.",

        # Messages / dialogs
        "err_no_key":           "Please enter a VirusTotal API key.",
        "err_no_file":          "Please select an input file.",
        "err_no_type":          "Please enable at least IPs or Domains.",
        "no_results":           "No results available.",
        "csv_saved":            "CSV saved:\n",
        "pdf_saved":            "PDF saved:\n",
        "dlg_export":           "Export",
        "dlg_error":            "Error",

        # Log messages (from scanner)
        "log_reading":          "Reading file …",
        "log_no_targets":       "No IPs or domains found in file.",
        "log_aborted":          "Scan was aborted.",
        "log_rate_limit":       "Rate limit reached – waiting 60 s …",
        "log_invalid_key":      "Invalid API key – scan aborted.",
        "log_read_err":         "Error reading file: ",
        "log_unexpected":       "Unexpected error: ",

        # Feature 1 – TLS cert pinning
        "cert_first_title":     "Certificate saved (TOFU)",
        "cert_first_msg":       (
            "First connection to VirusTotal.\n"
            "Certificate fingerprint saved locally (Trust On First Use):\n\n"
            "{hash}\n\n"
            "This fingerprint will be verified on every scan."
        ),
        "cert_ok":              "✅ Certificate verified",
        "cert_warn_title":      "⚠️  Certificate Warning",
        "cert_warn_msg":        (
            "The VirusTotal certificate has changed!\n\n"
            "Stored:   {old}\n"
            "Current: {new}\n\n"
            "Possible causes:\n"
            "  • Routine certificate renewal by VirusTotal\n"
            "  • Man-in-the-middle attack (MITM)\n"
            "  • Corporate proxy with TLS inspection\n\n"
            "Accept and save new certificate?"
        ),
        "cert_accept":          "Accept & save",
        "cert_reject":          "Abort",
        "cert_error":           "Certificate could not be verified: ",

        # Feature 2 – Proxy warning
        "proxy_title":          "⚠️  HTTP Proxy Detected",
        "proxy_msg":            (
            "An HTTP/HTTPS proxy is configured:\n\n"
            "  {proxy}\n\n"
            "Your API key will be transmitted through this proxy.\n"
            "Make sure you trust the proxy operator.\n\n"
            "Continue anyway?"
        ),
        "proxy_continue":       "Continue",
        "proxy_abort":          "Abort",

        # Feature 4 – Clipboard guard
        "clipboard_cleared":    "🔒 Clipboard automatically cleared.",

        # Feature 5 & 6 – File hash + audit log
        "audit_title":          "Scan logged to audit log",
        "audit_path":           "Path: ",
        "file_hash_lbl":        "SHA-256 input file: ",

        # Feature 7 – Key rotation
        "rotation_title":       "API Key Rotation Recommended",
        "rotation_msg":         (
            "Your API key is {days} days old.\n\n"
            "Best practice: rotate credentials every 90 days.\n"
            "Please renew your key at:\n"
            "virustotal.com → Profile → API Key"
        ),

        # Feature 8 – XLSM warning
        "xlsm_title":           "⚠️  Macro File Detected",
        "xlsm_msg":             (
            "The selected file contains macros (.xlsm).\n\n"
            "VT-Analyzer does NOT execute macros.\n"
            "However, the file may contain manipulated text content\n"
            "referencing malicious domains or IPs.\n\n"
            "Proceed with reading the file?"
        ),

        # Feature 9 – Export encryption
        "export_pwd_title":     "Export Encryption (optional)",
        "export_pwd_lbl":       "Password (leave blank = no encryption):",
        "export_pwd_confirm":   "Confirm password:",
        "export_pwd_mismatch":  "Passwords do not match.",
        "export_encrypted_ok":  "Encrypted export saved:\n",
        "export_ok":            "OK",
        "export_cancel":        "Cancel",

        # Feature 10 – Inactivity timeout
        "timeout_fired_title":  "Session Locked",
        "timeout_fired_msg":    (
            "Inactivity timeout reached.\n"
            "The API key has been removed from the input field.\n\n"
            "Please re-enter your key to continue."
        ),
    },
}

# ── Sicherheitsgarantien (Security Panel) ──────────────────────────────────
SECURITY_GUARANTEES: dict[str, list[tuple[str, str, str, str]]] = {
    "de": [
        ("✅", "Netzwerk-Allowlist",
         "Nur www.virustotal.com darf kontaktiert werden.\n"
         "Jede andere Verbindung wird automatisch blockiert und protokolliert.",
         "#005500"),
        ("", "API-Key-Speicherung",
         "Speicherort: OS-Schlüsselbund oder lokale Datei (chmod 600).\n"
         "Der Key verlässt Ihr Gerät nur als HTTP-Header an virustotal.com.",
         ""),
        ("✅", "TLS-Zertifikat-Pinning (TOFU)",
         "Beim ersten Verbindungsaufbau wird der Zertifikat-Fingerprint gespeichert.\n"
         "Jede Änderung wird erkannt und dem Nutzer zur Bestätigung angezeigt.",
         "#005500"),
        ("✅", "Proxy-Erkennung",
         "Vor jedem Scan wird geprüft, ob ein HTTP-Proxy konfiguriert ist.\n"
         "Bei Fund: Warnung mit Proxy-URL und Bestätigungsdialog.",
         "#005500"),
        ("✅", "Key-Masking",
         "Der API-Key erscheint in keiner Log-Ausgabe, keinem Export und\n"
         "keiner Bildschirmanzeige im Klartext.",
         "#005500"),
        ("✅", "Session-Modus",
         "Optional: Key wird nur im RAM gehalten, niemals auf Disk geschrieben.\n"
         "Aktivierbar über Checkbox in der Konfiguration.",
         "#005500"),
        ("✅", "Clipboard-Guard",
         "Nach dem Einfügen des API-Keys wird die Zwischenablage automatisch\n"
         "nach 30 Sekunden geleert.",
         "#005500"),
        ("✅", "Inaktivitäts-Timeout",
         "Nach konfigurierbarer Inaktivitätsdauer wird der API-Key aus dem\n"
         "Eingabefeld entfernt (konfigurierbar in Minuten, 0 = deaktiviert).",
         "#005500"),
        ("✅", "Auditlog mit Hash-Chain",
         "Jeder Scan wird in einer unveränderlichen Hash-Chain protokolliert.\n"
         "Enthält Datum, Dateiname, SHA-256, Ergebnis – keinen API-Key.",
         "#005500"),
        ("✅", "Export-Verschlüsselung",
         "CSV: AES-256-verschlüsselte ZIP-Datei.\n"
         "PDF: Passwortgeschützte PDF (Standard-Verschlüsselung).",
         "#005500"),
        ("✅", "Kein Telemetrie / keine Drittanbieter",
         "Die App sendet keinerlei Nutzungsdaten. Kein Update-Server, keine Telemetrie.",
         "#005500"),
    ],
    "en": [
        ("✅", "Network Allowlist",
         "Only www.virustotal.com may be contacted.\n"
         "Any other connection is automatically blocked and logged.",
         "#005500"),
        ("", "API Key Storage",
         "Storage: OS keychain or local file (chmod 600).\n"
         "The key leaves your device only as an HTTP header to virustotal.com.",
         ""),
        ("✅", "TLS Certificate Pinning (TOFU)",
         "On first connection, the certificate fingerprint is stored locally.\n"
         "Any change is detected and presented to the user for confirmation.",
         "#005500"),
        ("✅", "Proxy Detection",
         "Before each scan, the app checks for a configured HTTP proxy.\n"
         "If found: warning with proxy URL and confirmation dialog.",
         "#005500"),
        ("✅", "Key Masking",
         "The API key never appears in any log output, export or\n"
         "on-screen display in plain text.",
         "#005500"),
        ("✅", "Session Mode",
         "Optional: key is held only in RAM, never written to disk.\n"
         "Enabled via checkbox in the configuration panel.",
         "#005500"),
        ("✅", "Clipboard Guard",
         "After pasting the API key, the clipboard is automatically\n"
         "cleared after 30 seconds.",
         "#005500"),
        ("✅", "Inactivity Timeout",
         "After configurable inactivity, the API key is removed from\n"
         "the input field (configurable in minutes, 0 = disabled).",
         "#005500"),
        ("✅", "Audit Log with Hash Chain",
         "Every scan is logged in a tamper-evident hash chain.\n"
         "Contains date, file name, SHA-256, results – no API key.",
         "#005500"),
        ("✅", "Export Encryption",
         "CSV: AES-256 encrypted ZIP archive.\n"
         "PDF: Password-protected PDF (standard encryption).",
         "#005500"),
        ("✅", "No Telemetry / No Third Parties",
         "The app sends no usage data. No update server, no telemetry.",
         "#005500"),
    ],
}


# ── Öffentliche API ────────────────────────────────────────────────────────

def get_lang() -> str:
    return _lang


def set_lang(lang: str) -> None:
    global _lang
    if lang in _T:
        _lang = lang


def t(key: str) -> str:
    return _T.get(_lang, _T["de"]).get(key, key)


def toggle() -> str:
    set_lang("en" if _lang == "de" else "de")
    return _lang


def guarantees() -> list[tuple[str, str, str, str]]:
    return SECURITY_GUARANTEES.get(_lang, SECURITY_GUARANTEES["de"])
