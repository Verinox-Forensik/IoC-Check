"""
VirusTotal API v3 – Client für Domains und IP-Adressen.
Basiert auf dem originalen vt_domaincheck.py, erweitert auf IPs.
"""
from __future__ import annotations

import time
from datetime import datetime
from queue import Queue
from typing import Optional

from security.secure_session import SecureSession, SecurityViolation

_BASE = "https://www.virustotal.com/api/v3"

# Felder, die in jedem Ergebnis-Dict vorhanden sind (für CSV-Konsistenz)
RESULT_FIELDS = [
    "target", "type", "verdict", "abgefragt_am", "letzte_analyse",
    "malicious", "suspicious", "harmless", "undetected", "engines_gesamt",
    "registrar", "registriert_am", "läuft_ab", "nameserver",
    "ip_v4", "ip_v6", "mx_record", "ssl_aussteller", "ssl_gültig_von",
    "ssl_gültig_bis", "asn", "land", "error",
]


class VTClient:
    def __init__(self, api_key: str, log_queue: Optional[Queue] = None):
        self._session = SecureSession(api_key, log_queue)
        self._session.headers.update({
            "accept":   "application/json",
            "x-apikey": api_key,
        })

    def check_domain(self, domain: str) -> dict:
        data, err = self._get(f"domains/{domain}")
        if err:
            return _error_row(domain, "domain", err)
        return _parse_domain(domain, data)

    def check_ip(self, ip: str) -> dict:
        data, err = self._get(f"ip_addresses/{ip}")
        if err:
            return _error_row(ip, "ip", err)
        return _parse_ip(ip, data)

    # ------------------------------------------------------------------

    def _get(self, endpoint: str) -> tuple[Optional[dict], Optional[str]]:
        url = f"{_BASE}/{endpoint}"
        try:
            r = self._session.get(url, timeout=30)
        except SecurityViolation:
            raise
        except Exception as exc:
            return None, str(exc)

        if r.status_code == 200:
            return r.json(), None
        if r.status_code == 401:
            return None, "INVALID_KEY"
        if r.status_code == 404:
            return None, "NOT_FOUND"
        if r.status_code == 429:
            return None, "RATE_LIMIT"
        return None, f"HTTP_{r.status_code}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _verdict(stats: dict) -> str:
    if stats.get("malicious",  0) > 0: return "MALICIOUS"
    if stats.get("suspicious", 0) > 0: return "SUSPICIOUS"
    return "CLEAN"


def _ts(epoch) -> str:
    if not epoch:
        return "N/A"
    return datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%d %H:%M UTC")


def _parse_domain(domain: str, data: dict) -> dict:
    attrs  = data.get("data", {}).get("attributes", {})
    stats  = attrs.get("last_analysis_stats", {})

    mal  = stats.get("malicious",  0)
    sus  = stats.get("suspicious", 0)
    har  = stats.get("harmless",   0)
    und  = stats.get("undetected", 0)

    rdap      = attrs.get("rdap", {})
    events    = {e["event_action"]: e["event_date"] for e in rdap.get("events", [])}
    ns        = ", ".join(n.get("ldh_name", "") for n in rdap.get("nameservers", []))

    registrar = "N/A"
    for ent in rdap.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for v in ent.get("vcard_array", []):
                if isinstance(v, dict) and v.get("name") == "fn":
                    registrar = v.get("values", ["N/A"])[0]

    dns   = attrs.get("last_dns_records", [])
    ip_a  = ", ".join(r["value"] for r in dns if r.get("type") == "A")
    ip_aa = ", ".join(r["value"] for r in dns if r.get("type") == "AAAA")
    mx    = ", ".join(r["value"] for r in dns if r.get("type") == "MX")

    cert   = attrs.get("last_https_certificate", {})
    c_val  = cert.get("validity", {})

    return {
        "target":         domain,
        "type":           "domain",
        "verdict":        _verdict(stats),
        "abgefragt_am":   datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "letzte_analyse": _ts(attrs.get("last_analysis_date")),
        "malicious":      mal,
        "suspicious":     sus,
        "harmless":       har,
        "undetected":     und,
        "engines_gesamt": mal + sus + har + und,
        "registrar":      registrar,
        "registriert_am": events.get("registration", "N/A"),
        "läuft_ab":       events.get("expiration",   "N/A"),
        "nameserver":     ns,
        "ip_v4":          ip_a,
        "ip_v6":          ip_aa,
        "mx_record":      mx,
        "ssl_aussteller": cert.get("issuer", {}).get("O", "N/A"),
        "ssl_gültig_von": c_val.get("not_before", "N/A"),
        "ssl_gültig_bis": c_val.get("not_after",  "N/A"),
        "asn":            "N/A",
        "land":           "N/A",
        "error":          "",
    }


def _parse_ip(ip: str, data: dict) -> dict:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    mal = stats.get("malicious",  0)
    sus = stats.get("suspicious", 0)
    har = stats.get("harmless",   0)
    und = stats.get("undetected", 0)

    return {
        "target":         ip,
        "type":           "ip",
        "verdict":        _verdict(stats),
        "abgefragt_am":   datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        "letzte_analyse": _ts(attrs.get("last_analysis_date")),
        "malicious":      mal,
        "suspicious":     sus,
        "harmless":       har,
        "undetected":     und,
        "engines_gesamt": mal + sus + har + und,
        "registrar":      "N/A",
        "registriert_am": "N/A",
        "läuft_ab":       "N/A",
        "nameserver":     "N/A",
        "ip_v4":          ip,
        "ip_v6":          "N/A",
        "mx_record":      "N/A",
        "ssl_aussteller": "N/A",
        "ssl_gültig_von": "N/A",
        "ssl_gültig_bis": "N/A",
        "asn":            str(attrs.get("asn",     "N/A")),
        "land":           str(attrs.get("country", "N/A")),
        "error":          "",
    }


def _error_row(target: str, kind: str, err: str) -> dict:
    row = {f: "N/A" for f in RESULT_FIELDS}
    row.update(target=target, type=kind, verdict="ERROR", error=err,
               malicious=0, suspicious=0, harmless=0, undetected=0,
               engines_gesamt=0)
    return row
