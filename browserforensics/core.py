"""Core forensic analysis engine for BROWSERFORENSICS.

Parses exported browser history and download records and applies a battery of
heuristics that flag indicators of compromise (IOCs) and data-exfiltration
signs. Pure standard library; no network access.

Input formats accepted (auto-detected):
  * JSON  : a top-level list of objects, OR an object with a "history" /
            "downloads" / "records" list.
  * CSV   : header row + rows; common Chrome/Firefox-export column names are
            normalized.

Normalized record fields:
  history  : url, title, visit_time, visit_count
  download : url, target_path / file, received_bytes / bytes, start_time,
             mime_type, danger_type
"""
from __future__ import annotations

import csv
import io
import json
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, time
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, parse_qsl

TOOL_NAME = "BROWSERFORENSICS"


def _read_version() -> str:
    """Read the tool version from the repo VERSION file, with a safe fallback."""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (
        os.path.join(here, os.pardir, "VERSION"),
        os.path.join(here, "VERSION"),
    ):
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                v = fh.read().strip()
            if v:
                return v
        except OSError:
            continue
    return "0.3.6"


TOOL_VERSION = _read_version()


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    _ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls._ORDER.get(sev, 0)


# Heuristic knowledge bases ------------------------------------------------

# Free / anonymous file-sharing & paste sites frequently used for exfiltration.
EXFIL_HOSTS = {
    "pastebin.com", "paste.ee", "ghostbin.com", "hastebin.com", "rentry.co",
    "transfer.sh", "file.io", "anonfiles.com", "gofile.io", "mega.nz",
    "mega.io", "send.cm", "wetransfer.com", "0x0.st", "controlc.com",
    "dpaste.com", "privatebin.net", "bashupload.com", "temp.sh",
    "ufile.io", "keep.sh", "oshi.at", "catbox.moe", "litterbox.catbox.moe",
}

# Known URL shorteners — common in phishing / C2 redirection.
SHORTENER_HOSTS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "rb.gy", "tiny.cc", "adf.ly",
}

# Suspicious / abused TLDs (commonly used for free malicious infrastructure).
SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work",
    "click", "link", "country", "kim", "loan", "download", "review",
    "rest", "fit", "cam",
}

# Dangerous executable / script download extensions.
DANGEROUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".jar", ".msi", ".msp",
    ".dll", ".cpl", ".lnk", ".reg", ".apk", ".dmg", ".pkg", ".sh", ".py",
}

# Archive types that frequently smuggle the above.
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".iso", ".img", ".cab", ".gz", ".tgz"}

# IP-literal host regex (raw IPv4 in URL is a phishing / C2 IOC).
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# Double-extension trick e.g. invoice.pdf.exe
DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|csv|html?)\."
    r"(?:exe|scr|js|vbs|bat|cmd|hta|ps1|jar|msi)$",
    re.IGNORECASE,
)

# Cloud / SaaS storage hosts (large uploads here are worth correlating).
CLOUD_HOSTS = {
    "drive.google.com", "docs.google.com", "dropbox.com", "box.com",
    "onedrive.live.com", "1drv.ms", "s3.amazonaws.com",
}

# Sensitive keyword signals in URLs / titles.
SENSITIVE_KEYWORDS = (
    "password", "passwd", "credential", "secret", "apikey", "api_key",
    "token", "backup", "dump", "exfil", "ssn", "payroll", "confidential",
)

LARGE_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
LARGE_UPLOAD_HINT_BYTES = 50 * 1024 * 1024


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    artifact: str  # "history" | "download"
    indicator: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---- parsing helpers ------------------------------------------------------

_HISTORY_ALIASES = {
    "url": "url",
    "title": "title",
    "visit_time": "visit_time",
    "last_visit_time": "visit_time",
    "visittime": "visit_time",
    "date": "visit_time",
    "visit_count": "visit_count",
    "visitcount": "visit_count",
}

_DOWNLOAD_ALIASES = {
    "url": "url",
    "tab_url": "url",
    "referrer": "referrer",
    "target_path": "target_path",
    "current_path": "target_path",
    "file": "target_path",
    "filename": "target_path",
    "received_bytes": "received_bytes",
    "bytes": "received_bytes",
    "total_bytes": "received_bytes",
    "size": "received_bytes",
    "start_time": "start_time",
    "time": "start_time",
    "mime_type": "mime_type",
    "mimetype": "mime_type",
    "danger_type": "danger_type",
}


def _normalize_keys(row: Dict[str, Any], aliases: Dict[str, str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in row.items():
        if k is None:
            continue
        key = aliases.get(str(k).strip().lower())
        if key:
            out[key] = v
        else:
            out.setdefault(str(k).strip().lower(), v)
    return out


def _to_int(val: Any) -> int:
    if val is None or val == "":
        return 0
    try:
        return int(float(val))
    except (ValueError, TypeError):
        return 0


def _detect_payload(data: Any, kind: str) -> List[Dict[str, Any]]:
    """Pull the relevant list out of a parsed JSON document."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for key in (kind, "records", "items", "data"):
            if isinstance(data.get(key), list):
                return [r for r in data[key] if isinstance(r, dict)]
    return []


def load_records(path: str, kind: str) -> List[Dict[str, Any]]:
    """Load + normalize records from a JSON or CSV export.

    kind: "history" or "downloads".
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    aliases = _HISTORY_ALIASES if kind == "history" else _DOWNLOAD_ALIASES
    stripped = raw.lstrip()
    rows: List[Dict[str, Any]]
    if stripped[:1] in "[{":
        try:
            rows = _detect_payload(json.loads(raw), kind)
        except json.JSONDecodeError:
            rows = list(csv.DictReader(io.StringIO(raw)))
    else:
        rows = list(csv.DictReader(io.StringIO(raw)))
    return [_normalize_keys(r, aliases) for r in rows]


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _registrable_host(host: str) -> str:
    # naive eTLD strip: keep last two labels for matching
    return host[4:] if host.startswith("www.") else host


def _tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def _parse_time(val: Any) -> Optional[datetime]:
    if val is None or val == "":
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(float(val))
        except (ValueError, OSError, OverflowError):
            return None
    s = str(val).strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", ""))
    except ValueError:
        return None


# ---- analyzers ------------------------------------------------------------


def analyze_history(records: Iterable[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    records = list(records)

    for rec in records:
        url = str(rec.get("url", "") or "")
        if not url:
            continue
        title = str(rec.get("title", "") or "")
        host = _host_of(url)
        reg = _registrable_host(host)
        tld = _tld_of(host)
        ev = {"url": url, "title": title, "visit_count": _to_int(rec.get("visit_count"))}

        if host and IPV4_RE.match(host):
            findings.append(Finding(
                "history.ip_literal_host", Severity.HIGH,
                "Browsing to a raw IP address",
                f"Visited {host} directly by IP rather than a domain name; common "
                "for phishing landing pages and C2 panels.",
                "history", host, ev))

        if reg in EXFIL_HOSTS:
            findings.append(Finding(
                "history.exfil_site_visit", Severity.HIGH,
                "Visit to anonymous paste/file-share site",
                f"{reg} is frequently used to stage or transfer exfiltrated data.",
                "history", reg, ev))

        if reg in SHORTENER_HOSTS:
            findings.append(Finding(
                "history.url_shortener", Severity.MEDIUM,
                "URL shortener used",
                f"Shortened link via {reg} hides the true destination; common in "
                "phishing redirection chains.",
                "history", reg, ev))

        if tld in SUSPICIOUS_TLDS:
            findings.append(Finding(
                "history.suspicious_tld", Severity.MEDIUM,
                f"Visit to abused TLD .{tld}",
                f"Host {host} uses the .{tld} TLD, disproportionately used for "
                "free malicious infrastructure.",
                "history", host, ev))

        low = (url + " " + title).lower()
        hits = [k for k in SENSITIVE_KEYWORDS if k in low]
        if hits:
            findings.append(Finding(
                "history.sensitive_keyword", Severity.LOW,
                "Sensitive keyword in URL/title",
                "Matched keyword(s): " + ", ".join(sorted(set(hits))),
                "history", ", ".join(sorted(set(hits))), ev))

        # Long base64/hex query strings can carry beaconed/encoded data.
        try:
            qs = urlsplit(url).query
        except ValueError:
            qs = ""
        if qs:
            for _k, v in parse_qsl(qs):
                if len(v) >= 80 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
                    findings.append(Finding(
                        "history.encoded_query", Severity.MEDIUM,
                        "Long encoded query-string parameter",
                        "A query parameter carries an 80+ char base64/hex-like "
                        "blob, a possible beacon or encoded payload.",
                        "history", reg or host, {**ev, "param_len": len(v)}))
                    break

    # Cross-record heuristic: many distinct exfil/shortener hosts.
    distinct_exfil = {
        _registrable_host(_host_of(str(r.get("url", ""))))
        for r in records
        if _registrable_host(_host_of(str(r.get("url", "")))) in EXFIL_HOSTS
    }
    if len(distinct_exfil) >= 3:
        findings.append(Finding(
            "history.multi_exfil_pattern", Severity.CRITICAL,
            "Multiple distinct exfiltration sites visited",
            "Visits to " + str(len(distinct_exfil)) + " different anonymous "
            "file-share/paste services suggest data-staging activity: "
            + ", ".join(sorted(distinct_exfil)),
            "history", "", {"hosts": sorted(distinct_exfil)}))

    return findings


def analyze_downloads(records: Iterable[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    records = list(records)

    for rec in records:
        url = str(rec.get("url", "") or "")
        target = str(rec.get("target_path", "") or "")
        name = os.path.basename(target.replace("\\", "/")) if target else ""
        host = _host_of(url)
        reg = _registrable_host(host)
        size = _to_int(rec.get("received_bytes"))
        ext = os.path.splitext(name)[1].lower() if name else ""
        ev = {"url": url, "file": name or target, "bytes": size,
              "danger_type": rec.get("danger_type", "")}

        if name and DOUBLE_EXT_RE.search(name):
            findings.append(Finding(
                "download.double_extension", Severity.CRITICAL,
                "Double-extension executable disguise",
                f"'{name}' masquerades as a document but is an executable/script.",
                "download", name, ev))
        elif ext in DANGEROUS_EXT:
            sev = Severity.HIGH
            findings.append(Finding(
                "download.executable", sev,
                f"Executable/script download ({ext})",
                f"Downloaded '{name}' from {reg or host or 'unknown source'}.",
                "download", name, ev))

        if ext in ARCHIVE_EXT:
            findings.append(Finding(
                "download.archive", Severity.LOW,
                f"Archive download ({ext})",
                f"Archive '{name}' may bundle scripts/executables; inspect contents.",
                "download", name, ev))

        if reg in EXFIL_HOSTS:
            findings.append(Finding(
                "download.from_exfil_host", Severity.HIGH,
                "Download from anonymous file-share",
                f"File retrieved from {reg}, a host commonly used to deliver "
                "second-stage payloads.",
                "download", reg, ev))

        if host and IPV4_RE.match(host):
            findings.append(Finding(
                "download.from_ip", Severity.HIGH,
                "Download served from raw IP address",
                f"Payload fetched directly from {host} (no domain name).",
                "download", host, ev))

        dt = str(rec.get("danger_type", "") or "").lower()
        if dt and dt not in ("0", "not_dangerous", "none", "safe"):
            findings.append(Finding(
                "download.browser_flagged", Severity.HIGH,
                "Browser flagged download as dangerous",
                f"Browser danger_type='{dt}' was recorded for '{name or url}'.",
                "download", name or host, ev))

        if size >= LARGE_DOWNLOAD_BYTES:
            findings.append(Finding(
                "download.large_transfer", Severity.LOW,
                "Large file transfer",
                f"'{name or url}' is {size / (1024*1024):.0f} MB; correlate with "
                "egress if this looks like bulk data movement.",
                "download", name or host, ev))

    return findings


def analyze(history_path: Optional[str] = None,
            downloads_path: Optional[str] = None) -> List[Finding]:
    findings: List[Finding] = []
    if history_path:
        findings += analyze_history(load_records(history_path, "history"))
    if downloads_path:
        findings += analyze_downloads(load_records(downloads_path, "downloads"))
    findings.sort(key=lambda f: Severity.rank(f.severity), reverse=True)
    return findings


def summarize(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts
