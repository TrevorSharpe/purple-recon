#!/usr/bin/env python3
"""
Purple Recon — Web Vulnerability Assessment Scanner

A NON-DESTRUCTIVE reconnaissance and vulnerability-identification tool.
It fingerprints a target, audits its security posture, and correlates
detected software against the NVD (National Vulnerability Database).

It does NOT exploit anything. It identifies attack surface and known
vulnerabilities so a human can investigate them under proper authorization.

AUTHORIZED USE ONLY. Only scan systems you own or have explicit written
permission to test. Unauthorized scanning may be illegal in your jurisdiction.
"""

from __future__ import annotations

import re
import ssl
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

USER_AGENT = "PurpleRecon/1.0 (+authorized-assessment)"
TIMEOUT = 10


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    category: str
    title: str
    severity: str  # info | low | medium | high
    detail: str
    reference: str = ""


@dataclass
class ScanResult:
    target: str
    started: str
    software: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def add(self, **kw) -> None:
        self.findings.append(Finding(**kw))


# --------------------------------------------------------------------------- #
# HTTP probing + fingerprinting
# --------------------------------------------------------------------------- #
# header/body signatures -> friendly software name used for CVE correlation
_SERVER_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)/([0-9][0-9A-Za-z\.\-]*)")

_TECH_SIGNATURES = [
    ("x-powered-by", None, "X-Powered-By header"),
    ("x-aspnet-version", None, "ASP.NET version"),
    ("x-generator", None, "Generator"),
]

_BODY_SIGNATURES = [
    (re.compile(r'name="generator" content="WordPress ([0-9.]+)"', re.I), "WordPress {0}"),
    (re.compile(r"/wp-content/", re.I), "WordPress"),
    (re.compile(r'name="generator" content="Joomla', re.I), "Joomla"),
    (re.compile(r"Drupal.settings", re.I), "Drupal"),
    (re.compile(r'name="generator" content="Drupal ([0-9.]+)', re.I), "Drupal {0}"),
]


def probe(url: str, result: ScanResult) -> requests.Response | None:
    try:
        resp = requests.get(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=True,
        )
    except RequestException as e:
        result.add(
            category="connectivity",
            title="Target unreachable",
            severity="info",
            detail=f"Could not complete request: {e}",
        )
        return None

    result.add(
        category="recon",
        title=f"HTTP {resp.status_code} from {resp.url}",
        severity="info",
        detail=f"Final URL after redirects: {resp.url}",
    )
    return resp


def fingerprint(resp: requests.Response, result: ScanResult) -> None:
    headers = resp.headers

    server = headers.get("Server", "")
    if server:
        result.add(
            category="fingerprint",
            title="Server header",
            severity="info",
            detail=server,
        )
        m = _SERVER_RE.match(server)
        if m:
            result.software.append(f"{m.group(1)} {m.group(2)}")

    for hdr, _, label in _TECH_SIGNATURES:
        val = headers.get(hdr)
        if val:
            result.add(
                category="fingerprint",
                title=label,
                severity="info",
                detail=val,
            )
            m = _SERVER_RE.match(val)
            if m:
                result.software.append(f"{m.group(1)} {m.group(2)}")
            elif any(c.isdigit() for c in val):
                result.software.append(val)

    body = resp.text[:200_000]
    for rx, tmpl in _BODY_SIGNATURES:
        m = rx.search(body)
        if m:
            name = tmpl.format(*m.groups()) if m.groups() else tmpl
            result.add(
                category="fingerprint",
                title="Technology detected",
                severity="info",
                detail=name,
            )
            if any(c.isdigit() for c in name):
                result.software.append(name)

    # de-dup while preserving order
    seen: set[str] = set()
    result.software = [s for s in result.software if not (s in seen or seen.add(s))]


# --------------------------------------------------------------------------- #
# Security header audit
# --------------------------------------------------------------------------- #
_SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS not set", "medium",
        "Missing HSTS lets clients be downgraded to plaintext HTTP."),
    "content-security-policy": ("No Content-Security-Policy", "medium",
        "Absent CSP increases XSS blast radius."),
    "x-frame-options": ("X-Frame-Options missing", "low",
        "Page may be framed (clickjacking) if CSP frame-ancestors also absent."),
    "x-content-type-options": ("X-Content-Type-Options missing", "low",
        "MIME-sniffing not disabled (set to 'nosniff')."),
    "referrer-policy": ("Referrer-Policy missing", "info",
        "Referrer data may leak to third parties."),
}


def audit_headers(resp: requests.Response, result: ScanResult) -> None:
    present = {k.lower() for k in resp.headers}
    for hdr, (title, sev, detail) in _SECURITY_HEADERS.items():
        if hdr not in present:
            result.add(category="headers", title=title, severity=sev, detail=detail)

    # info-leak headers
    for leaky in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if leaky in present:
            result.add(
                category="headers",
                title=f"Information disclosure via {leaky}",
                severity="low",
                detail=f"'{resp.headers.get(leaky)}' reveals stack details useful to attackers.",
            )


# --------------------------------------------------------------------------- #
# TLS inspection
# --------------------------------------------------------------------------- #
def inspect_tls(host: str, port: int, result: ScanResult) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                proto = tls.version()
                cipher = tls.cipher()
                cert = tls.getpeercert()
    except (ssl.SSLError, socket.error, OSError) as e:
        result.add(category="tls", title="TLS check failed", severity="info", detail=str(e))
        return

    result.add(category="tls", title="TLS protocol", severity="info",
               detail=f"{proto} / {cipher[0] if cipher else '?'}")

    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        result.add(category="tls", title=f"Weak TLS protocol: {proto}",
                   severity="high", detail="Deprecated protocol should be disabled.")

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                result.add(category="tls", title="Certificate expired", severity="high",
                           detail=f"Expired {abs(days)} days ago ({not_after}).")
            elif days < 21:
                result.add(category="tls", title="Certificate expiring soon", severity="medium",
                           detail=f"Expires in {days} days ({not_after}).")
            else:
                result.add(category="tls", title="Certificate valid", severity="info",
                           detail=f"Expires in {days} days ({not_after}).")
        except ValueError:
            pass


# --------------------------------------------------------------------------- #
# Non-destructive content discovery (GET only, common exposed paths)
# --------------------------------------------------------------------------- #
_SENSITIVE_PATHS = [
    ("/.git/config", "high", "Exposed .git repository — source/history may be downloadable."),
    ("/.env", "high", "Exposed environment file — often contains secrets."),
    ("/.svn/entries", "medium", "Exposed SVN metadata."),
    ("/server-status", "medium", "Apache server-status exposed."),
    ("/phpinfo.php", "medium", "phpinfo() exposes full config."),
    ("/.well-known/security.txt", "info", "security.txt present (good practice)."),
    ("/robots.txt", "info", "robots.txt present."),
    ("/backup.zip", "medium", "Possible exposed backup archive."),
    ("/.DS_Store", "low", "Exposed .DS_Store may leak directory names."),
]


def discover_paths(base: str, result: ScanResult) -> None:
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path, sev, detail in _SENSITIVE_PATHS:
        try:
            r = requests.get(root + path, headers={"User-Agent": USER_AGENT},
                             timeout=TIMEOUT, allow_redirects=False)
        except RequestException:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            result.add(category="exposure", title=f"Accessible: {path}",
                       severity=sev, detail=detail, reference=root + path)
        time.sleep(0.15)  # be polite


# --------------------------------------------------------------------------- #
# CVE correlation via NVD 2.0 (keyless; rate-limited)
# --------------------------------------------------------------------------- #
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def correlate_cves(result: ScanResult, max_per_product: int = 5) -> None:
    for sw in result.software:
        keyword = sw.replace("/", " ").strip()
        try:
            r = requests.get(
                NVD_API,
                params={"keywordSearch": keyword, "resultsPerPage": max_per_product},
                headers={"User-Agent": USER_AGENT},
                timeout=20,
            )
            if r.status_code != 200:
                continue
            data = r.json()
        except (RequestException, ValueError):
            continue

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "CVE-?")
            descs = cve.get("descriptions", [])
            desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score, sev = _cvss(metrics)
            result.add(
                category="cve",
                title=f"{cid} affects {sw}",
                severity=sev,
                detail=(desc[:280] + "…") if len(desc) > 280 else desc,
                reference=f"https://nvd.nist.gov/vuln/detail/{cid}",
            )
        time.sleep(1.0)  # respect keyless NVD rate limit


def _cvss(metrics: dict) -> tuple[float, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            if score >= 9:
                return score, "high"
            if score >= 7:
                return score, "high"
            if score >= 4:
                return score, "medium"
            return score, "low"
    return 0.0, "info"


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_scan(target: str, do_paths: bool = True, do_cve: bool = True) -> ScanResult:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    result = ScanResult(target=target, started=datetime.now(timezone.utc).isoformat())

    resp = probe(target, result)
    if resp is None:
        return result

    fingerprint(resp, result)
    audit_headers(resp, result)

    parsed = urlparse(str(resp.url))
    if parsed.scheme == "https":
        inspect_tls(parsed.hostname, parsed.port or 443, result)

    if do_paths:
        discover_paths(str(resp.url), result)
    if do_cve and result.software:
        correlate_cves(result)

    return result
