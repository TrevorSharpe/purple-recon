#!/usr/bin/env python3
"""
Purple Recon — Web Vulnerability Assessment Scanner

A NON-DESTRUCTIVE reconnaissance and vulnerability-identification tool.
For every finding it reports:
  • Impact       — what an attacker could achieve (attack scenario, not a payload)
  • Exposed      — the actual information observed to be leaking (secrets redacted)
  • Remediation  — the concrete fix

It IDENTIFIES and EXPLAINS. It does not run exploits, deliver payloads, dump
your files, or reconstruct your data. Findings are for a human to fix under
proper authorization.

AUTHORIZED USE ONLY. Only scan systems you own or have explicit written
permission to test.
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

USER_AGENT = "PurpleRecon/1.1 (+authorized-assessment)"
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
    location: str = ""      # URL where this finding was observed (required in report)
    impact: str = ""        # how it can be exploited / what an attacker gains
    exposed: str = ""       # the actual information observed leaking (redacted)
    component: str = ""     # affected component/module named in the advisory
    remediation: str = ""   # how to fix it
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
_SERVER_RE = re.compile(r"^([A-Za-z0-9_\-\.]+)/([0-9][0-9A-Za-z\.\-]*)")

_TECH_HEADERS = [
    ("x-powered-by", "X-Powered-By header"),
    ("x-aspnet-version", "ASP.NET version"),
    ("x-generator", "Generator"),
]

_BODY_SIGNATURES = [
    (re.compile(r'name="generator" content="WordPress ([0-9.]+)"', re.I), "WordPress {0}"),
    (re.compile(r"/wp-content/", re.I), "WordPress"),
    (re.compile(r'name="generator" content="Joomla', re.I), "Joomla"),
    (re.compile(r'name="generator" content="Drupal ([0-9.]+)', re.I), "Drupal {0}"),
]


def probe(url: str, result: ScanResult) -> requests.Response | None:
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=TIMEOUT, allow_redirects=True, verify=True)
    except RequestException as e:
        result.add(category="connectivity", title="Target unreachable", location=url,
                   severity="info", detail=f"Could not complete request: {e}")
        return None

    result.add(category="recon", title=f"HTTP {resp.status_code} from {resp.url}",
               severity="info", location=str(resp.url),
               detail=f"Final URL after redirects: {resp.url}")
    return resp


def fingerprint(resp: requests.Response, result: ScanResult) -> None:
    headers = resp.headers
    loc = str(resp.url)

    server = headers.get("Server", "")
    if server:
        m = _SERVER_RE.match(server)
        versioned = bool(m)
        result.add(
            category="fingerprint", title="Server header", location=loc,
            severity="low" if versioned else "info", detail=server,
            impact=("The exact server software and version are advertised, letting an "
                    "attacker skip reconnaissance and look up version-specific exploits "
                    "for this host.") if versioned else "",
            exposed=server if versioned else "",
            remediation=("Suppress version details — Apache 'ServerTokens Prod', "
                         "nginx 'server_tokens off'.") if versioned else "",
        )
        if m:
            result.software.append(f"{m.group(1)} {m.group(2)}")

    for hdr, label in _TECH_HEADERS:
        val = headers.get(hdr)
        if val:
            result.add(
                category="fingerprint", title=f"Stack disclosure: {label}",
                severity="low", detail=val, location=loc,
                impact="Reveals the technology and version behind the site, narrowing an "
                       "attacker's search to exploits known to affect this exact stack.",
                exposed=f"{hdr}: {val}",
                remediation="Remove or blank this header (PHP 'expose_php=Off', or strip "
                            "it at the reverse proxy).",
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
            result.add(category="fingerprint", title="Technology detected",
                       severity="info", detail=name, location=loc)
            if any(c.isdigit() for c in name):
                result.software.append(name)

    seen: set[str] = set()
    result.software = [s for s in result.software if not (s in seen or seen.add(s))]


# --------------------------------------------------------------------------- #
# Security header audit  (impact + remediation)
# --------------------------------------------------------------------------- #
_SECURITY_HEADERS = {
    "strict-transport-security": (
        "HSTS not set", "medium",
        "Browsers may connect over plaintext HTTP at least once.",
        "An on-path attacker (public Wi-Fi, rogue router) can strip TLS and silently "
        "downgrade the session to HTTP, then read or modify traffic including session "
        "cookies and login credentials.",
        "Send: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
    ),
    "content-security-policy": (
        "No Content-Security-Policy", "medium",
        "No policy restricting where scripts/styles may load from.",
        "If any XSS flaw exists, injected JavaScript runs unrestricted — enabling "
        "session-cookie theft, keylogging of login forms, and full page takeover in "
        "the victim's browser.",
        "Define a CSP limiting script/style/frame sources; roll out with "
        "Content-Security-Policy-Report-Only first to catch breakage.",
    ),
    "x-frame-options": (
        "X-Frame-Options missing", "low",
        "Page may be embeddable in a frame.",
        "The page can be loaded invisibly over an attacker's site so a victim's clicks "
        "land on hidden controls (clickjacking) — e.g. tricking them into changing a "
        "setting or confirming an action.",
        "Set X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors 'self'.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options missing", "low",
        "MIME-type sniffing is not disabled.",
        "A browser may reinterpret an uploaded or user-controlled file as a different "
        "type and execute it as script, turning a benign upload into stored XSS.",
        "Set X-Content-Type-Options: nosniff.",
    ),
    "referrer-policy": (
        "Referrer-Policy missing", "info",
        "Full referrer URLs may be shared cross-site.",
        "URLs containing session tokens, reset links, or internal paths can leak to "
        "third-party sites via the Referer header.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer).",
    ),
}


def audit_headers(resp: requests.Response, result: ScanResult) -> None:
    loc = str(resp.url)
    present = {k.lower() for k in resp.headers}
    for hdr, (title, sev, detail, impact, fix) in _SECURITY_HEADERS.items():
        if hdr not in present:
            result.add(category="headers", title=title, severity=sev, location=loc,
                       detail=detail, impact=impact, remediation=fix)


# --------------------------------------------------------------------------- #
# TLS inspection
# --------------------------------------------------------------------------- #
def inspect_tls(host: str, port: int, result: ScanResult, url: str) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                proto, cipher, cert = tls.version(), tls.cipher(), tls.getpeercert()
    except (ssl.SSLError, socket.error, OSError) as e:
        result.add(category="tls", title="TLS check failed", severity="info",
                   detail=str(e), location=url)
        return

    result.add(category="tls", title="TLS protocol", severity="info", location=url,
               detail=f"{proto} / {cipher[0] if cipher else '?'}", exposed=proto)

    if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
        result.add(
            category="tls", title=f"Weak TLS protocol: {proto}", severity="high",
            detail="A deprecated protocol version is accepted.", exposed=proto, location=url,
            impact="These protocols have known cryptographic weaknesses (e.g. BEAST, "
                   "POODLE) that can let an attacker decrypt or tamper with the session.",
            remediation="Disable SSLv3 / TLS 1.0 / TLS 1.1; require TLS 1.2 or 1.3.",
        )

    not_after = cert.get("notAfter") if cert else None
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                result.add(category="tls", title="Certificate expired", severity="high",
                           detail=f"Expired {abs(days)} days ago ({not_after}).", location=url,
                           impact="Visitors get security warnings and may be trained to click "
                                  "through them, making a man-in-the-middle attack easier.",
                           remediation="Renew now and automate renewal (ACME / Let's Encrypt).")
            elif days < 21:
                result.add(category="tls", title="Certificate expiring soon", severity="medium",
                           detail=f"Expires in {days} days ({not_after}).", location=url,
                           remediation="Renew before expiry; automate with ACME.")
            else:
                result.add(category="tls", title="Certificate valid", severity="info",
                           detail=f"Expires in {days} days ({not_after}).", location=url)
        except ValueError:
            pass


# --------------------------------------------------------------------------- #
# Non-destructive exposure discovery (GET only)
# --------------------------------------------------------------------------- #
# path -> (severity, detail, impact, remediation)
_SENSITIVE_PATHS = {
    "/.git/config": ("high",
        "Version-control metadata is web-accessible.",
        "The source repository and its full history can be reconstructed offline, "
        "commonly revealing hardcoded credentials, API keys, and internal logic.",
        "Block access to /.git in the server config, or keep the working tree outside "
        "the web root. Rotate any secrets that were ever committed."),
    "/.env": ("high",
        "An environment/secrets file is web-accessible.",
        "These files typically hold database passwords, API keys, and app secrets — "
        "reading it can directly compromise connected services.",
        "Deny web access to dotfiles, move secrets out of the web root, and rotate "
        "every exposed secret immediately."),
    "/.svn/entries": ("medium",
        "Subversion metadata is exposed.",
        "Repository structure and file paths can be recovered to guide further attacks.",
        "Block /.svn in the web server configuration."),
    "/server-status": ("medium",
        "Apache server-status page is exposed.",
        "Live requests, client IPs, and internal URLs are visible — valuable "
        "reconnaissance for targeting other users and hidden endpoints.",
        "Restrict mod_status to localhost or authenticated admins."),
    "/phpinfo.php": ("medium",
        "A phpinfo() page is exposed.",
        "Full PHP configuration, absolute paths, and loaded modules are revealed, "
        "giving an attacker a precise map for targeted attacks.",
        "Delete phpinfo() files from production."),
    "/backup.zip": ("medium",
        "A backup archive is web-accessible.",
        "Backups often contain complete source code and database dumps — a single "
        "download can hand over the whole application.",
        "Remove backups from web-accessible directories; store them off-host."),
    "/.DS_Store": ("low",
        "A macOS .DS_Store file is exposed.",
        "It leaks directory and file names, helping an attacker discover hidden or "
        "unlinked content.",
        "Prevent .DS_Store from being deployed; block dotfiles at the web server."),
    "/.well-known/security.txt": ("info",
        "security.txt is present (good practice).", "", ""),
    "/robots.txt": ("info", "robots.txt is present.", "", ""),
}

_SECRET_KEY_RE = re.compile(r"(PASS|PASSWORD|SECRET|TOKEN|APIKEY|API_KEY|KEY|PRIVATE|"
                            r"CREDENTIAL|AUTH|DSN|DATABASE_URL)", re.I)
_ENV_LINE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", re.M)


def _redacted_secret_summary(text: str) -> str:
    """Report variable NAMES present in an env-like file. Values are never shown."""
    names = _ENV_LINE_RE.findall(text[:8192])
    if not names:
        return ""
    uniq: list[str] = []
    for n in names:
        if n not in uniq:
            uniq.append(n)
    sensitive = [n for n in uniq if _SECRET_KEY_RE.search(n)]
    parts = [f"{len(uniq)} variables exposed (values redacted): " + ", ".join(uniq[:12])]
    if sensitive:
        parts.append("Sensitive names to rotate: " + ", ".join(sensitive[:12]))
    return " | ".join(parts)


def discover_paths(base: str, result: ScanResult) -> None:
    parsed = urlparse(base)
    root = f"{parsed.scheme}://{parsed.netloc}"
    for path, (sev, detail, impact, fix) in _SENSITIVE_PATHS.items():
        try:
            r = requests.get(root + path, headers={"User-Agent": USER_AGENT},
                             timeout=TIMEOUT, allow_redirects=False)
        except RequestException:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            exposed = f"HTTP 200, {len(r.content)} bytes at {path}"
            if path.endswith(".env"):
                summary = _redacted_secret_summary(r.text)
                if summary:
                    exposed += " — " + summary
            result.add(category="exposure", title=f"Accessible: {path}", severity=sev,
                       detail=detail, impact=impact, exposed=exposed,
                       remediation=fix, location=root + path)
        time.sleep(0.15)


# --------------------------------------------------------------------------- #
# CVE correlation via NVD 2.0  (impact derived from authoritative CVSS/CWE data)
# --------------------------------------------------------------------------- #
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

_AV_TEXT = {
    "NETWORK": "remotely over the network, with no prior access",
    "ADJACENT_NETWORK": "from the adjacent network segment",
    "LOCAL": "with local access to the host",
    "PHYSICAL": "with physical access to the device",
}
_IMPACT_TEXT = {"HIGH": "full", "LOW": "partial", "NONE": "no",
                "COMPLETE": "full", "PARTIAL": "partial"}


def correlate_cves(result: ScanResult, observed_url: str, max_per_product: int = 5) -> None:
    for sw in result.software:
        keyword = sw.replace("/", " ").strip()
        try:
            r = requests.get(NVD_API,
                             params={"keywordSearch": keyword, "resultsPerPage": max_per_product},
                             headers={"User-Agent": USER_AGENT}, timeout=20)
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
            cvss, sev = _cvss(cve.get("metrics", {}))
            cwe = _cwe(cve.get("weaknesses", []))

            result.add(
                category="cve",
                title=f"{cid} affects {sw}" + (f"  [{cwe}]" if cwe else ""),
                severity=sev,
                detail=(desc[:300] + "…") if len(desc) > 300 else desc,
                location=observed_url,
                impact=_impact_sentence(cvss),
                component=_affected_component(desc, cwe),
                remediation=f"Upgrade {sw} to a fixed release; review the vendor advisory "
                            f"linked below and apply interim mitigations until patched.",
                reference=f"https://nvd.nist.gov/vuln/detail/{cid}",
            )
        time.sleep(1.0)  # respect keyless NVD rate limit


def _cvss(metrics: dict) -> tuple[dict, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore", 0.0)
            sev = "high" if score >= 7 else "medium" if score >= 4 else "low"
            return data, sev
    return {}, "info"


def _cwe(weaknesses: list) -> str:
    for w in weaknesses:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v != "CWE-noinfo":
                return v
    return ""


# Human-readable names for common weakness classes (from MITRE CWE).
_CWE_NAMES = {
    "CWE-20": "Improper Input Validation", "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection", "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)", "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection", "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow", "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication", "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)", "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload", "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-611": "XML External Entity (XXE)",
    "CWE-787": "Out-of-bounds Write", "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization", "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

_AREA_KEYWORDS = (r"directives?|scripts?|normalization|parsing|parser|handling|decoding|"
                  r"deserialization|serialization|validation|sanitization|routine|mechanism|"
                  r"endpoint|interface|module|component|function|handler|plugin|feature|filter")
_AREA_RE = re.compile(
    r"\b([A-Za-z][A-Za-z0-9\-]*(?:\s+[A-Za-z][A-Za-z0-9\-]*)?)\s+(" + _AREA_KEYWORDS + r")\b",
    re.I,
)
_STOPWORDS = {"the", "a", "an", "this", "that", "these", "those", "affected",
              "vulnerable", "such", "any", "some", "which", "for", "and", "or",
              "of", "to", "in", "by", "with", "usual", "default", "if", "on",
              "from", "into", "when", "where", "via", "also", "not", "only"}


def _affected_component(desc: str, cwe: str = "") -> str:
    """Surface the affected area NAMED in the advisory, plus the weakness class.

    This only reflects what the public NVD/CWE data already states (e.g.
    'Path Traversal in path normalization / CGI scripts') so a defender knows
    which part to patch, disable, or harden. It does NOT construct an endpoint,
    parameter, or payload.
    """
    parts: list[str] = []
    if cwe and cwe in _CWE_NAMES:
        parts.append(f"weakness: {_CWE_NAMES[cwe]}")

    if desc:
        hits: list[str] = []
        hits += re.findall(r"\bmod_[a-z0-9_]+\b", desc)               # Apache modules
        hits += re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\(\)", desc)  # function() refs
        for m in _AREA_RE.finditer(desc):
            # drop any leading preposition/stopword tokens (e.g. "to path" -> "path")
            tokens = m.group(1).strip().split()
            while tokens and tokens[0].lower() in _STOPWORDS:
                tokens.pop(0)
            word = " ".join(tokens)
            if word and word.lower() not in _STOPWORDS and len(word) > 2:
                hits.append(f"{word} {m.group(2).lower()}")
        seen: set[str] = set()
        for h in hits:
            k = h.lower()
            if k not in seen:
                seen.add(k)
                parts.append(h)
                if len(parts) >= 5:
                    break

    return "; ".join(parts)


def _impact_sentence(cvss: dict) -> str:
    if not cvss:
        return ""
    av = cvss.get("attackVector") or cvss.get("accessVector", "")
    where = _AV_TEXT.get(av, "under the conditions in the CVSS vector")
    c = _IMPACT_TEXT.get(cvss.get("confidentialityImpact", ""))
    i = _IMPACT_TEXT.get(cvss.get("integrityImpact", ""))
    a = _IMPACT_TEXT.get(cvss.get("availabilityImpact", ""))
    cons = []
    if c and c != "no":
        cons.append(f"{c} disclosure of data (confidentiality)")
    if i and i != "no":
        cons.append(f"{i} tampering with data (integrity)")
    if a and a != "no":
        cons.append(f"{a} disruption of service (availability)")
    result_txt = "; ".join(cons) if cons else "impact per the CVSS vector"
    vec = cvss.get("vectorString", "")
    return f"Exploitable {where}. Potential result — {result_txt}. CVSS vector: {vec}."


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

    observed = str(resp.url)
    parsed = urlparse(observed)
    if parsed.scheme == "https":
        inspect_tls(parsed.hostname, parsed.port or 443, result, observed)
    if do_paths:
        discover_paths(observed, result)
    if do_cve and result.software:
        correlate_cves(result, observed)

    # Requirement: every reported finding must have a URL where it was observed.
    # Drop anything without a location so the report can't contain locationless items.
    result.findings = [f for f in result.findings if f.location]
    return result
