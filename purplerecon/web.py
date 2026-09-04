"""
Purple Recon — local web GUI.

Runs a small Flask server on localhost so you can type a URL and scan it.
The scanner logic is unchanged; this only wraps it in a browser front-end.

    python -m purplerecon.web            # then open http://127.0.0.1:8000
    python -m purplerecon.web --port 9000

Binds to 127.0.0.1 by default so the scanner is not exposed to your network.
AUTHORIZED USE ONLY — the page requires you to confirm authorization per scan.
"""

from __future__ import annotations

import argparse
import base64
import hmac
import os
from dataclasses import asdict

from flask import Flask, request, jsonify, Response

from .scanner import run_fast_scan, correlate_cves, run_site_scan, ScanResult

app = Flask(__name__)

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# Optional HTTP basic auth. Set PURPLERECON_AUTH="user:password" to require it on
# every request — essential if this is reachable beyond localhost, since an open
# scanner lets anyone drive your server to scan other targets.
_AUTH = os.environ.get("PURPLERECON_AUTH", "")


@app.before_request
def _require_auth():
    if not _AUTH:
        return None
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Basic "):
        try:
            decoded = base64.b64decode(hdr[6:]).decode("utf-8", "replace")
        except Exception:
            decoded = ""
        if hmac.compare_digest(decoded, _AUTH):
            return None
    return Response("Authentication required.", 401,
                    {"WWW-Authenticate": 'Basic realm="Purple Recon"'})


@app.get("/")
def index() -> Response:
    return Response(_PAGE, mimetype="text/html")


@app.post("/api/scan")
def api_scan():
    """Fast phase — everything except CVE correlation. Returns near-instantly."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Enter a target URL to scan."}), 400
    if not data.get("authorized"):
        return jsonify({"error": "Confirm you're authorized to scan this target first."}), 403

    try:
        result = run_fast_scan(target, do_paths=bool(data.get("paths", True)))
    except Exception as e:
        return jsonify({"error": f"Scan couldn't complete: {e}"}), 500

    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return jsonify({
        "target": result.target,
        "observed_url": result.observed_url,
        "started": result.started,
        "software": result.software,
        "findings": [asdict(f) for f in findings],
    })


@app.post("/api/sitescan")
def api_sitescan():
    """Crawl the site (same host, bounded) and scan every page. One request;
    slower than the two-phase scan, so the UI marks it as such."""
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Enter a target URL to scan."}), 400
    if not data.get("authorized"):
        return jsonify({"error": "Confirm you're authorized to scan this target first."}), 403
    try:
        max_pages = int(data.get("max_pages", 25))
    except (TypeError, ValueError):
        max_pages = 25
    max_pages = max(1, min(max_pages, 100))
    try:
        result = run_site_scan(target, max_pages=max_pages, do_cve=bool(data.get("cve", True)))
    except Exception as e:
        return jsonify({"error": f"Scan couldn't complete: {e}"}), 500

    findings = sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return jsonify({
        "target": result.target,
        "observed_url": result.observed_url,
        "software": result.software,
        "pages": result.pages,
        "findings": [asdict(f) for f in findings],
    })


@app.post("/api/cve")
def api_cve():
    """CVE phase — queried separately so it never blocks the fast results.
    Cached on disk, so repeat lookups of the same software are instant."""
    data = request.get_json(force=True, silent=True) or {}
    software = data.get("software") or []
    observed = (data.get("observed_url") or data.get("target") or "").strip()
    if not software or not observed:
        return jsonify({"findings": []})

    r = ScanResult(target=observed, started="", observed_url=observed, software=list(software))
    try:
        correlate_cves(r, observed)
    except Exception as e:
        return jsonify({"error": f"CVE lookup failed: {e}", "findings": []}), 200

    findings = sorted(r.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))
    return jsonify({"findings": [asdict(f) for f in findings]})


def main() -> None:
    p = argparse.ArgumentParser(prog="purplerecon.web",
                                description="Purple Recon web GUI (localhost).")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default localhost)")
    p.add_argument("--port", type=int, default=8000, help="port (default 8000)")
    args = p.parse_args()
    if args.host not in ("127.0.0.1", "localhost") and not _AUTH:
        print("\n  ⚠  Binding to a non-local address with no auth configured.")
        print("     A reachable scanner with no auth lets anyone drive your server.")
        print("     Set PURPLERECON_AUTH='user:password', or keep it behind an")
        print("     authenticated proxy / VPN (see DEPLOY.md).")
    print(f"\n  ◆ Purple Recon GUI → http://{args.host}:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False)


# --------------------------------------------------------------------------- #
# Front-end (single page, embedded). Console-style target prompt as the hero.
# --------------------------------------------------------------------------- #
_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#140a1f">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Purple Recon">
<title>Purple Recon</title>
<style>
  :root{
    --bg:#140a1f; --panel:#1b0f2b; --panel2:#241338; --line:#38215a;
    --p:#a855f7; --p2:#c084fc; --ink:#ede9fe; --mut:#9d8bc0;
    --high:#f87171; --med:#fbbf24; --low:#38bdf8; --info:#8b7aa8; --ok:#34d399;
  }
  @media (prefers-reduced-motion: reduce){ *{animation:none!important;transition:none!important} }
  *{box-sizing:border-box}
  body{margin:0;background:radial-gradient(1200px 600px at 50% -10%,#26123f 0%,var(--bg) 60%);
       color:var(--ink);font-family:ui-monospace,"JetBrains Mono",SFMono-Regular,Menlo,monospace;
       min-height:100vh;padding:40px 18px;
       padding-left:max(18px,env(safe-area-inset-left));
       padding-right:max(18px,env(safe-area-inset-right));
       padding-bottom:max(40px,env(safe-area-inset-bottom))}
  .shell{max-width:860px;margin:0 auto}
  .brand{display:flex;align-items:center;gap:10px;color:var(--p2);font-weight:700;
         letter-spacing:.5px;font-size:15px;margin-bottom:22px}
  .brand .dot{width:10px;height:10px;border-radius:50%;background:var(--p);
              box-shadow:0 0 12px var(--p)}
  /* hero prompt */
  .prompt{background:var(--panel);border:1px solid var(--line);border-radius:12px;
          padding:18px 18px 16px;box-shadow:0 20px 60px -30px #000}
  .promptline{display:flex;align-items:center;gap:12px}
  .caret{color:var(--p);font-weight:700;font-size:18px;user-select:none}
  #target{flex:1;background:transparent;border:none;outline:none;color:var(--ink);
          font:inherit;font-size:18px;padding:8px 0}
  #target::placeholder{color:#6d5b90}
  #scan{background:linear-gradient(180deg,var(--p),#7c3aed);color:#fff;border:none;
        border-radius:8px;padding:10px 18px;font:inherit;font-weight:700;cursor:pointer;
        white-space:nowrap}
  #scan:disabled{opacity:.4;cursor:not-allowed}
  #scan:not(:disabled):hover{filter:brightness(1.08)}
  .opts{display:flex;flex-wrap:wrap;gap:16px;margin-top:14px;padding-top:14px;
        border-top:1px dashed var(--line);font-size:13px;color:var(--mut)}
  .opt{display:flex;align-items:center;gap:7px;cursor:pointer}
  .opt input{accent-color:var(--p);width:15px;height:15px}
  .auth{color:var(--p2)}
  .hint{margin:10px 2px 0;font-size:12px;color:#7a6a99;line-height:1.5}
  /* status line */
  .status{margin:20px 2px 6px;font-size:13px;color:var(--mut);min-height:20px}
  .status .blink{animation:blink 1s steps(2) infinite;color:var(--p2)}
  @keyframes blink{50%{opacity:0}}
  .err{color:var(--high)}
  /* summary */
  .summary{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0 18px}
  .stack{color:var(--mut);font-size:12px;margin-left:auto}
  .chip{padding:4px 12px;border-radius:20px;font-size:12px;font-weight:700}
  .chip.high{background:#3b1414;color:var(--high)} .chip.medium{background:#3a2a0c;color:var(--med)}
  .chip.low{background:#0c2a3a;color:var(--low)} .chip.info{background:#241d33;color:#c7bcdb}
  /* findings */
  .find{background:var(--panel);border:1px solid var(--line);border-left-width:3px;
        border-radius:10px;padding:14px 16px;margin-bottom:12px}
  .find.high{border-left-color:var(--high)} .find.medium{border-left-color:var(--med)}
  .find.low{border-left-color:var(--low)} .find.info{border-left-color:var(--info)}
  .fhead{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap}
  .badge{padding:2px 9px;border-radius:6px;font-size:11px;font-weight:700}
  .badge.high{background:#3b1414;color:var(--high)} .badge.medium{background:#3a2a0c;color:var(--med)}
  .badge.low{background:#0c2a3a;color:var(--low)} .badge.info{background:#241d33;color:#c7bcdb}
  .ftitle{font-weight:700;color:#f3ecff}
  .fcat{color:#7a6a99;font-size:11px;margin-left:auto}
  .fdetail{color:#c4b5db;font-size:12.5px;margin:8px 0}
  .line{margin:6px 0;font-size:12.5px;line-height:1.55;padding-left:11px;border-left:2px solid var(--line)}
  .line .lbl{font-weight:700;margin-right:8px}
  .l-comp{border-left-color:#8b5cf6} .l-comp .lbl{color:#c4b5fd}
  .l-impact{border-left-color:var(--high)} .l-impact .lbl{color:#fca5a5}
  .l-exposed{border-left-color:var(--med)} .l-exposed .lbl{color:#fcd34d}
  .l-fix{border-left-color:var(--ok)} .l-fix .lbl{color:#86efac}
  .l-found{border-left-color:var(--low)} .l-found .lbl{color:#7dd3fc}
  .l-found a{color:#bae6fd}
  .l-lock{border-left-color:var(--med);background:#2a1c10;padding:8px 11px;border-radius:5px}
  .l-lock .lbl{color:#fcd34d} .l-lock a{color:#fde68a}
  .l-ref{border-left-color:var(--p)} .l-ref .lbl{color:var(--p2)} .l-ref a{color:var(--p2)}
  a{word-break:break-all}
  .foot{margin-top:26px;color:#6d5b90;font-size:11px;line-height:1.6}
  /* site map */
  .sitemap{background:var(--panel);border:1px solid var(--line);border-radius:10px;
           padding:12px 14px;margin-bottom:16px}
  .sitemap h3{margin:0 0 8px;font-size:12px;color:var(--p2);text-transform:uppercase;letter-spacing:.5px}
  .pagerow{display:flex;gap:10px;font-size:12px;padding:3px 0;border-bottom:1px solid #241338}
  .pagerow:last-child{border-bottom:none}
  .pcode{min-width:38px;font-weight:700}
  .pcode.ok{color:var(--ok)} .pcode.warn{color:var(--med)} .pcode.err{color:var(--high)}
  .purl{color:#c4b5db;word-break:break-all}
  /* mobile */
  @media (max-width:560px){
    body{padding:22px 14px;padding-bottom:max(22px,env(safe-area-inset-bottom))}
    .prompt{padding:14px}
    .promptline{flex-wrap:wrap;row-gap:12px}
    #target{font-size:17px}
    #scan{width:100%;order:3;padding:13px}
    .opts{gap:12px}
    .opt{width:100%}
    .opt input{width:20px;height:20px}
    .fhead{gap:8px}
    .fcat{margin-left:0;width:100%;order:5}
    .stack{margin-left:0;width:100%;margin-top:2px}
    .find{padding:13px 14px}
  }
</style></head>
<body>
  <div class="shell">
    <div class="brand"><span class="dot"></span> purple recon</div>

    <div class="prompt">
      <div class="promptline">
        <span class="caret">▸</span>
        <input id="target" placeholder="example.com" autocomplete="off" spellcheck="false"
               autocapitalize="off" />
        <button id="scan" disabled>scan</button>
      </div>
      <div class="opts">
        <label class="opt"><input type="checkbox" id="paths" checked> path discovery</label>
        <label class="opt"><input type="checkbox" id="cve" checked> CVE lookup <span style="color:#6d5b90">(slower)</span></label>
        <label class="opt"><input type="checkbox" id="crawl"> crawl whole site <span style="color:#6d5b90">(slower)</span></label>
        <label class="opt auth"><input type="checkbox" id="authorized"> I'm authorized to scan this target</label>
      </div>
    </div>
    <div class="hint">Assesses a site's exposure and known-vulnerability surface — it identifies and
      explains findings, it doesn't exploit them. Only scan systems you own or have written permission to test.</div>

    <div class="status" id="status"></div>
    <div class="summary" id="summary" hidden></div>
    <div id="sitemap"></div>
    <div id="results"></div>

    <div class="foot">Purple Recon runs locally. CVE data from the NVD; findings are for you to verify and fix.</div>
  </div>

<script>
const $ = s => document.querySelector(s);
const targetEl = $("#target"), scanEl = $("#scan"), authEl = $("#authorized");
const statusEl = $("#status"), summaryEl = $("#summary"), resultsEl = $("#results");

function refresh(){ scanEl.disabled = !(targetEl.value.trim() && authEl.checked); }
targetEl.addEventListener("input", refresh);
authEl.addEventListener("change", refresh);
targetEl.addEventListener("keydown", e => { if(e.key === "Enter" && !scanEl.disabled) scan(); });
scanEl.addEventListener("click", scan);

const esc = s => (s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const link = u => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`;

function block(label, val, cls){
  if(!val) return "";
  return `<div class="line ${cls}"><span class="lbl">${label}</span>${esc(val)}</div>`;
}

function findingCard(f){
  const exposure = f.category === "exposure";
  const found = f.location
    ? (exposure
        ? `<div class="line l-lock"><span class="lbl">Found at — lock down this URL</span>${link(f.location)}</div>`
        : `<div class="line l-found"><span class="lbl">Found at</span>${link(f.location)}</div>`)
    : "";
  const ref = f.reference
    ? `<div class="line l-ref"><span class="lbl">Reference</span>${link(f.reference)}</div>` : "";
  return `<div class="find ${f.severity}">
    <div class="fhead">
      <span class="badge ${f.severity}">${f.severity.toUpperCase()}</span>
      <span class="ftitle">${esc(f.title)}</span>
      <span class="fcat">${esc(f.category)}</span>
    </div>
    <div class="fdetail">${esc(f.detail)}</div>
    ${block("Affected component", f.component, "l-comp")}
    ${block("How it's exploited", f.impact, "l-impact")}
    ${block("What's exposed", f.exposed, "l-exposed")}
    ${block("Fix", f.remediation, "l-fix")}
    ${found}
    ${ref}
  </div>`;
}

let currentFindings = [];

function renderSitemap(pages){
  const el = document.querySelector("#sitemap");
  if(!pages || !pages.length){ el.innerHTML = ""; return; }
  const rows = pages.map(pg => {
    const code = String(pg.status);
    const cls = code.startsWith("2") ? "ok" : code.startsWith("4")||code.startsWith("5") ? "err" : "warn";
    return `<div class="pagerow"><span class="pcode ${cls}">${esc(code)}</span><span class="purl">${esc(pg.url)}</span></div>`;
  }).join("");
  el.innerHTML = `<div class="sitemap"><h3>Site map — ${pages.length} pages</h3>${rows}</div>`;
}

async function scan(){
  const target = targetEl.value.trim();
  scanEl.disabled = true;
  summaryEl.hidden = true; summaryEl.innerHTML = "";
  document.querySelector("#sitemap").innerHTML = ""; resultsEl.innerHTML = "";
  currentFindings = [];
  statusEl.className = "status";
  const wantCve = $("#cve").checked;
  const wantCrawl = $("#crawl").checked;

  // Crawl mode: one request, scans every page (slower).
  if(wantCrawl){
    statusEl.innerHTML = `crawling & scanning ${esc(target)} <span class="blink">▊</span>  ·  this can take a bit`;
    try{
      const res = await fetch("/api/sitescan", {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ target, authorized: authEl.checked, cve: wantCve, max_pages: 25 })
      });
      const data = await res.json();
      if(!res.ok){ statusEl.className = "status err"; statusEl.textContent = data.error || "Scan failed."; return; }
      renderSitemap(data.pages);
      currentFindings = data.findings;
      render(data.target, currentFindings, "");
    }catch(err){
      statusEl.className = "status err";
      statusEl.textContent = "Couldn't reach the scanner. Is the server still running?";
    }finally{ refresh(); }
    return;
  }

  statusEl.innerHTML = `scanning ${esc(target)} <span class="blink">▊</span>`;
  try{
    const res = await fetch("/api/scan", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ target, authorized: authEl.checked, paths: $("#paths").checked })
    });
    const data = await res.json();
    if(!res.ok){ statusEl.className = "status err"; statusEl.textContent = data.error || "Scan failed."; return; }

    currentFindings = data.findings;
    render(data.target, currentFindings, wantCve && data.software.length ? "checking known CVEs…" : "");

    if(wantCve && data.software.length){
      try{
        const cveRes = await fetch("/api/cve", {
          method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify({ software: data.software, observed_url: data.observed_url || data.target })
        });
        const cveData = await cveRes.json();
        currentFindings = currentFindings.concat(cveData.findings || []);
        render(data.target, currentFindings, "");
      }catch(e){
        render(data.target, currentFindings, "");
      }
    }
  }catch(err){
    statusEl.className = "status err";
    statusEl.textContent = "Couldn't reach the scanner. Is the server still running?";
  }finally{
    refresh();
  }
}

const SEV_ORDER = {high:0, medium:1, low:2, info:3};

function render(target, findings, note){
  findings.sort((a,b) => (SEV_ORDER[a.severity]??9) - (SEV_ORDER[b.severity]??9));
  const counts = {high:0,medium:0,low:0,info:0};
  findings.forEach(f => counts[f.severity] = (counts[f.severity]||0)+1);

  statusEl.className = "status";
  statusEl.innerHTML = `${findings.length} findings on ${esc(target)}` +
    (note ? `  ·  <span class="blink">${esc(note)}</span>` : "");

  const chips = ["high","medium","low","info"]
    .map(s => `<span class="chip ${s}">${s} ${counts[s]||0}</span>`).join("");
  const stackList = [...new Set(findings.filter(f=>f.category==="fingerprint")
    .map(f=>f.exposed).filter(Boolean))];
  summaryEl.innerHTML = chips;
  summaryEl.hidden = false;

  resultsEl.innerHTML = findings.map(findingCard).join("");
}
</script>
</body></html>"""


if __name__ == "__main__":
    main()
