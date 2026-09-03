"""Report rendering for Purple Recon — terminal and purple-themed HTML."""

from __future__ import annotations

import html
from .scanner import ScanResult

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEV_COLOR = {"high": "\033[91m", "medium": "\033[93m", "low": "\033[96m", "info": "\033[90m"}
_RESET = "\033[0m"
_PURPLE = "\033[95m"


def _sorted(result: ScanResult):
    return sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))


def to_terminal(result: ScanResult) -> str:
    out = [
        f"{_PURPLE}╔══════════════════════════════════════════════╗{_RESET}",
        f"{_PURPLE}║           PURPLE RECON  ·  REPORT            ║{_RESET}",
        f"{_PURPLE}╚══════════════════════════════════════════════╝{_RESET}",
        f"Target : {result.target}",
        f"Started: {result.started}",
    ]
    if result.software:
        out.append(f"Stack  : {', '.join(result.software)}")
    out.append("")

    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    out.append("Findings: " + "  ".join(f"{s}:{counts.get(s,0)}"
               for s in ("high", "medium", "low", "info")))
    out.append("─" * 50)

    for f in _sorted(result):
        c = _SEV_COLOR.get(f.severity, "")
        out.append(f"{c}[{f.severity.upper():6}]{_RESET} {f.title}")
        if f.detail:
            out.append(f"          {f.detail}")
        if f.component:
            out.append(f"          {_PURPLE}Affected component:{_RESET} {f.component}")
        if f.impact:
            out.append(f"          {_PURPLE}How it's exploited:{_RESET} {f.impact}")
        if f.exposed:
            out.append(f"          {_PURPLE}What's exposed:{_RESET} {f.exposed}")
        if f.remediation:
            out.append(f"          {_PURPLE}Fix:{_RESET} {f.remediation}")
        if f.location:
            label = "Found at (lock down this URL)" if f.category == "exposure" else "Found at"
            out.append(f"          {_PURPLE}{label}:{_RESET} {f.location}")
        if f.reference:
            out.append(f"          {_PURPLE}Reference:{_RESET} {f.reference}")
        out.append("")
    return "\n".join(out)


def _block(label: str, value: str, cls: str) -> str:
    if not value:
        return ""
    return (f'<div class="line {cls}"><span class="lbl">{label}</span>'
            f'{html.escape(value)}</div>')


def to_html(result: ScanResult) -> str:
    rows = []
    for f in _sorted(result):
        is_loc_exposure = f.category == "exposure"
        loc_label = "Found at — lock down this URL" if is_loc_exposure else "Found at"
        loc_cls = "loc" if is_loc_exposure else "foundat"
        loc_block = (f'<div class="line {loc_cls}"><span class="lbl">{loc_label}</span>'
                     f'<a href="{html.escape(f.location)}" target="_blank" rel="noopener">'
                     f'{html.escape(f.location)}</a></div>') if f.location else ""
        ref_block = (f'<div class="line ref"><span class="lbl">Reference</span>'
                     f'<a href="{html.escape(f.reference)}" target="_blank" rel="noopener">'
                     f'{html.escape(f.reference)}</a></div>') if f.reference else ""
        rows.append(f"""
        <tr class="sev-{f.severity}">
          <td class="sevcol"><span class="badge {f.severity}">{f.severity.upper()}</span>
              <div class="cat">{html.escape(f.category)}</div></td>
          <td>
            <div class="title">{html.escape(f.title)}</div>
            <div class="detail">{html.escape(f.detail)}</div>
            {_block("Affected component", f.component, "component")}
            {_block("How it's exploited", f.impact, "impact")}
            {_block("What's exposed", f.exposed, "exposed")}
            {_block("Fix", f.remediation, "fix")}
            {loc_block}
            {ref_block}
          </td>
        </tr>""")

    stack = ", ".join(html.escape(s) for s in result.software) or "—"
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    chips = "".join(
        f'<span class="chip {s}">{s.upper()} {counts.get(s,0)}</span>'
        for s in ("high", "medium", "low", "info"))

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Purple Recon — {html.escape(result.target)}</title>
<style>
  :root {{ --bg:#140a1f; --card:#1e1030; --line:#38215a; --p:#a855f7; --p2:#c084fc; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:#ede9fe;
         font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
  header {{ padding:28px 32px; background:linear-gradient(120deg,#2a1245,#12081e);
           border-bottom:2px solid var(--p); }}
  h1 {{ margin:0; font-size:22px; color:var(--p2); letter-spacing:1px; }}
  .meta {{ margin-top:8px; font-size:13px; color:#b9a7d6; }}
  .chips {{ margin-top:12px; }}
  .chip {{ padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; margin-right:6px; }}
  .chip.high {{ background:#7f1d1d; color:#fecaca; }}
  .chip.medium {{ background:#78350f; color:#fed7aa; }}
  .chip.low {{ background:#164e63; color:#a5f3fc; }}
  .chip.info {{ background:#312e40; color:#c7bcdb; }}
  .wrap {{ padding:24px 32px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  td {{ padding:14px; border-bottom:1px solid var(--line); vertical-align:top; font-size:13px; }}
  .sevcol {{ width:110px; }}
  .cat {{ color:#8b7aa8; font-size:10px; margin-top:6px; text-transform:uppercase; }}
  .title {{ font-weight:700; color:#f3ecff; }}
  .detail {{ color:#c4b5db; margin:5px 0 8px; font-size:12px; }}
  .line {{ margin:5px 0; font-size:12px; line-height:1.5; padding-left:10px;
          border-left:2px solid var(--line); }}
  .lbl {{ display:inline-block; font-weight:700; margin-right:8px; }}
  .component {{ border-left-color:#8b5cf6; }} .component .lbl {{ color:#c4b5fd; }}
  .impact {{ border-left-color:#ef4444; }} .impact .lbl {{ color:#fca5a5; }}
  .exposed {{ border-left-color:#f59e0b; }} .exposed .lbl {{ color:#fcd34d; }}
  .fix {{ border-left-color:#22c55e; }} .fix .lbl {{ color:#86efac; }}
  .ref {{ border-left-color:var(--p); }} .ref .lbl {{ color:var(--p2); }}
  .foundat {{ border-left-color:#38bdf8; }} .foundat .lbl {{ color:#7dd3fc; }} .foundat a {{ color:#bae6fd; }}
  .loc {{ border-left-color:#f59e0b; background:#2a1c10; padding:7px 10px; border-radius:4px; }}
  .loc .lbl {{ color:#fcd34d; }} .loc a {{ color:#fde68a; }}
  .badge {{ padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
  .badge.high {{ background:#7f1d1d; color:#fecaca; }}
  .badge.medium {{ background:#78350f; color:#fed7aa; }}
  .badge.low {{ background:#164e63; color:#a5f3fc; }}
  .badge.info {{ background:#312e40; color:#c7bcdb; }}
  a {{ color:var(--p2); word-break:break-all; }}
  footer {{ padding:16px 32px; color:#7a6a99; font-size:11px; }}
</style></head>
<body>
  <header>
    <h1>◆ PURPLE RECON</h1>
    <div class="meta">Target: {html.escape(result.target)} &nbsp;·&nbsp; {html.escape(result.started)}<br>
    Detected stack: {stack}</div>
    <div class="chips">{chips}</div>
  </header>
  <div class="wrap">
    <table><tbody>{''.join(rows)}</tbody></table>
  </div>
  <footer>Authorized assessment only. Purple Recon identifies and explains — it does not exploit.</footer>
</body></html>"""


# --------------------------------------------------------------------------- #
# Machine-readable output: JSON and SARIF 2.1.0 (for CI / ticketing pipelines)
# --------------------------------------------------------------------------- #
import json
from dataclasses import asdict


def to_json(result: ScanResult) -> str:
    payload = {
        "tool": "PurpleRecon",
        "target": result.target,
        "started": result.started,
        "software": result.software,
        "findings": [asdict(f) for f in _sorted(result)],
    }
    return json.dumps(payload, indent=2)


# SARIF severity mapping
_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "none"}


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in _sorted(result):
        rule_id = f"{f.category}/{f.title.split(':')[0].strip()}".replace(" ", "-")
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.title,
            "shortDescription": {"text": f.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "none")},
        })
        message_parts = [f.detail]
        if f.impact:
            message_parts.append(f"Impact: {f.impact}")
        if f.exposed:
            message_parts.append(f"Exposed: {f.exposed}")
        if f.component:
            message_parts.append(f"Affected component: {f.component}")
        if f.remediation:
            message_parts.append(f"Remediation: {f.remediation}")
        result_obj = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "none"),
            "message": {"text": "  ".join(p for p in message_parts if p)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location}
                }
            }],
            "properties": {
                "severity": f.severity,
                "category": f.category,
                "reference": f.reference,
            },
        }
        results.append(result_obj)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PurpleRecon",
                "informationUri": "https://github.com/TrevorSharpe/purple-recon",
                "version": "1.2.0",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)
