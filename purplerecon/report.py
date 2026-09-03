"""Report rendering for Purple Recon — terminal and HTML output."""

from __future__ import annotations

import html
from .scanner import ScanResult

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEV_COLOR = {
    "high": "\033[91m", "medium": "\033[93m",
    "low": "\033[96m", "info": "\033[90m",
}
_RESET = "\033[0m"
_PURPLE = "\033[95m"


def _sorted(result: ScanResult):
    return sorted(result.findings, key=lambda f: _SEV_ORDER.get(f.severity, 9))


def to_terminal(result: ScanResult) -> str:
    out = []
    out.append(f"{_PURPLE}╔══════════════════════════════════════════════╗{_RESET}")
    out.append(f"{_PURPLE}║           PURPLE RECON  ·  REPORT            ║{_RESET}")
    out.append(f"{_PURPLE}╚══════════════════════════════════════════════╝{_RESET}")
    out.append(f"Target : {result.target}")
    out.append(f"Started: {result.started}")
    if result.software:
        out.append(f"Stack  : {', '.join(result.software)}")
    out.append("")

    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = "  ".join(f"{s}:{counts.get(s,0)}" for s in ("high", "medium", "low", "info"))
    out.append(f"Findings: {summary}")
    out.append("─" * 50)

    for f in _sorted(result):
        c = _SEV_COLOR.get(f.severity, "")
        out.append(f"{c}[{f.severity.upper():6}]{_RESET} {f.title}")
        if f.detail:
            out.append(f"          {f.detail}")
        if f.reference:
            out.append(f"          ↳ {f.reference}")
    return "\n".join(out)


def to_html(result: ScanResult) -> str:
    rows = []
    for f in _sorted(result):
        ref = (f'<a href="{html.escape(f.reference)}" target="_blank" rel="noopener">'
               f'{html.escape(f.reference)}</a>') if f.reference else ""
        rows.append(f"""
        <tr class="sev-{f.severity}">
          <td><span class="badge {f.severity}">{f.severity.upper()}</span></td>
          <td>{html.escape(f.category)}</td>
          <td><strong>{html.escape(f.title)}</strong><div class="detail">{html.escape(f.detail)}</div>{ref}</td>
        </tr>""")

    stack = ", ".join(html.escape(s) for s in result.software) or "—"
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
  .wrap {{ padding:24px 32px; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
          border:1px solid var(--line); border-radius:10px; overflow:hidden; }}
  th,td {{ text-align:left; padding:12px 14px; border-bottom:1px solid var(--line);
          vertical-align:top; font-size:13px; }}
  th {{ background:#241338; color:var(--p2); text-transform:uppercase; font-size:11px; }}
  .detail {{ color:#c4b5db; margin:4px 0; font-size:12px; }}
  a {{ color:var(--p2); word-break:break-all; }}
  .badge {{ padding:2px 8px; border-radius:6px; font-size:11px; font-weight:700; }}
  .badge.high {{ background:#7f1d1d; color:#fecaca; }}
  .badge.medium {{ background:#78350f; color:#fed7aa; }}
  .badge.low {{ background:#164e63; color:#a5f3fc; }}
  .badge.info {{ background:#312e40; color:#c7bcdb; }}
  footer {{ padding:16px 32px; color:#7a6a99; font-size:11px; }}
</style></head>
<body>
  <header>
    <h1>◆ PURPLE RECON</h1>
    <div class="meta">Target: {html.escape(result.target)} &nbsp;·&nbsp; {html.escape(result.started)}<br>
    Detected stack: {stack}</div>
  </header>
  <div class="wrap">
    <table>
      <thead><tr><th>Severity</th><th>Category</th><th>Finding</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
  <footer>Authorized assessment only. Purple Recon identifies — it does not exploit.</footer>
</body></html>"""
