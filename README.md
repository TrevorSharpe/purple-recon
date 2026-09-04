# ◆ Purple Recon

A non-destructive **web vulnerability assessment** scanner. It fingerprints a
target, audits its security posture, and correlates detected software against
the [NVD](https://nvd.nist.gov/) — then hands you the findings with references.

It **identifies** attack surface and known vulnerabilities. It does **not**
exploit anything. There is deliberately no payload delivery, no exploit
execution, and no auto-pwn. Findings are for a human to investigate under
proper authorization.

## What it checks

- **Recon & fingerprinting** — server, `X-Powered-By`, framework/CMS detection
- **Security header audit** — HSTS, CSP, X-Frame-Options, nosniff, Referrer-Policy
- **TLS inspection** — protocol version, cipher, certificate expiry
- **Exposure discovery** — common accidentally-exposed paths (`.git`, `.env`,
  `server-status`, backups…) via non-destructive `GET` requests
- **SQL surface (passive)** — flags pages that leak raw database errors, and
  inventories where user input enters (query params, form fields) so you can
  review them for parameterized queries. No payloads are sent; active injection
  testing is intentionally out of scope (use sqlmap / OWASP ZAP under your own
  authorization for that).
- **CVE correlation** — detected versions → known CVEs via the NVD 2.0 API,
  each linked to its NVD detail page (which references Exploit-DB where relevant)

Every finding carries the **URL where it was observed** — the exact file URL
for an exposed resource, or the fingerprinted endpoint where a vulnerable
version/header was seen. Findings without a location are excluded from the
report. (For CVEs the location is where the vulnerable version was *detected*,
not a crafted exploit URL.)

## Usage

```bash
pip install -r requirements.txt

python -m purplerecon example.com                  # full assessment (prompts for auth)
python -m purplerecon https://example.com -y       # skip the auth prompt
python -m purplerecon example.com --html out.html  # themed HTML report
python -m purplerecon example.com --json out.json  # machine-readable JSON
python -m purplerecon example.com --sarif out.sarif # SARIF 2.1.0 for CI/code-scanning
python -m purplerecon example.com --no-cve -q      # skip NVD lookups, suppress terminal
python -m purplerecon example.com --crawl          # crawl the whole site (same host) and scan every page
python -m purplerecon example.com --crawl --max-pages 50
```

The **SARIF** output drops into GitHub code-scanning, Azure DevOps, and most
CI security dashboards; **JSON** is easy to pipe into ticketing or custom tooling.


## Web GUI

Prefer typing a URL into a page? Run the local GUI:

```bash
python -m purplerecon.web        # then open http://127.0.0.1:8000
python -m purplerecon.web --port 9000
```

It serves a purple console where you enter a target, tick the authorization
box, and scan — the results render inline with the same impact / exposed /
fix / found-at breakdown. It binds to localhost only, so the scanner isn't
exposed to your network. The page is responsive and works on a phone.

**On iPhone?** See [MOBILE.md](MOBILE.md) — run it on-device with iSH, or run
it on another machine and reach it privately from the phone.

**No install at all?** See [CODESPACES.md](CODESPACES.md) — run it in a GitHub
Codespace and open the forwarded URL in any browser, including your phone.

**Host it at your own domain?** See [DEPLOY.md](DEPLOY.md) — self-host behind
HTTPS + auth, or keep it private over Tailscale. (Never expose a scanner unauthenticated.)


## Speed

The scan is built to feel instant: the target's headers, TLS, fingerprint, and
exposed-path checks all run over one reused connection in parallel, so the main
results come back in well under a second on a normal connection. The CVE lookup
(the one slow part, since it queries the NVD) runs as a separate phase — in the
GUI the findings render first and CVEs stream in after, and results are cached
for 7 days so repeat scans of the same software are instant.

Inside iSH the x86 emulation adds overhead; for the snappiest experience run the
server on a real machine and browse to it from the phone (see MOBILE.md).

## ⚠️ Authorized use only

Only scan systems you **own** or have **explicit written permission** to test.
Unauthorized scanning may be illegal. The tool asks you to confirm authorization
before it runs, sends a low, polite request rate, and never attempts to gain
access or modify anything on the target.

## Roadmap ideas

- CPE-based matching for more precise CVE correlation
- Pluggable check modules
- JSON/SARIF output for pipeline integration
- Optional `nmap`/`nuclei` handoff for deeper (still-authorized) testing

## License

MIT — see `LICENSE`.
