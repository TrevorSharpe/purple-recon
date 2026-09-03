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
- **CVE correlation** — detected versions → known CVEs via the NVD 2.0 API,
  each linked to its NVD detail page (which references Exploit-DB where relevant)

## Usage

```bash
pip install -r requirements.txt

python -m purplerecon example.com                 # full assessment (prompts for auth)
python -m purplerecon https://example.com -y      # skip the auth prompt
python -m purplerecon example.com --html out.html # also write a themed HTML report
python -m purplerecon example.com --no-cve        # skip NVD lookups (faster)
```

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
