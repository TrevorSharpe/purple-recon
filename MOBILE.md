# Running Purple Recon on iPhone

The page needs a Python server behind it (the scan opens TLS sockets and queries
the NVD — Safari can't do that on its own). So "on the iPhone" means running
Python on the phone. Two routes, depending on whether you want it fully
on-device or just reachable from your phone.

## Option A — fully on-device with iSH (free)

[iSH](https://ish.app) is a small Alpine Linux shell for iOS.

1. Install **iSH Shell** from the App Store and open it.
2. Install Python, Flask, requests, and git from Alpine's prebuilt packages
   (this avoids needing a C compiler on the phone):
   ```sh
   apk update
   apk add python3 py3-flask py3-requests git
   ```
3. Get the code and run the GUI:
   ```sh
   git clone https://github.com/TrevorSharpe/purple-recon
   cd purple-recon
   python3 -m purplerecon.web
   ```
   When iSH asks to *find and connect to devices on your local network*, tap
   **OK** — that permission is what makes `localhost` work.
4. Open **Safari** and go to `http://localhost:8000`.
5. Optional: Share → **Add to Home Screen** to launch it full-screen like an app
   (the page is set up as a home-screen web app).

Notes:
- iSH emulates x86, so scans — especially CVE lookups — run slower than on a
  laptop. Fine for a target or two; not a bulk scanner.
- Keep iSH in the foreground while a scan runs; iOS suspends backgrounded apps.
- If `py3-flask` is unavailable, fall back to
  `apk add py3-pip` then `pip install -r requirements.txt --break-system-packages`.

## Option B — run it elsewhere, use it from your phone (smoother)

Since the page is now mobile-friendly, the easiest day-to-day setup is to run
the server on a machine you already have — your VPS, a home box, or your Mac —
and just browse to it from the iPhone:

```sh
python -m purplerecon.web --host 0.0.0.0 --port 8000
```

Then open `http://<that-machine-ip>:8000` on the phone.

Because this is a scanning tool, **don't expose it to the public internet.**
The clean way to reach it privately is [Tailscale](https://tailscale.com):
put the phone and the host on the same tailnet and hit the host's Tailscale IP.
No router ports opened, nothing internet-facing.

## Pythonista (paid alternative)

Pythonista (App Store, paid) bundles a native Python runtime and can run Flask.
Drop the `purplerecon` folder into Pythonista, run `web.py`, and open
`http://localhost:8000` in Safari. Handy if you already own it; otherwise iSH
covers the free case.
