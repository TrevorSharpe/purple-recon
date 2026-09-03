# Run Purple Recon in your browser (GitHub Codespaces)

You can run the whole thing from a browser — no local install — using a
**Codespace**, a Linux machine GitHub runs for you in the cloud. This repo ships
a devcontainer, so a Codespace sets itself up automatically.

GitHub **Pages won't work** for this: it only serves static files and can't run
the Python server or do the socket/TLS checks. Codespaces runs real Python, so
it can.

## Steps

1. On the repo page, click the green **Code** button → **Codespaces** tab →
   **Create codespace on main**.
2. Wait for it to build. The devcontainer runs `pip install -r requirements.txt`
   for you.
3. In the Codespace terminal, start the GUI bound to all interfaces (so the port
   forwarder can reach it):
   ```sh
   python -m purplerecon.web --host 0.0.0.0
   ```
4. GitHub auto-forwards port 8000 and pops a browser tab (and shows it in the
   **Ports** tab). The URL looks like `https://<name>-8000.app.github.dev`.
5. Open that URL on your phone or any browser **where you're signed into your
   GitHub account** — the forwarded port is private to you by default, so being
   signed in is what grants access.

## Keep in mind

- **Leave the port private.** Don't switch it to Public in the Ports tab — this
  is a scanner, and a public URL would let anyone drive it.
- **Scans run from GitHub's network**, not your phone or home connection. That's
  fine for your own sites. GitHub's Acceptable Use terms — like this tool's own
  rule — mean you should only scan systems you own or are authorized to test.
- **Free allowance:** personal accounts include a monthly pool of free Codespace
  hours (60 core-hours at the time of writing); the Codespace also auto-stops
  after a period of inactivity, so it won't quietly burn the pool.
- This is the same mobile-friendly page as everything else — it just happens to
  be served from a Codespace instead of your machine.
