# Hosting Purple Recon at your own domain

This runs the GUI permanently at something like `scanner.trevor.lol` instead of
a temporary Codespace.

## ⚠️ Read this first

Purple Recon is a scanner. **If it's reachable on the internet without
authentication, anyone who finds the URL can drive your server to scan any
target they type in** — turning your host into an attack relay tied to your IP.
So the only safe ways to host it are:

1. **Behind authentication** (basic auth at the proxy *and/or* the app's own
   `PURPLERECON_AUTH`), over HTTPS, or
2. **Not exposed at all** — bound to localhost and reached over Tailscale/VPN.

The setup below does both layers. Don't skip the auth.

## Option 1 — VPS with Caddy (auto-HTTPS + auth)

On a server you control (you've run VPS infra before, so this is familiar):

```sh
# 1. Get the code
sudo git clone https://github.com/TrevorSharpe/purple-recon /opt/purple-recon
cd /opt/purple-recon
sudo useradd -r -s /usr/sbin/nologin purplerecon || true

# 2. Virtualenv + deps + production server
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt -r requirements-deploy.txt
sudo chown -R purplerecon:purplerecon /opt/purple-recon

# 3. Run it as a service (binds to 127.0.0.1:8000 only)
sudo cp deploy/purplerecon.service /etc/systemd/system/
sudo nano /etc/systemd/system/purplerecon.service   # set PURPLERECON_AUTH=user:pass
sudo systemctl daemon-reload
sudo systemctl enable --now purplerecon

# 4. DNS: add an A record for scanner.trevor.lol -> your server IP

# 5. Caddy in front for HTTPS + auth
sudo caddy hash-password           # copy the hash it prints
sudo nano deploy/Caddyfile         # paste the hash, set your domain
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Now `https://scanner.trevor.lol` prompts for your username/password and serves
the GUI. Caddy gets a Let's Encrypt certificate automatically.

Using nginx instead? Reverse-proxy `location / { proxy_pass http://127.0.0.1:8000; }`,
add `auth_basic` with an htpasswd file, and use certbot for TLS — same shape.

## Option 2 — localhost + Tailscale (lowest risk)

Skip the public domain entirely. Run the service bound to localhost (as above,
or just `python -m purplerecon.web`), put the server on your
[Tailscale](https://tailscale.com) tailnet, and reach it from your phone at
`http://<server-tailscale-ip>:8000`. Nothing is internet-facing, so there's no
public attack surface at all. You can still layer `PURPLERECON_AUTH` on top.

## Note on scanning your own site

Hosting the tool and scanning your site are independent — you can point *any*
install (local, Codespace, or this hosted one) at `trevor.lol` or your other
domains. The tool only assesses; fixes are yours to apply (see the header
snippet your scan suggested).
