# OpenVPN Connect

A small Flask control panel for the OpenVPN client on **one machine**. Start and stop the tunnel,
watch its state and traffic, see what it actually routes and resolves — from a web page you can
open on another device. It runs as a systemd service and needs root for exactly one operation.

## Why this exists

I have a headless Linux box on my home network. It has no monitor and no keyboard, and it needs a
work VPN up — which meant SSHing in every single time to run a shell script, typing an
authenticator code into a terminal, and then having no idea what the tunnel was actually doing
once it was up. Was it split or full? What was it routing? Was it eating all my DNS? The answer
to all of those was "SSH back in and go digging".

So this is a web page for that box, openable from a phone or a laptop on the same network. Nothing
here is novel; it exists because the alternative was another terminal window.

Two consequences of that origin worth knowing before you adopt it:

- **It is deliberately single-machine and single-user.** It controls the local `openvpn` binary,
  not a fleet. There is one login, no user accounts, no multi-tenancy. It should never be exposed
  to the internet — put it on your LAN or behind a VPN of its own (yes, really).
- **The design bias throughout is *report what is actually true*, not what was configured.** The
  routes panel reads the kernel's routing table, not the server's `PUSH_REPLY`. The DNS panel reads
  systemd-resolved, not the pushed options. That distinction has repeatedly been the difference
  between a panel that reassures you and one that tells you your VPN provider can see every domain
  you look up.

## Vibe-coded, on purpose

This project was written almost entirely by an AI assistant (Claude), by design, as an experiment
in how far that gets you on a real problem with real consequences — something that runs as a
service, holds credentials, and calls `sudo`. I am not going to pretend otherwise, and you should
factor it into your judgement about running it.

What I would say in its defence: the tests are real (500+, and they never touch the real system —
`subprocess.run` and the management client are injected throughout), the privilege boundary is
narrow and deliberate (one root helper, a fixed set of verbs, no caller-supplied paths or content
crossing into root), and several of the bugs found along the way were the kind that hide from
tests and turn up only when you check the running system — a `systemctl reload` that never re-read
the config, a `dnsmasq` conf-dir that loads every file it is handed. Those were caught by reading
the machine, not by reading the code.

What I would say against it: no human has line-by-line reviewed all of it, and it has one user and
one deployment. Read the code before you trust it with a credential. MIT licensed — see
[LICENSE](LICENSE) — so it is yours to fork and take in whatever direction you like.

## How it works

```
browser ──HTTP──> Flask (as you, unprivileged)
                    │
                    ├── sudo -n /usr/local/sbin/vpn-connect-helper start <profile>   ← only root op
                    │        └── openvpn --daemon --management /run/vpn-connect/mgmt.sock unix
                    │                    --management-hold --management-query-passwords
                    │
                    └── unix socket ──> management interface
                             hold release · username/password (SCRV1:<pass>:<otp>) ·
                             state · bytecount · log · signal SIGTERM
```

Only *starting* the tunnel needs root. Status, live log, byte counters and shutdown all go through
the management socket, which is unprivileged. The socket lives in `/run/vpn-connect/` (mode 0770,
group-owned by you) and OpenVPN is told `--management-client-user <you>`, so no other local account
can drive the tunnel.

**MFA is per-profile, and the profile decides.** A `static-challenge` line in the `.ovpn` is
OpenVPN's own statement that the server will ask for a second field, so that is what the app reads:
profiles that have one get a code box and the `SCRV1:<base64 password>:<base64 code>` challenge
response; profiles that do not sign in with their stored password alone and are never asked for a
code. Nothing is passed on the openvpn command line to force one or the other.

## Requirements

- **Linux with systemd** — the service is a systemd unit and the root helper uses `systemctl`.
- **OpenVPN 2.5+** — `openvpn` on `PATH`, or set `OPENVPN=/path/to/openvpn` when installing.
- **`sudo`** — for the install, and for the one root operation at runtime.
- **[uv](https://docs.astral.sh/uv/)** — Python is managed entirely by uv; there is no
  `requirements.txt` and no virtualenv to make by hand. Install it as **the user who will run the
  app**, not as root:

  ```bash
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # then restart your shell, or: source $HOME/.local/bin/env
  uv --version
  ```

  `install.sh` looks up uv as that user and refuses to continue without it. If you installed it
  somewhere unusual, pass the path: `sudo UV=/opt/uv/bin/uv ./deploy/install.sh`.
- **dnsmasq** — optional, only for the DNS panel. Without it everything else works and applying a
  DNS rule reports that dnsmasq is not running.

## Install

```bash
mkdir -p ~/.vpn                # must exist before installing; see below
uv sync

sudo ./deploy/install.sh       # asks where to listen, defaults to 127.0.0.1:5000

uv run flask --app app set-password >> ~/.vpn/webapp.env    # sets the web login password
sudo systemctl enable --now vpn-connect
```

The installer asks one question — which address to listen on — and defaults to localhost. Setting
`BIND` in the environment answers it in advance and skips the prompt entirely, which is what makes
unattended installs work:

```bash
sudo BIND=0.0.0.0 PORT=5000 ./deploy/install.sh
```

On a re-run the address already in the installed unit becomes the default, so pressing enter never
silently takes away access you had already set up.

`install.sh` puts three things on the system, and nothing else:

| Path | What |
| --- | --- |
| `/usr/local/sbin/vpn-connect-helper` | root helper: `start <profile>` / `stop` / `status` / `dns-apply` |
| `/etc/sudoers.d/vpn-connect` | NOPASSWD rule for **that helper only** |
| `/etc/systemd/system/vpn-connect.service` | the web app, running as you, one worker |

## What lives in `~/.vpn`

This directory is the app's entire state. It must exist before you install, and it belongs to you,
not to root. Nothing here is edited by hand.

| File | Mode | Written by | What it is |
| --- | --- | --- | --- |
| `vpn-connect.db` | 0600 | the app | **Everything.** Connections and their encrypted profile, username and password; DNS rules; connection history; traffic samples. `-wal` and `-shm` alongside it are SQLite's own and come and go. |
| `webapp.env` | 0600 | `install.sh`, then you | The `VPN_CONNECT_*` settings systemd loads: Flask secret, login password hash, paths. |
| `<name>.ovpn` | 0600 | the app | A **derived** file, rewritten from the database every time you save or connect. Root reads it to start the tunnel. Editing it achieves nothing — re-save the connection instead. |
| `dns-staged.conf` | 0644 | the app | Rendered dnsmasq rules, staged for the root helper to validate and install. Overwritten on every DNS change. |
| `openvpn.log` | 0600 | openvpn (root) | The tunnel's own log, which the UI tails. |
| `openvpn.pid` | 0644 | openvpn (root) | How the helper knows whether a tunnel is running. |

**Nothing here is stored in plaintext.** The VPN username, password and the profile itself are
encrypted in the database, under a key derived from your web login password. That key exists only
in memory, for as long as you are signed in — it is never written to disk, and the app cannot read
your connections while nobody is logged in. A copy of the database on its own reveals the
connection *names* and nothing else.

The practical consequence: **back up `vpn-connect.db` and `webapp.env` together, or not at all.**
The database is useless without the login password, and the hash that password is checked against
lives in the env file. Changing your password re-encrypts every stored connection in place, so a
database restored next to a *different* `webapp.env` cannot be decrypted at all.

## Remote access, and what it costs

The default is `127.0.0.1`, reachable only from the machine itself:

```bash
ssh -L 5000:localhost:5000 <host>     # then open http://localhost:5000/
```

Choosing `0.0.0.0` at install time puts the login page on every interface, so anything on your LAN
can reach it — and this panel can rewrite the machine's routing and DNS, which makes the login
password the only barrier in front of a root-equivalent tool. That is a real trade-off for being able
to open it on your phone; make it deliberately. Mitigations in place: scrypt-hashed password,
signed session cookie, per-IP lockout after 5 failures, CSRF on every state change, `POST`-only
state changes, and a restrictive CSP.

A middle option, if you run [Tailscale](https://tailscale.com/) or similar: bind the tailnet
address instead of `0.0.0.0`, and only your own devices can reach it, from anywhere.

```bash
sudo BIND=100.64.0.5 PORT=5000 ./deploy/install.sh    # your tailnet IP
```

There is no TLS, so leave `VPN_CONNECT_COOKIE_SECURE` off unless you put a reverse proxy in front.

## Configuration

Everything is `VPN_CONNECT_*` environment variables, read at startup from `~/.vpn/webapp.env`:

| Variable | Default | Purpose |
| --- | --- | --- |
| `SECRET_KEY` | random per boot | session signing; set it, or sessions drop on restart |
| `PASSWORD_HASH` | *(unset)* | web login; without it the app shows a setup page |
| `VPN_DIR` | `~/.vpn` | the state directory described above |
| `DATABASE` | `~/.vpn/vpn-connect.db` | connections, DNS rules, history, notification settings |
| `ENV_FILE` | `~/.vpn/webapp.env` | this file; read only so the deployment check can spot damage in it |
| `HELPER` | `/usr/local/sbin/vpn-connect-helper` | the root helper |
| `MGMT_SOCKET` | `/run/vpn-connect/mgmt.sock` | management socket path |
| `TUN_DEVICE` | `tun0` | the tunnel interface; its address and routes are what the UI shows |
| `STATIC_CHALLENGE` | `Enter Authenticator Code` | the label above the code box, for a profile that asks for one |
| `NTFY_SERVER` | `https://ntfy.sh` | ntfy instance; point it at a self-hosted one if you have one |
| `NOTIFY_TIMEOUT` | `5` | seconds allowed for a notification POST |
| `CONNECT_TIMEOUT` | `90` | seconds to wait for `CONNECTED` |
| `SESSION_HOURS` | `12` | login lifetime |
| `LOGIN_MAX_ATTEMPTS` / `LOGIN_LOCKOUT_SECONDS` | `5` / `300` | login throttle |
| `DNS_LEGACY_CONF` | *(unset)* | a hand-maintained dnsmasq file the DNS panel offers to import, then retires |
| `DNS_STAGING` | `~/.vpn/dns-staged.conf` | where rendered DNS rules are written for the root helper to pick up |

## Routes

The **Routes** card lists everything the tunnel installed — over a hundred prefixes on the split
tunnel this was built for, so it is a scrolling table with a filter box rather than a plain list.
Each row
shows the destination, the gateway it goes via, how many addresses the prefix covers, and its
metric.

The rows come from the **kernel routing table** (`ip -json -4 route show`), not from the server's
`PUSH_REPLY`. That is deliberate: the push says what was *offered*, `ip route` says what was
actually installed, and they diverge whenever a route is rejected, overridden by a local one, or
added by hand. Reading the kernel also means the table still works for an `unmanaged`
tunnel — one started outside this app, where there is no management connection to ask.

Two rows are tagged because they are not pushed routes:

- **on-link** — the tunnel's own subnet, attached to the device by the kernel.
- **server** — the host route to the concentrator, pinned to the *physical* NIC so the tunnel's
  own packets do not try to travel through the tunnel. It only appears once the app knows the
  server's address, which it learns from the management interface's `>STATE` line.

`ip route` needs no privileges, so this stays outside the root helper. The list is served by
`GET /api/routes` and deliberately kept off `/api/status`, which the page polls every few seconds.
The page refetches it when the tunnel changes state, and the **Refresh** button forces a re-read.

## DNS

The **DNS** card manages split-DNS rules — domain-scoped forwarders (send this domain's lookups to
a specific server, typically one only reachable once the tunnel is up) and fallback servers (tried
in order for everything else). It replaces hand-editing a file under `/etc/dnsmasq.d/`.

The app is the source of truth: every change is validated, saved to the database, then rendered
and applied immediately — there is no separate "Apply" step, so the database and the live config
cannot silently drift apart. Applying means writing `/etc/dnsmasq.d/vpn-connect.conf` and
restarting dnsmasq — *restarting*, because dnsmasq reads its configuration only at startup and
SIGHUP (what `systemctl reload` sends) explicitly does not re-read it. The previous file is kept
aside for the duration, so a set of rules dnsmasq refuses to start with is put back rather than
leaving the box with no resolver. This is done by a root helper verb, `dns-apply`, which takes
**no argument at all**: it reads
one fixed, name-resolved staging file the app already wrote, the same way `start` resolves a
profile from a name rather than accepting a path. The staged file is independently re-validated by
the helper itself before anything is installed.

If `DNS_LEGACY_CONF` points at an existing hand-maintained file (e.g.
`/etc/dnsmasq.d/examplecorp.conf`), the panel shows what it contains and offers a one-click import. The
first successful apply after that renames the legacy file to `.<name>.disabled` in the same
operation that installs the new one — one source of truth, never a window where both files define
a rule for the same domain. The leading dot is load-bearing: a conf-dir reads every file in it
whatever the extension, and only ever skips names beginning with `.`, so a plain `.disabled`
suffix would have left the retired file still in force.

`dns-apply` writes under `/etc`, which the unit's `ProtectSystem=full` read-only-mounts for the
service **and every process it spawns** — a mount namespace, not a permission check, so the
sudo'd root helper is inside it too and fails with `install: Read-only file system` despite being
root. `ReadWritePaths=-/etc/dnsmasq.d` punches out that one directory. Nothing else under `/etc`
is writable.

### Who is actually resolving what

Above the rules, the panel says which resolver answers a lookup right now. This is not cosmetic:
**OpenVPN 2.6+ applies pushed `dhcp-option DNS` itself, over D-Bus to systemd-resolved**, with no
`--up` script involved — so a client that runs no external scripts at all (see Notifications) can
still have DNS taken away from it entirely. When the server pushes a catch-all, resolved gets a
`~.` route-only domain on `tun0` and *every* lookup goes over the tunnel, dnsmasq included. The
same rules that are load-bearing on an older client are then dead weight, and nothing about a rule
itself says which case you are in.

So `GET /api/dns/status` reads **systemd-resolved** (`resolvectl --json=short status <tun>`) for
what was actually installed, the same choice the Routes table makes in reading the kernel table
rather than `PUSH_REPLY`. Four verdicts:

| Mode | Means |
| --- | --- |
| `all` | `~.` on the tunnel link — everything resolves over the VPN, the rules below are bypassed |
| `split` | the tunnel is scoped to named domains, everything else stays local — no action needed |
| `none` | the tunnel is up with no resolver of its own — the rules below are what make internal names work |
| `down` | no tunnel interface — the rules below are the whole story |

Each saved domain forwarder gets a line saying whether it is in use, redundant, or bypassed. The
pushed options are shown too when the management log still holds the `PUSH_REPLY`, but they are
only ever context: the log is a rolling 200 lines, so on a long-running tunnel that is simply
empty and the verdict does not depend on it.

### Taking DNS back — "Ignore pushed DNS"

A per-connection flag, on the connection row and in the add form. With it on, the profile is
written out with one extra line:

```
pull-filter ignore "dhcp-option DNS"
```

OpenVPN then discards the pushed DNS instead of handing it to systemd-resolved, so `tun0` gets no
resolver, everything falls back to dnsmasq, and the rules above decide what goes where. The match
is a prefix, so it covers `dhcp-option DNS6` too.

It is **a flag, not an edit to the stored profile**. The profile is the operator's own
vendor-supplied file; rewriting it on a tick could not be undone on an untick. The directive is
appended to the *derived* `.ovpn` at write time instead, which is regenerated from the database on
every connect — so the flag is the only state, turning it off genuinely reverts it, and toggling
takes effect on the next connect without re-uploading anything. A profile that already filters
pushed DNS is left alone rather than given a second identical line.

The trade: names that only resolve over the tunnel (via a domain forwarder pointed at an internal
server) stop resolving while disconnected. That is the normal split-DNS bargain.

## Notifications

The app posts to [ntfy.sh](https://ntfy.sh) when the tunnel changes state, which is how you hear
about the ~24h concentrator drop. **Three events are reported separately**, because a disconnect
you asked for and a connection that was cut are not the same news:

| Event | Title | Priority |
| --- | --- | --- |
| Tunnel came up | `VPN connected` | default |
| You pressed Disconnect | `VPN disconnected` | default |
| It dropped on its own | `VPN dropped` | **high** |

Telling the last two apart is only possible inside the app. OpenVPN's own `--down` script fires
identically whether the client was asked to stop or the server cut it off, so the earlier
hook-based version needed a marker file on disk to carry that fact across. The controller knows
directly — `disconnect()` sets a flag — so sending moved into `app/services/notifications.py` and
the marker went away. As a consequence **OpenVPN runs no external script at all**: the helper no
longer passes `--script-security`, `--up` or `--down`.

Notifications never affect the tunnel. Each one is sent fire-and-forget on its own thread with a
short timeout, and failures are logged rather than raised — losing a push is an annoyance, failing
a disconnect because a push timed out is a fault. The one exception is **Send test**, which is
synchronous and reports the error to you, because you asked for it and are waiting.

The topic and the three message bodies are editable from the **Notifications** card. An empty
topic turns notifications off; an empty body restores that body's default. Titles are fixed —
consistent titles are what make a push scannable on a lock screen, and keeping them out of
editable text means nothing operator-supplied ever reaches an HTTP header.

Bodies support four placeholders: `{ip}`, `{server}`, `{duration}` and `{time}`. They are
substituted by literal replacement, never `str.format`, so a stray brace in your text is just a
brace.

## Look and feel

Bootstrap 5.3 and the OpenVPN mark are **vendored** into `app/static/vendor/` and
`app/static/img/` — nothing is fetched from a CDN at runtime, which is what lets the CSP stay
`'self'`. The palette is OpenVPN orange on warm graphite neutrals, defined as CSS custom properties
in `app/static/css/app.css`; tunnel status has its own green/blue/red/amber scale so "in progress"
never blends into the brand colour. Light and dark are driven by `[data-bs-theme]`, which
`static/js/theme.js` sets before first paint from `localStorage` or the OS preference, and the
toggle in the header flips it.

## Tunnels this app did not start

A tunnel started outside the app — by hand, or by a shell script with a TCP management interface on
`127.0.0.1:7505` rather than the unix socket this uses — shows up in the UI as `unmanaged`. The app
can see the pid and the tun address, and can stop it, but cannot read its state or its log. Stop it
and reconnect from the UI to get full control. Use one or the other for a given session.

## Development

```bash
uv run flask --app app run --debug --port 5000     # localhost dev server
uv run pytest
uv run ruff check . && uv run ruff format .
```

Tests never touch the real system: `subprocess.run` and the management client are both injected into
`OpenVpnController`, and the argv assertions in `tests/test_openvpn.py` are the standing defence
against command-injection regressions.

## Licence

MIT — see [LICENSE](LICENSE).
