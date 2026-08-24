#!/usr/bin/env python
"""Regenerate every screenshot in ``docs/screenshots`` from invented data.

Never hand-edit a screenshot, for the same reason ``tools/generate-icons.py`` exists: an image
that cannot be regenerated is an image that quietly stops matching the thing it claims to show.
This script serves the real app -- real templates, real CSS, real JavaScript, real endpoints --
and photographs it.

**Nothing here touches this machine.** The tunnel is a stub, the routing table is invented, the
resolver is canned, and the database is a throwaway under ``/tmp``. Every address comes from a
documentation range (RFC 5737, RFC 3849) and every name is an ``example.*`` one, because a
screenshot is a *published* artefact: the same reason this repository's own notes are kept out of
git is the reason a real concentrator's name must never end up in a picture of the UI.

Usage::

    uv run --group screenshots python tools/screenshots.py
    uv run --group screenshots python tools/screenshots.py --keep-serving   # to look yourself

It drives the Google Chrome already installed on the machine rather than downloading a browser.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import create_app  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.config import Config  # noqa: E402
from app.db import open_migrated  # noqa: E402
from app.services import store, vault  # noqa: E402
from app.services.connections import Connections  # noqa: E402
from app.services.dns_rules import DnsRules  # noqa: E402
from app.services.firewall import SETTING as FIREWALL_SETTING  # noqa: E402
from app.services.firewall import Firewall  # noqa: E402
from app.services.history import History  # noqa: E402
from app.services.openvpn import VpnStatus  # noqa: E402
from app.services.routing import Route  # noqa: E402
from app.services.scope import FamilyScope, TunnelScope  # noqa: E402
from app.services.whois import WhoisResult  # noqa: E402

#: The password the screenshot session signs in with. It protects a database that is deleted
#: thirty seconds later and never leaves /tmp.
PASSWORD = "screenshot-demo-password"

PORT = 5099
#: A second instance, with no password configured, so the setup page can be photographed too.
#: It cannot be the same one: that page exists precisely when the app has nothing to sign in to.
SETUP_PORT = 5100
OUT = ROOT / "docs" / "screenshots"

#: Documentation ranges, in the two roles a split tunnel actually has: the operator's own private
#: space, and the public blocks a corporate VPN so often also pulls in.
TUN_IP = "10.20.30.40"
SERVER_IP = "198.51.100.20"


LIVE_SERIES: list[tuple[float, int, int]] = []


class StubController:
    """A tunnel that is up, and stays up, and is not on this machine.

    Same surface the API blueprint uses (``snapshot``/``routes``/``scope``/``whois``), so the
    pictures come out of the real endpoints rather than out of fixtures pasted into the page.
    """

    def __init__(self) -> None:
        self.status = VpnStatus(
            state="connected",
            openvpn_state="CONNECTED",
            detail="Tunnel established.",
            profile="acme-vpn",
            tun_ip=TUN_IP,
            remote_ip=SERVER_IP,
            connected_since=time.time() - 8 * 3600 - 41 * 60,
            # The same totals the traffic panel will draw from the samples below.
            bytes_in=LIVE_SERIES[-1][1],
            bytes_out=LIVE_SERIES[-1][2],
            pid=4821,
            log_lines=[
                f"TCPv4_CLIENT link remote: [AF_INET]{SERVER_IP}:1194",
                "VERIFY OK: depth=1, CN=Example Corp Issuing CA",
                "VERIFY OK: depth=0, CN=vpn.example.com",
                "Control Channel: TLSv1.3, cipher TLSv1.3 TLS_AES_256_GCM_SHA384",
                f"[vpn.example.com] Peer Connection Initiated with [AF_INET]{SERVER_IP}:1194",
                "SENT CONTROL [vpn.example.com]: 'PUSH_REQUEST' (status=1)",
                # Nine routes pushed, six of them in route_list below -- so the picture shows a
                # real three-row "pushed but not installed" table rather than a contrived one.
                "PUSH: Received control message: 'PUSH_REPLY,route 10.20.0.0 255.255.0.0,"
                "route 10.40.0.0 255.252.0.0,route 172.20.0.0 255.252.0.0,"
                "route 52.94.0.0 255.255.0.0,route 13.107.6.0 255.255.255.0,"
                "route 162.159.0.0 255.255.0.0,route 192.168.30.0 255.255.255.0,"
                "route 172.31.12.0 255.255.252.0,route 10.60.0.0 255.255.0.0 vpn_gateway 500,"
                "dhcp-option DNS 10.20.0.53,route-gateway 10.20.30.1,"
                f"ifconfig {TUN_IP} 255.255.254.0'",
                "OPTIONS IMPORT: route options modified",
                "net_addr_v4_add: 10.20.30.40/23 dev tun0",
                "ERROR: Linux route add command failed: external program exited with error "
                "status: 2",
                "Initialization Sequence Completed",
            ],
        )
        self.route_list = [
            Route("10.20.0.0/16", "10.20.30.1", "tun0", 101),
            Route("10.40.0.0/14", "10.20.30.1", "tun0", 101),
            Route("172.20.0.0/14", "10.20.30.1", "tun0", 101),
            # Real, allocated blocks with their real owners. Documentation ranges (192.0.2.0/24
            # and friends) are *reserved*, which the app correctly declines to call public -- so
            # using them here would produce a screenshot with the owner column permanently empty,
            # which is precisely the thing the column exists to show.
            Route("52.94.0.0/16", "10.20.30.1", "tun0", 101),
            Route("13.107.6.0/24", "10.20.30.1", "tun0", 101),
            Route("162.159.0.0/16", "10.20.30.1", "tun0", 101),
            Route("10.20.30.0/23", None, "tun0", None, kind="on-link"),
            Route(f"{SERVER_IP}/32", "192.168.1.1", "enp5s0", 100, kind="bypass"),
        ]
        #: What a whois lookup would return for the public prefixes above. Invented owners for
        #: invented ranges -- the point of the column is that the panel *has* one.
        self.whois_orgs = {
            "52.94.0.0/16": "Amazon.com, Inc.",
            "13.107.6.0/24": "Microsoft Corporation",
            "162.159.0.0/16": "Cloudflare, Inc.",
        }
        self.tunnel_scope = TunnelScope(
            device="tun0",
            ipv4=FamilyScope(
                family=4,
                mode="split",
                coverage=0.0041,
                prefixes=6,
                blocks=6,
                default_via_tunnel=False,
                redirect_pair=False,
                egress_device="enp5s0",
                public_prefixes=3,
                public_blocks=3,
                public_coverage=0.00009,
            ),
            ipv6=FamilyScope(
                family=6,
                mode="none",
                coverage=0.0,
                prefixes=0,
                blocks=0,
                default_via_tunnel=False,
                redirect_pair=False,
                egress_device="enp5s0",
            ),
        )

    def snapshot(self) -> VpnStatus:
        return self.status

    def recent_events(self, limit: int = 10) -> list[str]:
        now = datetime.now().astimezone()

        def stamp(**delta) -> str:
            return (now - timedelta(**delta)).isoformat(timespec="seconds")

        return [
            f"{stamp(hours=8, minutes=41)} UP",
            f"{stamp(hours=9, minutes=2)} DOWN link-lost",
            f"{stamp(days=1, hours=3)} UP",
            f"{stamp(days=1, hours=15)} DOWN operator-requested",
            f"{stamp(days=2, hours=1)} UP",
        ][:limit]

    def routes(self) -> list[Route]:
        return list(self.route_list)

    def pushed(self, installed: list[Route] | None = None):
        """Run the real comparison over the canned push, so the table is not hand-written."""
        from app.services.pushed import find_reply
        from app.services.pushed import report as push_report

        lines = self.status.log_lines
        return push_report(
            find_reply(lines), self.route_list if installed is None else installed, lines
        )

    def scope(self) -> TunnelScope:
        return self.tunnel_scope

    def whois(self, destinations: list[str]) -> list[WhoisResult]:
        return [WhoisResult(destination=d, org=self.whois_orgs.get(d)) for d in destinations]

    def connect(self, profile: str, otp: str) -> None:  # pragma: no cover - never clicked
        raise AssertionError("the screenshot instance does not connect anything")

    def disconnect(self) -> None:  # pragma: no cover - never clicked
        raise AssertionError("the screenshot instance does not disconnect anything")

    def attach(self) -> None:  # pragma: no cover
        raise AssertionError("the screenshot instance must not touch the system")


class StubResolvectl:
    """Canned ``resolvectl --json=short status tun0``: the tunnel resolves its own domains only.

    Which is the arrangement the DNS panel is *for* -- a tunnel that has taken every lookup makes
    a duller picture and a worse example.
    """

    def __call__(self, argv, **kwargs):
        import subprocess

        link = [
            {
                "servers": [{"addressString": "10.20.0.53"}],
                "searchDomains": [
                    {"name": "acme.example", "routeOnly": True},
                    {"name": "corp.acme.example", "routeOnly": True},
                ],
                "defaultRoute": False,
            }
        ]
        return subprocess.CompletedProcess(argv, 0, json.dumps(link), "")


#: A realistic-looking day of throughput: a busy morning, a quiet lunch, a big afternoon
#: download. Cumulative counters, exactly as OpenVPN reports them, because that is what the
#: traffic panel differentiates on read.
def traffic_series(samples: int = 900) -> list[tuple[float, int, int]]:
    import math
    import random

    random.seed(20260822)  # the same picture every time it is regenerated
    now = time.time()
    step = 35.0
    rx = rx_total = 0
    tx = tx_total = 0
    series = []
    for index in range(samples):
        phase = index / samples
        busy = 0.25 + 0.75 * abs(math.sin(phase * math.pi * 2.4))
        burst = 6.0 if 0.62 < phase < 0.78 else 1.0
        rx = int(320_000 * busy * burst * random.uniform(0.6, 1.4))
        tx = int(38_000 * busy * random.uniform(0.5, 1.6))
        rx_total += rx
        tx_total += tx
        series.append((now - (samples - index) * step, rx_total, tx_total))
    return series


def seed(tmp: Path) -> tuple:
    """Build a whole plausible installation in a throwaway directory."""
    vpn_dir = tmp / "vpn"
    vpn_dir.mkdir()
    config = replace(
        Config(),
        SECRET_KEY="screenshot-secret",
        PASSWORD_HASH=hash_password(PASSWORD),
        VPN_DIR=vpn_dir,
        HELPER=tmp / "helper-that-does-not-exist",
        MGMT_SOCKET=tmp / "socket-that-does-not-exist",
    )  # the database follows VPN_DIR, so it lands in the throwaway directory too
    db = open_migrated(config.database)

    state = vault.VaultState()
    state.store(vault.initialise(db, PASSWORD))
    connections = Connections(db, state, vpn_dir)
    connections.save(
        name="acme-vpn",
        label="Acme Corp (work)",
        profile=(
            "client\nremote vpn.example.com 1194 udp\nauth-user-pass\n"
            'static-challenge "Enter Authenticator Code" 1\n'
        ),
        username="a.stone",
        password="not-a-real-password",
        make_default=True,
    )
    connections.save(
        name="home-lab",
        label="Home lab",
        profile="client\nremote vpn.example.net 1194 udp\nauth-user-pass\n",
        username="phil",
        password="not-a-real-password",
    )

    history = History(db)
    _seed_history(db, history)

    store.save_notify(db, topic="acme-vpn-a7f3c1")
    # Switched on, so the panel photographs a coherent state: the switch and the badge agreeing
    # that the tunnel's inbound traffic is being blocked.
    store.set_setting(db, FIREWALL_SETTING, "1")

    rules = DnsRules(db, config, runner=StubResolvectl())
    rules.add(kind="domain", domain="acme.example", address="10.20.0.53")
    rules.add(kind="domain", domain="corp.acme.example", address="10.20.0.53")
    rules.add(kind="fallback", domain=None, address="1.1.1.1")
    rules.add(kind="fallback", domain=None, address="9.9.9.9")

    return config, db, connections, history, rules


def _seed_history(db, history: History) -> None:
    """A week of attempts: two clean days, a flaky evening, one mistyped code."""
    now = datetime.now().astimezone()

    def ago(**delta) -> str:
        return (now - timedelta(**delta)).isoformat(timespec="seconds")

    plan = [
        # (connection, started, connected, ended, outcome, reason, MB in, MB out)
        (
            "acme-vpn",
            ago(days=6, hours=9),
            ago(days=6, hours=9),
            ago(days=6, hours=1),
            "disconnected",
            "operator-requested",
            8_100,
            640,
        ),
        (
            "acme-vpn",
            ago(days=5, hours=9),
            ago(days=5, hours=9),
            ago(days=4, hours=22),
            "disconnected",
            "link-lost",
            11_400,
            900,
        ),
        (
            "acme-vpn",
            ago(days=4, hours=9),
            ago(days=4, hours=9),
            ago(days=4, hours=1),
            "disconnected",
            "operator-requested",
            7_300,
            520,
        ),
        ("home-lab", ago(days=3, hours=20), None, ago(days=3, hours=20), "failed", "", 0, 0),
        (
            "home-lab",
            ago(days=3, hours=20),
            ago(days=3, hours=20),
            ago(days=3, hours=18),
            "disconnected",
            "operator-requested",
            240,
            190,
        ),
        (
            "acme-vpn",
            ago(days=2, hours=9),
            ago(days=2, hours=9),
            ago(days=2, hours=7),
            "disconnected",
            "link-lost",
            2_900,
            210,
        ),
        (
            "acme-vpn",
            ago(days=2, hours=7),
            ago(days=2, hours=7),
            ago(days=2, hours=6),
            "disconnected",
            "link-lost",
            1_050,
            88,
        ),
        (
            "acme-vpn",
            ago(days=2, hours=6),
            ago(days=2, hours=6),
            ago(days=1, hours=22),
            "disconnected",
            "operator-requested",
            6_600,
            470,
        ),
    ]
    for connection, started, connected, ended, outcome, reason, mb_in, mb_out in plan:
        history.start_session(connection)
        session = history.session_id
        if connected:
            history.mark_connected()
            store.record_sample(db, session, time.time(), mb_in * 1_000_000, mb_out * 1_000_000)
        for line in _attempt_log(connection, failed=connected is None):
            history.append(line)
        history.end_session(outcome, reason)
        db.execute(
            "UPDATE sessions SET started_at = ?, connected_at = ?, ended_at = ? WHERE id = ?",
            (started, connected, ended, session),
        )
        db.commit()

    # The attempt that is running now, and the series the traffic panel draws.
    history.start_session("acme-vpn")
    history.mark_connected()
    live = history.session_id
    for at, rx, tx in LIVE_SERIES:
        store.record_sample(db, live, at, rx, tx)
    db.execute(
        "UPDATE sessions SET started_at = ?, connected_at = ? WHERE id = ?",
        (
            (now - timedelta(hours=8, minutes=41)).isoformat(timespec="seconds"),
            (now - timedelta(hours=8, minutes=41)).isoformat(timespec="seconds"),
            live,
        ),
    )
    db.commit()


def _attempt_log(connection: str, *, failed: bool) -> list[str]:
    host = "vpn.example.com" if connection == "acme-vpn" else "vpn.example.net"
    if failed:
        return [
            f"TCPv4_CLIENT link remote: [AF_INET]{SERVER_IP}:1194",
            f"[{host}] Peer Connection Initiated",
            "SENT CONTROL: 'PUSH_REQUEST' (status=1)",
            "AUTH: Received control message: AUTH_FAILED",
            "SIGTERM[soft,auth-failure] received, process exiting",
        ]
    return [
        f"TCPv4_CLIENT link remote: [AF_INET]{SERVER_IP}:1194",
        "VERIFY OK: depth=0, CN=" + host,
        f"[{host}] Peer Connection Initiated",
        "OPTIONS IMPORT: route options modified",
        "Initialization Sequence Completed",
    ]


class StubHelperRunner:
    """Answers the firewall helper without a helper, so nothing here can reach sudo.

    Left unpinned, ``create_app`` would build a Firewall around the real ``subprocess.run`` and
    this script -- whose entire promise is that it touches no real system -- would start shelling
    out to sudo on whatever machine is taking the pictures. The drop count is invented like every
    other number in these screenshots.
    """

    def __call__(self, argv, **_kwargs):
        class Result:
            returncode = 0
            stdout = "armed 1284 96"
            stderr = ""

        return Result()


def build(config, db, connections, history, rules, source_root: Path):
    return create_app(
        {
            "APP_CONFIG": config,
            "CONTROLLER": StubController(),
            "DB": db,
            "VAULT": None,  # replaced below, once create_app has built its own
            "CONNECTIONS": connections,
            "HISTORY": history,
            "DNS_RULES": rules,
            "FIREWALL": Firewall(db, config, runner=StubHelperRunner()),
            "SOURCE_ROOT": source_root,
            "STARTED_AT": time.time() + 3600,
            "TESTING": True,
        }
    )


def instance(tmp: Path):
    """Stand the whole seeded installation up in one call, and hand back the Flask app.

    Both consumers of this module need the same four steps in the same order, and one of them is
    an ordering trap: ``StubController`` reads ``LIVE_SERIES[-1]`` at construction, so the series
    has to exist *before* the app is built. Doing it here means neither caller can get it wrong.
    """
    if not LIVE_SERIES:
        LIVE_SERIES.extend(traffic_series())
    config, db, connections, history, rules = seed(tmp)
    app = build(config, db, connections, history, rules, source_root=tmp / "vpn")
    # The vault has to be the one the seeding used, or the connections cannot be decrypted.
    app.config["VAULT"] = _vault_of(connections)
    return app


def build_unconfigured(tmp: Path):
    """A second app with **no login password**, which is the whole state being photographed.

    A fresh install looks like this: the database exists because migrations ran, and nothing else
    does -- no vault, no connections, nobody who can sign in.
    """
    vpn_dir = tmp / "fresh"
    vpn_dir.mkdir()
    config = replace(
        Config(),
        SECRET_KEY="screenshot-secret",
        PASSWORD_HASH="",
        VPN_DIR=vpn_dir,
        HELPER=tmp / "helper-that-does-not-exist",
        MGMT_SOCKET=tmp / "socket-that-does-not-exist",
    )
    db = open_migrated(config.database)
    state = vault.VaultState()
    return create_app(
        {
            "APP_CONFIG": config,
            "CONTROLLER": StubController(),
            "DB": db,
            "VAULT": state,
            "CONNECTIONS": Connections(db, state, vpn_dir),
            "HISTORY": History(db),
            "DNS_RULES": DnsRules(db, config, runner=StubResolvectl()),
            "FIREWALL": Firewall(db, config, runner=StubHelperRunner()),
            "SOURCE_ROOT": vpn_dir,
            "STARTED_AT": time.time() + 3600,
            "TESTING": True,
        }
    )


def serve(app, port: int = PORT):
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", port, app, threaded=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


# --- the photographs --------------------------------------------------------
#
# Panels are opened one at a time and photographed as *elements*, not as slices of a page: the
# card is the unit somebody is being shown, and cropping by coordinates would need redoing every
# time a card above it changed height.

PANELS = [
    ("connections", "#panel-connections", "#connections-body tr td"),
    ("traffic", "#panel-traffic", "#traffic-chart path"),
    ("session-history", "#panel-sessions", "#sessions-body .session-row"),
    ("scope", "#panel-scope", "#scope-verdict"),
    ("routes", "#panel-routes", "#routes-body tr td"),
    ("dns", "#panel-dns", "#dns-domain-body tr td"),
    ("firewall", "#panel-firewall", "#fw-toggle"),
    ("notifications", "#panel-notifications", "#ntfy-topic"),
]


def capture(out: Path) -> None:
    from playwright.sync_api import sync_playwright

    out.mkdir(parents=True, exist_ok=True)
    base = f"http://127.0.0.1:{PORT}"

    with sync_playwright() as driver:
        browser = driver.chromium.launch(channel="chrome")
        page = browser.new_context(
            viewport={"width": 1280, "height": 900},
            device_scale_factor=2,  # crisp on the displays people actually read a README on
            color_scheme="light",
        ).new_page()

        page.goto(f"{base}/login")
        page.wait_for_selector("#password")
        page.screenshot(path=out / "login.png")

        # The other thing /login can be: a fresh install with no password set yet. Served by the
        # second instance, since one app cannot be both configured and not.
        page.goto(f"http://127.0.0.1:{SETUP_PORT}/login")
        page.wait_for_selector("pre.code")
        page.screenshot(path=out / "setup.png")
        page.goto(f"{base}/login")
        page.wait_for_selector("#password")

        page.fill("#password", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_selector("#status-card[data-state=connected]")
        page.wait_for_timeout(900)  # let the first status poll settle the facts and the log

        _shot_top(page, out / "connected.png")

        for name, panel, ready in PANELS:
            _open(page, panel, ready)
            page.locator(f"section:has({panel})").screenshot(path=out / f"{name}.png")
            _close(page, panel)

        # The rejected table gets its own close-up. Inside the routes section it sits under a
        # 300px scroll box, so at section width the thing being explained is a strip at the
        # bottom of the picture.
        _open(page, "#panel-routes", "#routes-rejected-body tr")
        page.locator("#routes-rejected").screenshot(path=out / "routes-rejected.png")
        _close(page, "#panel-routes")

        # The two things a still image of a table cannot show: that a row opens its own log, and
        # that the search narrows by how a session ended rather than by date.
        _open(page, "#panel-sessions", "#sessions-body .session-row")
        page.locator("tr.session-row", has_text="FAILED").first.click()
        page.wait_for_selector(".session-log-row pre:not(:text('Loading log'))")
        page.wait_for_timeout(300)
        page.locator("section:has(#panel-sessions)").screenshot(path=out / "session-log.png")

        page.fill("#sessions-search", "dropped")
        page.wait_for_timeout(900)  # the debounce, then the request
        page.locator("section:has(#panel-sessions)").screenshot(path=out / "session-search.png")
        page.fill("#sessions-search", "")
        page.wait_for_timeout(600)
        _close(page, "#panel-sessions")

        _open(page, "#panel-log", "#log")
        page.locator("section:has(#panel-log)").screenshot(path=out / "log.png")
        _close(page, "#panel-log")

        _open(page, "#panel-events", "#events li")
        page.locator("section:has(#panel-events)").screenshot(path=out / "events.png")
        _close(page, "#panel-events")

        page.emulate_media(color_scheme="dark")
        page.evaluate("window.vpnTheme.toggle()")  # from the light default, this lands on dark
        page.wait_for_timeout(400)
        page.evaluate("window.scrollTo(0, 0)")
        _shot_top(page, out / "connected-dark.png")

        browser.close()


def _shot_top(page, path: Path) -> None:
    """The two cards above the fold, as one wide image."""
    first = page.locator("section:has(#status-card)").bounding_box()
    second = page.locator("section:has(#connect-form)").bounding_box()
    page.screenshot(
        path=path,
        clip={
            "x": first["x"],
            "y": first["y"],
            "width": second["x"] + second["width"] - first["x"],
            "height": max(first["height"], second["height"]),
        },
    )


def _open(page, panel: str, ready: str) -> None:
    if not page.locator(panel).evaluate("el => el.classList.contains('show')"):
        page.click(f"[data-bs-target='{panel}']")
    page.wait_for_selector(f"{panel}.show", state="attached")
    page.wait_for_selector(ready, timeout=10_000)
    page.wait_for_timeout(600)  # the collapse animation, and any lookup the panel kicked off


def _close(page, panel: str) -> None:
    page.click(f"[data-bs-target='{panel}']")
    page.wait_for_timeout(400)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUT, help="where the images go")
    parser.add_argument(
        "--keep-serving",
        action="store_true",
        help="leave the seeded instance running afterwards so you can look at it yourself",
    )
    args = parser.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="vpn-connect-shots-"))
    try:
        serve(instance(tmp))
        serve(build_unconfigured(tmp), SETUP_PORT)
        print(
            f"serving the seeded instance on http://127.0.0.1:{PORT}"
            f" and a fresh one on http://127.0.0.1:{SETUP_PORT}",
            file=sys.stderr,
        )
        capture(args.out)
        for image in sorted(args.out.glob("*.png")):
            print(f"  {image.relative_to(ROOT)}  {image.stat().st_size // 1024} KB")
        if args.keep_serving:
            print(f"still serving; sign in with {PASSWORD!r}. Ctrl-C to stop.", file=sys.stderr)
            threading.Event().wait()
    finally:
        if not args.keep_serving:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


def _vault_of(connections: Connections):
    return connections._vault  # noqa: SLF001 - the seeding side of the same object


if __name__ == "__main__":
    raise SystemExit(main())
