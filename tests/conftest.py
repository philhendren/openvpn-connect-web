from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path

import pytest

from app import auth, create_app
from app.auth import hash_password
from app.config import Config
from app.db import open_migrated
from app.services import store, vault
from app.services.clients import Clients
from app.services.connections import Connections
from app.services.dns_rules import DnsRules
from app.services.history import History
from app.services.openvpn import OpenVpnController, VpnStatus
from app.services.routing import Route

PASSWORD = "correct-horse-battery-staple"


#: scrypt is deliberately expensive, and this suite pays that price constantly: most fixtures hash
#: a login password and unlock a vault, so the production parameters cost roughly a tenth of a
#: second per test and around a minute across the run -- all of it spent proving that a key
#: derivation function is slow, which is not what any of these tests are about.
#:
#: So the whole session runs with cheap parameters. Nothing about correctness changes: scrypt
#: derives the same *shape* of key either way, and the tests that matter here are about which key
#: is used and when. The production values live beside these as ``*_PRODUCTION`` constants that
#: nothing patches, and ``test_vault.py`` asserts they have not moved -- so this shortcut cannot
#: leak into a real install without failing the suite.
@pytest.fixture(scope="session", autouse=True)
def cheap_key_derivation():
    """Run the suite with scrypt parameters chosen for speed, not for resisting an attacker."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(vault, "SCRYPT_N", 2**10)
        patch.setattr(auth, "PASSWORD_HASH_METHOD", "scrypt:1024:8:1")
        yield


def wait_for(predicate, timeout: float = 3.0, interval: float = 0.01) -> bool:
    """Poll ``predicate`` until it is true or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


class FakeClient:
    """Stands in for ManagementClient; records commands and can push events back."""

    instances: list[FakeClient] = []

    def __init__(self, socket_path, on_event=None, **_kwargs) -> None:
        self.socket_path = socket_path
        self.on_event = on_event or (lambda kind, payload: None)
        self.commands: list[str] = []
        self._open = False
        FakeClient.instances.append(self)

    @classmethod
    def reset(cls) -> None:
        cls.instances = []

    @classmethod
    def latest(cls) -> FakeClient:
        assert cls.instances, "no management client was opened"
        return cls.instances[-1]

    @property
    def is_open(self) -> bool:
        return self._open

    def connect(self, timeout: float = 5.0) -> None:
        self._open = True

    def close(self) -> None:
        self._open = False

    def command(self, line: str, timeout: float = 10.0) -> list[str]:
        self.commands.append(line)
        return []

    def send_credentials(self, realm: str, username: str, secret: str) -> None:
        self.commands.append(f'username "{realm}" "{username}"')
        self.commands.append(f'password "{realm}" "{secret}"')

    def emit(self, kind: str, payload: str) -> None:
        self.on_event(kind, payload)


class FakeRunner:
    """Replacement for subprocess.run that records argv and never executes anything."""

    def __init__(self, returncode: int = 0, stdout: str = "started", stderr: str = "") -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.side_effect: Exception | None = None

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        if self.side_effect is not None:
            raise self.side_effect
        if argv[:1] == ["ip"]:
            if "route" in argv:
                return _Completed(0, ROUTE_JSON, "")
            return _Completed(0, "tun0 UNKNOWN 10.99.0.177/23\n", "")
        return _Completed(self.returncode, self.stdout, self.stderr)


#: The shape of a real ``ip -json -4 route show`` on a split tunnel, with the addresses replaced:
#: a couple of pushed routes, the tunnel's own subnet, the server bypass route on the physical
#: NIC, and unrelated local routes that must be filtered out.
ROUTE_JSON = json.dumps(
    [
        {
            "dst": "default",
            "gateway": "192.168.4.1",
            "dev": "eno1",
            "protocol": "dhcp",
            "metric": 100,
        },
        {"dst": "10.100.0.0/18", "gateway": "10.99.0.1", "dev": "tun0", "metric": 101},
        {"dst": "5.20.0.0/14", "gateway": "10.99.0.1", "dev": "tun0", "metric": 101},
        {"dst": "14.70.228.6", "gateway": "10.99.0.1", "dev": "tun0", "metric": 101},
        {"dst": "14.75.69.22", "gateway": "192.168.4.1", "dev": "eno1"},
        {
            "dst": "10.99.0.0/23",
            "dev": "tun0",
            "protocol": "kernel",
            "scope": "link",
            "prefsrc": "10.99.1.21",
        },
        {"dst": "172.17.0.0/16", "dev": "docker0", "protocol": "kernel", "scope": "link"},
    ]
)


class _Completed:
    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeController:
    """Minimal controller for route tests."""

    def __init__(self) -> None:
        self.status = VpnStatus()
        self.route_list: list[Route] = [
            Route("5.20.0.0/14", "10.99.0.1", "tun0", 101),
            Route("10.99.0.0/23", None, "tun0", None, kind="on-link"),
        ]
        self.connect_calls: list[tuple[str, str]] = []
        self.disconnect_calls = 0
        self.tunnel_scope = None
        self.connect_error: Exception | None = None
        self.disconnect_error: Exception | None = None
        self.whois_calls: list[list[str]] = []
        #: destination -> organisation, as a real lookup would resolve it.
        self.whois_orgs: dict[str, str] = {}

    def snapshot(self) -> VpnStatus:
        return self.status

    def recent_events(self, limit: int = 10) -> list[str]:
        return ["2026-08-19T08:14:55+01:00 UP"]

    def routes(self) -> list[Route]:
        return list(self.route_list)

    def scope(self):
        from app.services.scope import EMPTY_SCOPE

        return self.tunnel_scope if self.tunnel_scope is not None else EMPTY_SCOPE

    def whois(self, destinations: list[str]):
        from app.services.whois import WhoisResult

        self.whois_calls.append(list(destinations))
        return [WhoisResult(destination=d, org=self.whois_orgs.get(d)) for d in destinations]

    def connect(self, profile: str, otp: str) -> None:
        if self.connect_error:
            raise self.connect_error
        self.connect_calls.append((profile, otp))

    def disconnect(self) -> None:
        if self.disconnect_error:
            raise self.disconnect_error
        self.disconnect_calls += 1

    def attach(self) -> None:  # pragma: no cover - never called under TESTING
        raise AssertionError("attach() must not touch the system in tests")


@pytest.fixture
def open_db(tmp_path: Path):
    """Factory for SQLite connections that are always closed again.

    Connections must be closed explicitly: pyproject turns warnings into errors, so a leaked
    handle fails the test that leaked it rather than some unrelated one later.
    """
    opened = []

    def _open(name: str = "app.db", directory=None):
        from app.db import connect

        conn = connect(tmp_path / name) if directory is None else connect(directory / name)
        opened.append(conn)
        return conn

    yield _open
    for conn in opened:
        conn.close()


@pytest.fixture
def db(tmp_path: Path):
    """A migrated, empty database."""
    conn = open_migrated(tmp_path / "app.db")
    yield conn
    conn.close()


@pytest.fixture
def app_db(config):
    """The database at the path this config points at, so the app and the test share one."""
    conn = open_migrated(config.database)
    yield conn
    conn.close()


@pytest.fixture
def vault_state(app_db):
    """An unlocked vault, as it would be immediately after signing in."""
    state = vault.VaultState()
    state.store(vault.initialise(app_db, PASSWORD))
    return state


@pytest.fixture
def connections(app_db, vault_state, vpn_dir):
    return Connections(app_db, vault_state, vpn_dir)


@pytest.fixture
def history(app_db):
    return History(app_db)


@pytest.fixture
def dns_runner() -> FakeRunner:
    return FakeRunner(stdout="applied")


@pytest.fixture
def dns_rules(app_db, config, dns_runner):
    return DnsRules(app_db, config, runner=dns_runner)


@pytest.fixture
def seeded_topic(app_db):
    """A saved ntfy topic, matching what most notification tests assume is already configured."""
    store.save_notify(app_db, topic="existing-topic")
    return "existing-topic"


@pytest.fixture
def stored_connection(connections):
    """One saved connection, which is what most tests need to exist."""
    return connections.save(
        name="client", profile=PROFILE, username="alice", password="s3cret", label="Test VPN"
    )


#: A minimal but realistic profile: the connect path only cares that it is non-empty text.
PROFILE = (
    "client\nremote vpn.example.test 1194 udp\nauth-user-pass\n"
    'static-challenge "Enter Authenticator Code" 1\n'
)


@pytest.fixture
def vpn_dir(tmp_path: Path) -> Path:
    """Where .ovpn files get written out. Everything configurable now lives in the database."""
    directory = tmp_path / "vpn"
    directory.mkdir()
    return directory


@pytest.fixture
def config(tmp_path: Path, vpn_dir: Path) -> Config:
    return replace(
        Config(),
        SECRET_KEY="test-secret",
        PASSWORD_HASH=hash_password(PASSWORD),
        VPN_DIR=vpn_dir,
        HELPER=tmp_path / "helper",
        MGMT_SOCKET=tmp_path / "mgmt.sock",
        SOCKET_WAIT_SECONDS=1.0,
        CONNECT_TIMEOUT_SECONDS=2.0,
        COMMAND_TIMEOUT_SECONDS=1.0,
    )


class FakeNotifier:
    """Records notifications instead of sending them. ``explode`` proves a failing notifier
    cannot take a tunnel operation down with it."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, object]] = []
        self.explode = False

        self.test_error: Exception | None = None
        self.tests_sent = 0

    def notify(self, kind: str, context) -> None:
        if self.explode:
            raise RuntimeError("ntfy is down")
        self.sent.append((kind, context))

    def send_test(self) -> str:
        if self.test_error is not None:
            raise self.test_error
        self.tests_sent += 1
        return "https://ntfy.sh/existing-topic"


@pytest.fixture
def notifier() -> FakeNotifier:
    return FakeNotifier()


@pytest.fixture
def controller(
    config: Config,
    notifier: FakeNotifier,
    connections: Connections,
    history: History,
    stored_connection,
) -> OpenVpnController:
    FakeClient.reset()
    runner = FakeRunner()
    instance = OpenVpnController(
        config,
        connections=connections,
        history=history,
        runner=runner,
        client_factory=FakeClient,
        notifier=notifier,
    )
    instance.runner = runner  # type: ignore[attr-defined]
    return instance


@pytest.fixture
def fake_controller() -> FakeController:
    return FakeController()


@pytest.fixture
def app(
    config: Config,
    fake_controller: FakeController,
    notifier: FakeNotifier,
    app_db,
    vault_state,
    connections: Connections,
    history: History,
    dns_rules: DnsRules,
):
    application = create_app(
        {
            "APP_CONFIG": config,
            "CONTROLLER": fake_controller,
            "NOTIFIER": notifier,
            "DB": app_db,
            "VAULT": vault_state,
            "CONNECTIONS": connections,
            "HISTORY": history,
            "DNS_RULES": dns_rules,
            # Pinned, not discovered: otherwise every test's deployment self-check depends on
            # whether the machine running the suite happens to have openvpn installed, and the
            # CI runners do not.
            "CLIENTS": Clients(classic="/usr/sbin/openvpn", v3=None),
            # An empty checkout, so the deployment self-check has nothing real to compare
            # against and every test sees a clean deployment unless it arranges otherwise.
            # Pointed at the real repo these would report this developer's machine.
            "SOURCE_ROOT": config.VPN_DIR,
            "STARTED_AT": time.time() + 3600,
            "TESTING": True,
        }
    )
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def auth_client(app):
    """A test client with an authenticated session and a usable CSRF token."""
    test_client = app.test_client()
    page = test_client.get("/login")
    token = _extract_csrf(page.get_data(as_text=True))
    test_client.post("/login", data={"password": PASSWORD, "csrf_token": token})
    test_client.csrf_token = _extract_csrf(test_client.get("/").get_data(as_text=True))
    return test_client


def _extract_csrf(html: str) -> str:
    marker = 'name="csrf-token" content="'
    if marker in html:
        return html.split(marker, 1)[1].split('"', 1)[0]
    marker = 'name="csrf_token" value="'
    return html.split(marker, 1)[1].split('"', 1)[0]
