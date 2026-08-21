"""Line-protocol handling for the management interface, against an in-memory socket pair."""

from __future__ import annotations

import socket
import threading

import pytest

from app.services.management import ManagementClient, ManagementError, redact


class SocketPair:
    """A connected AF_UNIX pair: one end for the client, one to play OpenVPN with."""

    def __init__(self) -> None:
        self.client_side, self.server_side = socket.socketpair(socket.AF_UNIX)
        self.received = b""
        self._lock = threading.Lock()

    def factory(self, path, timeout):
        return self.client_side

    def send(self, line: str) -> None:
        self.server_side.sendall(line.encode() + b"\r\n")

    def read_line(self, timeout: float = 2.0) -> str:
        self.server_side.settimeout(timeout)
        buffer = b""
        while b"\n" not in buffer:
            chunk = self.server_side.recv(1024)
            if not chunk:
                raise AssertionError("client closed the socket")
            buffer += chunk
        return buffer.split(b"\n", 1)[0].decode().rstrip("\r")

    def close(self) -> None:
        self.server_side.close()


@pytest.fixture
def pair():
    instance = SocketPair()
    yield instance
    instance.close()


@pytest.fixture
def client(pair, tmp_path):
    events: list[tuple[str, str]] = []
    instance = ManagementClient(
        tmp_path / "mgmt.sock",
        on_event=lambda kind, payload: events.append((kind, payload)),
        connect_factory=pair.factory,
    )
    instance.events = events  # type: ignore[attr-defined]
    instance.connect()
    yield instance
    instance.close()


def test_command_collects_lines_until_end(client, pair):
    def responder():
        assert pair.read_line() == "state"
        pair.send("1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
        pair.send("END")

    thread = threading.Thread(target=responder)
    thread.start()
    assert client.command("state") == ["1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,"]
    thread.join()


def test_command_accepts_success_terminator(client, pair):
    def responder():
        pair.read_line()
        pair.send("SUCCESS: hold release succeeded")

    thread = threading.Thread(target=responder)
    thread.start()
    assert client.command("hold release") == ["SUCCESS: hold release succeeded"]
    thread.join()


def test_command_raises_on_error_response(client, pair):
    def responder():
        pair.read_line()
        pair.send("ERROR: unknown command")

    thread = threading.Thread(target=responder)
    thread.start()
    with pytest.raises(ManagementError, match="unknown command"):
        client.command("bogus")
    thread.join()


def test_command_times_out(client):
    with pytest.raises(ManagementError, match="timed out"):
        client.command("state", timeout=0.1)


def test_notifications_are_routed_to_the_event_callback(client, pair):
    pair.send(">STATE:1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
    pair.send(">BYTECOUNT:10,20")

    deadline = threading.Event()
    deadline.wait(0.3)
    kinds = [kind for kind, _ in client.events]
    assert "STATE" in kinds and "BYTECOUNT" in kinds


def test_notifications_do_not_leak_into_command_replies(client, pair):
    def responder():
        pair.read_line()
        pair.send(">BYTECOUNT:1,2")
        pair.send("1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
        pair.send("END")

    thread = threading.Thread(target=responder)
    thread.start()
    assert client.command("state") == ["1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,"]
    thread.join()


def test_closed_socket_is_reported(client, pair):
    pair.close()
    with pytest.raises(ManagementError):
        client.command("state", timeout=1.0)


def test_credentials_are_quoted_and_escaped(client, pair):
    lines: list[str] = []

    def responder():
        for _ in range(2):
            lines.append(pair.read_line())
            pair.send("SUCCESS: ok")

    thread = threading.Thread(target=responder)
    thread.start()
    client.send_credentials("Auth", 'ali"ce', "SCRV1:aaa:bbb")
    thread.join()
    assert lines == ['username "Auth" "ali\\"ce"', 'password "Auth" "SCRV1:aaa:bbb"']


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('password "Auth" "SCRV1:aaa:bbb"', "password [redacted]"),
        ('username "Auth" "alice"', "username [redacted]"),
        ("MANAGEMENT: CMD 'password [...]'", "MANAGEMENT: CMD 'password [...]'"),
        ("auth-user-pass SCRV1:zzz", "auth-user-pass SCRV1:[redacted]"),
        ("Initialization Sequence Completed", "Initialization Sequence Completed"),
    ],
)
def test_redaction(line, expected):
    assert redact(line) == expected


def test_a_handler_may_issue_commands_without_deadlocking(pair, tmp_path):
    """Regression: answering >PASSWORD: means calling command() from the event callback.

    Delivering notifications on the reader thread made that block forever -- the reply could
    only be read by the very thread that was waiting for it.
    """
    answered = threading.Event()
    client = ManagementClient(
        tmp_path / "mgmt.sock",
        on_event=lambda kind, payload: (
            (
                client.send_credentials("Auth", "alice", "SCRV1:aaa:bbb"),
                answered.set(),
            )
            if kind == "PASSWORD"
            else None
        ),
        connect_factory=pair.factory,
    )
    client.connect()

    sent: list[str] = []

    def openvpn():
        pair.send(">PASSWORD:Need 'Auth' username/password SC:1,Enter Authenticator Code")
        for _ in range(2):
            sent.append(pair.read_line(timeout=3.0))
            pair.send("SUCCESS: entered")

    thread = threading.Thread(target=openvpn)
    thread.start()
    assert answered.wait(5.0), "handler never completed -- reader thread deadlocked"
    thread.join(5.0)
    client.close()

    assert sent == [
        'username "Auth" "alice"',
        'password "Auth" "SCRV1:aaa:bbb"',
    ]


def test_a_raising_handler_does_not_kill_the_connection(pair, tmp_path):
    seen: list[str] = []

    def handler(kind, payload):
        seen.append(kind)
        if kind == "STATE":
            raise RuntimeError("boom")

    client = ManagementClient(
        tmp_path / "mgmt.sock", on_event=handler, connect_factory=pair.factory
    )
    client.connect()
    pair.send(">STATE:1,CONNECTING,,,,,,")
    pair.send(">BYTECOUNT:1,2")

    deadline = threading.Event()
    deadline.wait(0.4)
    assert seen == ["STATE", "BYTECOUNT"]
    assert client.is_open
    client.close()
