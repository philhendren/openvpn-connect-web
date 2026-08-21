"""Thin client for OpenVPN's management interface over a unix domain socket.

The socket speaks a line protocol: asynchronous notifications are prefixed with ``>``
(``>STATE:``, ``>PASSWORD:``, ``>BYTECOUNT:`` ...), while command responses are plain lines
terminated by ``SUCCESS:``, ``ERROR:`` or a bare ``END``.  A reader thread demultiplexes the
two so that notifications keep arriving while a command is in flight.
"""

from __future__ import annotations

import contextlib
import logging
import queue
import re
import socket
import threading
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger(__name__)

#: Commands whose arguments carry secrets and must never reach a log record.
_SECRET_COMMANDS = ("password ", "username ")
_REDACTED = re.compile(r'^(password|username)\s+"[^"]*"\s+".*"$', re.IGNORECASE)


class ManagementError(RuntimeError):
    """Raised when the management interface refuses a command or goes away."""


def redact(line: str) -> str:
    """Strip credential material out of a management-interface line."""
    if _REDACTED.match(line.strip()):
        verb = line.strip().split(None, 1)[0]
        return f"{verb} [redacted]"
    lowered = line.lower()
    if "auth-user-pass" in lowered or "scrv1:" in lowered:
        return re.sub(r"SCRV1:\S+", "SCRV1:[redacted]", line, flags=re.IGNORECASE)
    return line


class ManagementClient:
    """Owns one connection to the management socket.

    ``on_event`` is called from the reader thread with ``(kind, payload)`` for every ``>``
    notification, e.g. ``("STATE", "1723,CONNECTED,SUCCESS,10.0.0.2,,,,")``.
    """

    def __init__(
        self,
        socket_path: Path,
        on_event: Callable[[str, str], None] | None = None,
        *,
        connect_factory: Callable[[Path, float], socket.socket] | None = None,
    ) -> None:
        self._path = Path(socket_path)
        self._on_event = on_event or (lambda kind, payload: None)
        self._connect_factory = connect_factory or _connect_unix
        self._sock: socket.socket | None = None
        self._reader: threading.Thread | None = None
        self._dispatcher: threading.Thread | None = None
        self._responses: queue.Queue[str] = queue.Queue()
        # Notifications are handed to a second thread so that a callback issuing its own
        # command() cannot block the reader that has to deliver that command's reply.
        self._events: queue.Queue[tuple[str, str] | None] = queue.Queue()
        self._send_lock = threading.Lock()
        self._closed = threading.Event()

    # -- lifecycle --------------------------------------------------------

    @property
    def is_open(self) -> bool:
        return self._sock is not None and not self._closed.is_set()

    def connect(self, timeout: float = 5.0) -> None:
        if self.is_open:
            return
        self._closed.clear()
        self._sock = self._connect_factory(self._path, timeout)
        self._dispatcher = threading.Thread(
            target=self._dispatch_loop, name="openvpn-mgmt-events", daemon=True
        )
        self._dispatcher.start()
        self._reader = threading.Thread(target=self._read_loop, name="openvpn-mgmt", daemon=True)
        self._reader.start()

    def close(self) -> None:
        self._closed.set()
        self._events.put(None)
        sock, self._sock = self._sock, None
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    # -- protocol ---------------------------------------------------------

    def command(self, line: str, timeout: float = 10.0) -> list[str]:
        """Send one command and collect its response lines.

        Raises :class:`ManagementError` on ``ERROR:`` responses, a closed socket, or timeout.
        """
        if not self.is_open:
            raise ManagementError("management socket is not connected")
        safe = redact(line)
        with self._send_lock:
            self._drain()
            self._write(line)
            collected: list[str] = []
            while True:
                try:
                    reply = self._responses.get(timeout=timeout)
                except queue.Empty as exc:
                    raise ManagementError(f"timed out waiting for reply to {safe!r}") from exc
                if reply == _EOF:
                    raise ManagementError(f"management socket closed during {safe!r}")
                if reply == "END" or reply.startswith("SUCCESS:"):
                    if reply.startswith("SUCCESS:"):
                        collected.append(reply)
                    return collected
                if reply.startswith("ERROR:"):
                    raise ManagementError(f"{safe!r} failed: {reply}")
                collected.append(reply)

    def send_credentials(self, realm: str, username: str, secret: str) -> None:
        """Answer a ``>PASSWORD:Need '<realm>' username/password`` prompt."""
        self.command(f'username "{_quote(realm)}" "{_quote(username)}"')
        self.command(f'password "{_quote(realm)}" "{_quote(secret)}"')

    # -- internals --------------------------------------------------------

    def _write(self, line: str) -> None:
        sock = self._sock
        if sock is None:
            raise ManagementError("management socket is not connected")
        log.debug("mgmt -> %s", redact(line))
        try:
            sock.sendall(line.encode("utf-8") + b"\n")
        except OSError as exc:
            raise ManagementError(f"write failed: {exc}") from exc

    def _drain(self) -> None:
        while True:
            try:
                self._responses.get_nowait()
            except queue.Empty:
                return

    def _read_loop(self) -> None:
        sock = self._sock
        assert sock is not None
        buffer = b""
        try:
            while not self._closed.is_set():
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    raw, buffer = buffer.split(b"\n", 1)
                    self._dispatch(raw.decode("utf-8", "replace").rstrip("\r"))
        except OSError:
            pass
        finally:
            self._closed.set()
            self._responses.put(_EOF)
            self._events.put(("DISCONNECTED", ""))
            self._events.put(None)

    def _dispatch_loop(self) -> None:
        """Deliver notifications on their own thread.

        Handlers are allowed to call :meth:`command` -- answering a ``>PASSWORD:`` prompt does
        exactly that -- which only works because the reader thread stays free to feed replies.
        """
        while True:
            item = self._events.get()
            if item is None:
                return
            kind, payload = item
            try:
                self._on_event(kind, payload)
            except Exception:  # noqa: BLE001 - a bad handler must not kill the connection
                log.exception("management event handler failed for >%s", kind)

    def _dispatch(self, line: str) -> None:
        if line.startswith(">"):
            kind, _, payload = line[1:].partition(":")
            log.debug("mgmt <- >%s:%s", kind, redact(payload))
            self._events.put((kind.upper(), payload))
        else:
            log.debug("mgmt <- %s", redact(line))
            self._responses.put(line)


_EOF = "\x00EOF"


def _quote(value: str) -> str:
    """Escape a value for the management interface's quoted-string arguments."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _connect_unix(path: Path, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
    except OSError as exc:
        sock.close()
        raise ManagementError(f"cannot connect to management socket {path}: {exc}") from exc
    sock.settimeout(None)
    return sock
