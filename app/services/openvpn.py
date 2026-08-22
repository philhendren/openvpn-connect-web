"""The only module that talks to OpenVPN.

Everything above this layer sees typed snapshots, never raw stdout.  Three mechanisms are used:

* a fixed root helper invoked as ``sudo -n /usr/local/sbin/vpn-connect-helper start <profile>``,
  which is the sole privileged operation (bringing up the tun device needs root);
* the management interface on a unix socket, which needs no privileges and handles the
  ``auth-user-pass`` + static-challenge MFA exchange, live state, byte counters and shutdown;
* ``ip`` for the tunnel address and the installed routes, read-only and unprivileged.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import logging
import os
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from app.config import Config
from app.services.connections import Connections, Resolved
from app.services.history import History
from app.services.management import ManagementClient, ManagementError, redact
from app.services.notifications import NotifyContext
from app.services.rooted import SUDO, HelperError, run_helper  # noqa: F401 -- re-exported for tests
from app.services.routing import Route, read_routes
from app.services.scope import EMPTY_SCOPE, TunnelScope, read_scope
from app.services.store import StoreError
from app.services.whois import WhoisResult, lookup_many

log = logging.getLogger(__name__)

#: App-level lifecycle, distinct from OpenVPN's own >STATE: names.
DISCONNECTED = "disconnected"
STARTING = "starting"
AUTHENTICATING = "authenticating"
CONNECTING = "connecting"
CONNECTED = "connected"
DISCONNECTING = "disconnecting"
FAILED = "failed"
#: An openvpn process is running that this panel did not start and cannot talk to -- e.g. one
#: launched by scripts/vpn-connect.sh, whose management interface is elsewhere.
UNMANAGED = "unmanaged"

_BUSY_STATES = {STARTING, AUTHENTICATING, CONNECTING, DISCONNECTING}


class VpnError(RuntimeError):
    """Raised for operator-visible failures (already running, bad OTP, helper missing...)."""


@dataclass
class VpnStatus:
    """Immutable-ish view of the tunnel, safe to serialise straight to JSON."""

    state: str = DISCONNECTED
    openvpn_state: str = ""
    detail: str = ""
    profile: str | None = None
    tun_ip: str | None = None
    remote_ip: str | None = None
    connected_since: float | None = None
    bytes_in: int = 0
    bytes_out: int = 0
    pid: int | None = None
    error: str | None = None
    log_lines: list[str] = field(default_factory=list)

    @property
    def busy(self) -> bool:
        return self.state in _BUSY_STATES

    @property
    def uptime_seconds(self) -> int | None:
        if self.connected_since is None:
            return None
        return max(0, int(time.time() - self.connected_since))

    def to_dict(self) -> dict[str, object]:
        return {
            "state": self.state,
            "openvpn_state": self.openvpn_state,
            "detail": self.detail,
            "profile": self.profile,
            "tun_ip": self.tun_ip,
            "remote_ip": self.remote_ip,
            "uptime_seconds": self.uptime_seconds,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "pid": self.pid,
            "error": self.error,
            "busy": self.busy,
            "connected": self.state == CONNECTED,
            "controllable": self.state not in (UNMANAGED,),
        }


class OpenVpnController:
    """Owns the tunnel's lifecycle and the single management connection.

    One instance per process -- run the app with a single worker so that state is not split
    across processes.
    """

    def __init__(
        self,
        config: Config,
        *,
        connections: Connections,
        history: History,
        runner=subprocess.run,
        client_factory=ManagementClient,
        notifier=None,
    ) -> None:
        self._config = config
        self._connections = connections
        self._history = history
        self._notifier = notifier
        self._run = runner
        self._client_factory = client_factory
        self._lock = threading.RLock()
        self._status = VpnStatus()
        self._client: ManagementClient | None = None
        self._log: deque[str] = deque(maxlen=200)
        self._auth_prompt = threading.Event()
        self._settled = threading.Event()
        self._pending_secret: str | None = None
        self._worker: threading.Thread | None = None
        #: Whether the operator has been told the tunnel is up. Gates the matching "down", so a
        #: failed attempt that never connected does not report a tunnel going down.
        self._notified_up = False
        #: Set by disconnect(); the only thing distinguishing a deliberate stop from a drop.
        self._shutdown_requested = False
        #: Captured when an attempt starts, for the management auth exchange.
        self._username_for_auth = ""
        #: Counts connection attempts, so a worker thread can tell whether it is still the one
        #: that matters. Reconnecting quickly leaves the previous worker briefly alive, and
        #: without this it tidies up -- clearing the pending credential, reporting its own
        #: timeout -- on top of the attempt that replaced it.
        self._attempt = 0

    # -- public API -------------------------------------------------------

    def snapshot(self) -> VpnStatus:
        with self._lock:
            status = VpnStatus(**{**self._status.__dict__})
        status.pid = self._read_pid()
        if status.state == DISCONNECTED and status.pid is not None:
            status.state = UNMANAGED
            status.detail = (
                "An OpenVPN process is already running that this panel did not start. "
                "Disconnect to take control."
            )
        if status.state in (CONNECTED, UNMANAGED) and not status.tun_ip:
            status.tun_ip = self._tun_address()
        if status.state == DISCONNECTED and not status.detail:
            status.detail = "No tunnel running."

        status.log_lines = list(self._log)
        return status

    def attach(self) -> None:
        """Re-adopt a tunnel that is already running (e.g. after the web app restarts)."""
        with self._lock:
            if self._client is not None and self._client.is_open:
                return
            if not self._config.MGMT_SOCKET.exists():
                return
        try:
            client = self._open_client()
        except ManagementError as exc:
            log.info("no running tunnel to attach to: %s", exc)
            return
        self._history.start_session(None)  # a re-adopted tunnel needs somewhere to record too
        with self._lock:
            self._status.state = CONNECTING
            self._status.detail = "Re-attached to a running OpenVPN process."
            # Suppress the "up" that re-adopting an established tunnel would otherwise emit;
            # corrected below once the refreshed state says whether it really is up.
            self._notified_up = True
        self._prime(client)
        self._refresh_state(client)
        with self._lock:
            self._notified_up = self._status.state == CONNECTED

    def connect(self, profile_name: str, otp: str) -> None:
        """Start the tunnel and answer its credential + MFA challenge.

        Returns as soon as the attempt is under way; poll :meth:`snapshot` for the outcome.
        """
        otp = (otp or "").strip()

        # Decrypts the connection and writes its .ovpn out; raises if the vault is locked or
        # the name is unknown, both of which are operator-visible problems.
        try:
            resolved = self._connections.resolve(profile_name)
        except StoreError as exc:
            raise VpnError(str(exc)) from exc

        # Validated after resolving, not before: whether a code is required at all is a property
        # of the profile, so it cannot be known until the connection has been looked up. A
        # profile with no static-challenge line signs in with its password alone, and demanding
        # a code for it made such a connection impossible to use.
        if resolved.requires_mfa:
            if not otp:
                raise VpnError("An authenticator code is required.")
            if not otp.isdigit() or not 4 <= len(otp) <= 12:
                raise VpnError("The authenticator code should be 4-12 digits.")
        elif otp:
            raise VpnError("This connection does not use an authenticator code.")

        with self._lock:
            if self._status.busy:
                raise VpnError("A connection attempt is already in progress.")
            if self._status.state == CONNECTED or self._is_running():
                raise VpnError("OpenVPN is already running. Disconnect first.")
            self._status = VpnStatus(
                state=STARTING, profile=resolved.name, detail="Launching OpenVPN..."
            )
            self._log.clear()
            self._history.start_session(resolved.name)
            self._auth_prompt.clear()
            self._settled.clear()
            self._shutdown_requested = False
            self._notified_up = False
            self._attempt += 1
            self._worker = threading.Thread(
                target=self._connect_worker,
                args=(resolved, otp, self._attempt),
                name="vpn-connect",
                daemon=True,
            )
            self._worker.start()

    def disconnect(self) -> None:
        """Ask OpenVPN to exit, preferring the unprivileged management route."""
        with self._tracked():
            client = self._client
            if self._status.state == DISCONNECTED and not self._is_running():
                raise VpnError("OpenVPN is not running.")
            self._status.state = DISCONNECTING
            self._status.detail = "Stopping OpenVPN..."
            self._status.error = None

        self._shutdown_requested = True
        if client is not None and client.is_open:
            try:
                client.command("signal SIGTERM", timeout=self._config.COMMAND_TIMEOUT_SECONDS)
                return
            except ManagementError as exc:
                log.warning("management shutdown failed, falling back to helper: %s", exc)

        self._helper("stop")
        with self._tracked():
            self._status = VpnStatus(state=DISCONNECTED, detail="OpenVPN stopped.")

    def recent_events(self, limit: int = 10) -> list[str]:
        """Recent UP/DOWN history, newest first."""
        return self._history.recent_events(limit)

    def routes(self) -> list[Route]:
        """The routes currently installed for the tunnel device.

        Read from the kernel on demand rather than cached: routes can change under us (a rekey,
        a hook, a manual `ip route`), and the call is a single cheap subprocess.  Deliberately
        not folded into :meth:`snapshot`, which is polled every few seconds -- this list runs to
        hundreds of rows on a split tunnel.
        """
        if not self._is_running():
            return []
        with self._lock:
            remote_ip = self._status.remote_ip
        return read_routes(
            self._run,
            device=self._config.TUN_DEVICE,
            remote_ip=remote_ip,
            timeout=self._config.COMMAND_TIMEOUT_SECONDS,
        )

    def scope(self) -> TunnelScope:
        """What the tunnel actually carries: full, split, or nothing -- and whether IPv6 leaks.

        Read on demand from the kernel like :meth:`routes`, so it stays correct for a tunnel this
        app did not start and needs no privileges.
        """
        if not self._is_running():
            return EMPTY_SCOPE
        return read_scope(
            self._run,
            device=self._config.TUN_DEVICE,
            timeout=self._config.COMMAND_TIMEOUT_SECONDS,
        )

    def whois(self, destinations: list[str]) -> list[WhoisResult]:
        """Who registered each of these public destinations.

        Shares the controller's runner like every other subprocess call, so it is faked in tests
        the same way. Non-public destinations are filtered out by :mod:`app.services.whois`
        itself, so this needs no ``_is_running`` gate -- callers are expected to have already
        narrowed ``destinations`` to what :meth:`routes` currently reports.
        """
        return lookup_many(destinations, runner=self._run)

    # -- connect worker ---------------------------------------------------

    def _connect_worker(self, resolved: Resolved, otp: str, attempt: int) -> None:
        # SCRV1 is the static-challenge response format. Sending it to a server that never asked
        # for a challenge would fail authentication with a password the operator knows is right,
        # so a profile without one gets the password exactly as stored.
        if resolved.requires_mfa:
            secret = f"SCRV1:{_b64(resolved.password)}:{_b64(otp)}"
        else:
            secret = resolved.password
        self._username_for_auth = resolved.username
        try:
            self._helper("start", resolved.name)
            self._wait_for_socket()
            client = self._open_client()
            self._advance(AUTHENTICATING, "Waiting for the credential prompt...")
            self._pending_secret = secret
            self._prime(client, release_hold=True)

            if not self._auth_prompt.wait(timeout=self._config.SOCKET_WAIT_SECONDS):
                raise VpnError("OpenVPN never asked for credentials -- check the log below.")
            self._raise_if_failed()
            self._advance(CONNECTING, "Credentials submitted, negotiating tunnel...")

            if not self._settled.wait(timeout=self._config.CONNECT_TIMEOUT_SECONDS):
                raise VpnError("Timed out waiting for the tunnel to come up.")
            self._raise_if_failed()
        except (VpnError, ManagementError) as exc:
            if self._superseded(attempt):
                return
            self._fail(str(exc))
            self._abort_daemon()
        except Exception as exc:  # noqa: BLE001 - worker thread must never die silently
            log.exception("unexpected failure while connecting")
            if self._superseded(attempt):
                return
            self._fail(f"Unexpected failure: {exc}")
            self._abort_daemon()
        finally:
            # Only if this worker still owns the attempt. A superseded one arriving here would
            # otherwise wipe the credential the *new* attempt is waiting to answer its prompt
            # with, and the new attempt would fail with "none were pending".
            with self._lock:
                if self._attempt == attempt:
                    self._pending_secret = None
            del secret

    def _superseded(self, attempt: int) -> bool:
        """Has a newer attempt started since this worker began?

        A worker that has been replaced must stay quiet: its timeout, its torn-down daemon and
        its failure message all belong to a connection nobody is waiting for any more, and
        reporting them fails the attempt that replaced it.
        """
        with self._lock:
            return self._attempt != attempt

    def _abort_daemon(self) -> None:
        """Tear down a half-started daemon so a failed attempt leaves nothing stuck.

        Without this, an openvpn still sitting at its credential prompt survives the failure and
        blocks the next attempt with 'already running'.
        """
        with self._lock:
            if self._status.state == CONNECTED:
                return
            client = self._client
        self._shutdown_requested = True
        try:
            if client is not None and client.is_open:
                client.command("signal SIGTERM", timeout=self._config.COMMAND_TIMEOUT_SECONDS)
                return
        except ManagementError as exc:
            log.warning("could not signal the stuck daemon: %s", exc)
        try:
            self._helper("stop")
        except VpnError as exc:
            log.warning("could not stop the stuck daemon: %s", exc)

    def _prime(self, client: ManagementClient, *, release_hold: bool = False) -> None:
        """Turn on the notifications the UI depends on, then let OpenVPN out of its hold."""
        for command in ("state on", f"bytecount {self._config.BYTECOUNT_INTERVAL}", "log on all"):
            try:
                client.command(command, timeout=self._config.COMMAND_TIMEOUT_SECONDS)
            except ManagementError as exc:
                log.warning("management command %r failed: %s", command, exc)
        if release_hold:
            try:
                client.command("hold release", timeout=self._config.COMMAND_TIMEOUT_SECONDS)
            except ManagementError as exc:
                log.debug("hold release rejected (not held?): %s", exc)

    def _refresh_state(self, client: ManagementClient) -> None:
        try:
            for line in client.command("state", timeout=self._config.COMMAND_TIMEOUT_SECONDS):
                if "," in line:
                    self._on_state(line)
        except ManagementError as exc:
            log.warning("could not read state: %s", exc)

    # -- management events ------------------------------------------------

    def _on_event(self, kind: str, payload: str) -> None:
        if kind == "STATE":
            self._on_state(payload)
        elif kind == "PASSWORD":
            self._on_password(payload)
        elif kind == "BYTECOUNT":
            self._on_bytecount(payload)
        elif kind == "LOG":
            self._append_log(payload)
        elif kind == "FATAL":
            self._fail(redact(payload))
        elif kind == "DISCONNECTED":
            self._on_socket_closed()

    def _on_state(self, payload: str) -> None:
        fields = payload.split(",")
        if len(fields) < 2:
            return
        name = fields[1]
        detail = fields[2] if len(fields) > 2 else ""
        tun_ip = fields[3] if len(fields) > 3 and fields[3] else None
        remote_ip = fields[4] if len(fields) > 4 and fields[4] else None

        with self._tracked():
            self._status.openvpn_state = name
            self._status.detail = detail or name.replace("_", " ").title()
            if tun_ip:
                self._status.tun_ip = tun_ip
            if remote_ip:
                self._status.remote_ip = remote_ip
            if name == "CONNECTED":
                self._status.state = CONNECTED
                self._status.error = None
                self._status.detail = "Tunnel established."
                if self._status.connected_since is None:
                    self._status.connected_since = time.time()
                self._settled.set()
            elif name == "EXITING":
                self._status.state = DISCONNECTED if not self._status.error else FAILED
                self._status.connected_since = None
                self._settled.set()
            elif self._status.state not in _BUSY_STATES:
                self._status.state = CONNECTING

    def _on_password(self, payload: str) -> None:
        lowered = payload.lower()
        if "need" in lowered and "username/password" in lowered:
            realm = _realm(payload) or "Auth"
            secret = self._pending_secret
            client = self._client
            if client is None or secret is None:
                self._fail("OpenVPN asked for credentials but none were pending.")
                return
            try:
                client.send_credentials(realm, self._username(), secret)
            except ManagementError as exc:
                self._fail(f"Could not submit credentials: {exc}")
                return
            finally:
                self._pending_secret = None
            self._auth_prompt.set()
        elif "verification failed" in lowered:
            self._auth_prompt.set()
            self._fail("Authentication rejected -- check the authenticator code and try again.")

    def _on_bytecount(self, payload: str) -> None:
        parts = payload.split(",")
        if len(parts) != 2:
            return
        try:
            bytes_in, bytes_out = int(parts[0]), int(parts[1])
        except ValueError:
            return
        with self._lock:
            self._status.bytes_in = bytes_in
            self._status.bytes_out = bytes_out
        # Keep the reading rather than only the latest total: this is the whole data source for
        # the traffic graph, and it was previously thrown away every few seconds.
        self._history.record_sample(bytes_in, bytes_out)

    def _on_socket_closed(self) -> None:
        with self._tracked():
            self._client = None
            state = self._status.state
            if state in (STARTING, AUTHENTICATING, CONNECTING):
                # The daemon died before the tunnel came up -- usually a rejected credential.
                self._status.state = FAILED
                if not self._status.error:
                    self._status.error = "OpenVPN exited before the tunnel came up."
                self._status.detail = self._status.error
            elif state in (CONNECTED, DISCONNECTING):
                self._status.state = FAILED if self._status.error else DISCONNECTED
                if not self._status.error:
                    self._status.detail = "OpenVPN exited."
            self._status.connected_since = None
            self._status.tun_ip = None
        self._settled.set()
        self._auth_prompt.set()

    # -- state transitions -------------------------------------------------
    #
    # One chokepoint decides what the operator is told. It exists because the *reason* a tunnel
    # went down is knowable only here: OpenVPN's own --down hook fires identically whether we
    # asked it to stop or the concentrator cut us off, which is why that path needed a marker
    # file and this one does not -- ``disconnect()`` simply sets a flag in memory.

    @contextlib.contextmanager
    def _tracked(self):
        """Hold the lock for a state change, then announce any transition it caused.

        The announcement happens *after* the lock is released: it writes a file and starts a
        thread, and neither belongs inside the lock the reader thread needs.
        """
        with self._lock:
            before = self._status.state
            # Snapshotted before the change, because the very transition being announced is what
            # clears connected_since and tun_ip. Reading them only afterwards meant every
            # disconnect notification reported "an unknown time" for a tunnel that had just been
            # up for hours. The post-change values still win where they survive.
            was = (self._status.tun_ip, self._status.uptime_seconds)
            yield
            after = self._status.state
            tun_ip = self._status.tun_ip or was[0]
            remote_ip = self._status.remote_ip
            uptime = self._status.uptime_seconds
            if uptime is None:
                uptime = was[1]
        self._announce(before, after, tun_ip, remote_ip, uptime)

    def _announce(
        self,
        before: str,
        after: str,
        tun_ip: str | None,
        remote_ip: str | None,
        uptime: int | None,
    ) -> None:
        """Record and notify on a meaningful transition. Never raises."""
        if before == after:
            return

        kind: str | None = None
        event = ""
        reason = ""
        if after == CONNECTED and not self._notified_up:
            self._notified_up = True
            kind, event, reason = "up", "UP", ""
        elif before in (CONNECTED, DISCONNECTING) and after in (DISCONNECTED, FAILED, UNMANAGED):
            # An attempt that never came up is not a tunnel going down, so it notifies nothing --
            # but it is still an attempt, and closing its log is not a notification decision.
            if self._notified_up:
                self._notified_up = False
                requested = self._shutdown_requested
                self._shutdown_requested = False
                kind = "down_manual" if requested else "down_severed"
                event = "DOWN"
                reason = "operator-requested" if requested else "link-lost"

        # Flush the log buffer before anything else, so a failed attempt's tail is already
        # stored by the time the history it belongs to is readable.
        self._history.flush()
        if after == CONNECTED:
            # The one place that knows a tunnel actually came up. Recorded now because nothing
            # in the row can answer it afterwards, and "failed" and "dropped" are not the same
            # thing to anybody reading a week of attempts back.
            self._history.mark_connected()
        elif after in (DISCONNECTED, FAILED, UNMANAGED):
            # `reason` is empty unless this was a tunnel going down, which is exactly right: a
            # connect that failed at the credential prompt did not end for either of the two
            # reasons a live tunnel ends for.
            self._history.end_session("failed" if after == FAILED else "disconnected", reason)

        if kind is None:
            return

        self._write_event(event, reason)
        if self._notifier is None:
            return
        try:
            self._notifier.notify(
                kind,
                NotifyContext(
                    tun_ip=tun_ip,
                    server_ip=remote_ip,
                    uptime_seconds=uptime,
                    when=datetime.datetime.now().strftime("%H:%M"),
                ),
            )
        except Exception:  # noqa: BLE001 - a push is never worth failing a tunnel operation
            log.exception("could not dispatch the %s notification", kind)

    def _write_event(self, kind: str, reason: str) -> None:
        self._history.record_event(kind, reason, self._status.profile)

    # -- helpers ----------------------------------------------------------

    def _username(self) -> str:
        """The username for the management auth exchange, captured when the attempt started."""
        return self._username_for_auth

    def _open_client(self) -> ManagementClient:
        client = self._client_factory(self._config.MGMT_SOCKET, self._on_event)
        client.connect(timeout=self._config.COMMAND_TIMEOUT_SECONDS)
        with self._lock:
            self._client = client
        return client

    def _helper(self, action: str, *args: str) -> subprocess.CompletedProcess[str]:
        """Run the fixed root helper. ``action``/``args`` are always pre-validated values."""
        try:
            return run_helper(
                helper=self._config.HELPER,
                action=action,
                args=args,
                runner=self._run,
                timeout=self._config.COMMAND_TIMEOUT_SECONDS,
            )
        except HelperError as exc:
            raise VpnError(str(exc)) from exc

    def _wait_for_socket(self) -> None:
        deadline = time.monotonic() + self._config.SOCKET_WAIT_SECONDS
        while time.monotonic() < deadline:
            if self._config.MGMT_SOCKET.exists():
                return
            time.sleep(0.2)
        raise VpnError(
            f"Management socket {self._config.MGMT_SOCKET} never appeared "
            "-- OpenVPN failed to start."
        )

    def _read_pid(self) -> int | None:
        try:
            pid = int(self._config.pid_file.read_text().strip())
        except (OSError, ValueError):
            return None
        return pid if _pid_alive(pid) else None

    def _is_running(self) -> bool:
        return self._read_pid() is not None

    def _tun_address(self) -> str | None:
        try:
            result = self._run(
                ["ip", "-brief", "-4", "addr", "show", self._config.TUN_DEVICE],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        parts = result.stdout.split()
        return parts[2].split("/")[0] if len(parts) >= 3 else None

    def _append_log(self, payload: str) -> None:
        parts = payload.split(",", 2)
        message = parts[2] if len(parts) == 3 else payload
        redacted = redact(message)
        self._log.append(redacted)
        self._history.append(redacted)

    def _advance(self, state: str, detail: str) -> bool:
        """Move the attempt forward, unless it has already settled.

        Events arrive on their own thread, so CONNECTED or FAILED can land while the worker is
        still between steps; without this guard the worker would drag the state backwards.
        """
        with self._lock:
            if self._status.state in (CONNECTED, FAILED, DISCONNECTED):
                return False
            self._status.state = state
            self._status.detail = detail
            return True

    def _raise_if_failed(self) -> None:
        with self._lock:
            if self._status.state == FAILED:
                raise VpnError(self._status.error or "The connection attempt failed.")

    def _fail(self, message: str) -> None:
        with self._tracked():
            self._status.state = FAILED
            self._status.error = message
            self._status.detail = message
            self._status.connected_since = None
        self._settled.set()
        self._auth_prompt.set()


def _b64(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _realm(payload: str) -> str | None:
    start = payload.find("'")
    end = payload.find("'", start + 1)
    return payload[start + 1 : end] if start >= 0 and end > start else None


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except PermissionError:
        return True  # exists but owned by root
    except OSError:
        return False
    return True
