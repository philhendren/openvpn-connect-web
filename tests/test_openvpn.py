"""The command boundary. These assertions are the main defence against injection regressions."""

from __future__ import annotations

import base64
import os
import subprocess

import pytest

from app.services.openvpn import (
    CONNECTED,
    DISCONNECTED,
    FAILED,
    SUDO,
    UNMANAGED,
    OpenVpnController,
    VpnError,
)
from tests.conftest import FakeClient, wait_for


def _make_socket(config) -> None:
    config.MGMT_SOCKET.write_bytes(b"")


def _start(controller, config, otp: str = "123456") -> FakeClient:
    _make_socket(config)
    controller.connect("client", otp)
    assert wait_for(lambda: FakeClient.instances and "hold release" in FakeClient.latest().commands)
    return FakeClient.latest()


def test_helper_is_invoked_with_a_fixed_argument_list(controller, config):
    _start(controller, config)
    assert controller.runner.calls[0] == [SUDO, "-n", str(config.HELPER), "start", "client"]


def test_no_shell_is_ever_used(controller, config):
    _start(controller, config)
    for call in controller.runner.calls:
        assert isinstance(call, list)
        assert all(isinstance(arg, str) for arg in call)


def test_management_notifications_are_enabled_before_the_hold_is_released(controller, config):
    client = _start(controller, config)
    assert client.commands[:4] == [
        "state on",
        f"bytecount {config.BYTECOUNT_INTERVAL}",
        "log on all",
        "hold release",
    ]


def test_credentials_are_answered_with_the_scrv1_challenge_response(controller, config):
    client = _start(controller, config, otp="424242")
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")

    expected_password = (
        f"SCRV1:{base64.b64encode(b's3cret').decode()}:{base64.b64encode(b'424242').decode()}"
    )
    assert 'username "Auth" "alice"' in client.commands
    assert f'password "Auth" "{expected_password}"' in client.commands


# --- profiles that ask for no second factor ---------------------------------
#
# The app used to demand a code before it had even looked the connection up, and always answered
# with SCRV1 -- so a password-only profile could not be used at all.


def _password_only(connections):
    connections.save(
        name="plain",
        profile="client\nremote vpn.example.test 1194 udp\nauth-user-pass\n",
        username="alice",
        password="s3cret",
    )


def test_a_profile_without_a_static_challenge_needs_no_code(controller, config, connections):
    _password_only(connections)
    _make_socket(config)
    controller.connect("plain", "")  # no VpnError
    assert wait_for(lambda: FakeClient.instances and FakeClient.latest().commands)


def test_a_password_only_profile_is_answered_with_the_bare_password(
    controller, config, connections
):
    _password_only(connections)
    _make_socket(config)
    controller.connect("plain", "")
    assert wait_for(lambda: FakeClient.instances and "hold release" in FakeClient.latest().commands)
    client = FakeClient.latest()
    client.emit("PASSWORD", "Need 'Auth' username/password")
    assert 'password "Auth" "s3cret"' in client.commands
    assert not any("SCRV1" in command for command in client.commands)


def test_a_code_offered_to_a_password_only_profile_is_refused(controller, config, connections):
    """Sending SCRV1 to a server that never asked for a challenge fails authentication with a
    password the operator knows is right -- better to say so than to let it look like a typo."""
    _password_only(connections)
    _make_socket(config)
    with pytest.raises(VpnError, match="does not use an authenticator code"):
        controller.connect("plain", "424242")


def test_state_event_promotes_the_tunnel_to_connected(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.99.0.177,3.4.5.6,1194,,")

    assert wait_for(lambda: controller.snapshot().state == CONNECTED)
    status = controller.snapshot()
    assert status.tun_ip == "10.99.0.177"
    assert status.remote_ip == "3.4.5.6"
    assert status.uptime_seconds is not None
    assert status.error is None


def test_rejected_authentication_is_reported(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("PASSWORD", "Verification Failed: 'Auth'")

    assert wait_for(lambda: controller.snapshot().state == FAILED)
    assert "authenticator code" in controller.snapshot().error.lower()


def test_openvpn_exiting_clears_the_tunnel(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
    assert wait_for(lambda: controller.snapshot().state == CONNECTED)

    client.emit("STATE", "1755600100,EXITING,SIGTERM,,,,,")
    assert wait_for(lambda: controller.snapshot().state == DISCONNECTED)
    assert controller.snapshot().uptime_seconds is None


def test_byte_counters_are_tracked(controller, config):
    client = _start(controller, config)
    client.emit("BYTECOUNT", "2048,1024")
    assert wait_for(lambda: controller.snapshot().bytes_in == 2048)
    assert controller.snapshot().bytes_out == 1024


def test_log_lines_are_captured_and_redacted(controller, config):
    client = _start(controller, config)
    client.emit("LOG", '1755600000,,MANAGEMENT: CMD \'password "Auth" "SCRV1:aaa:bbb"\'')
    assert wait_for(lambda: controller.snapshot().log_lines)
    assert "SCRV1:aaa:bbb" not in "\n".join(controller.snapshot().log_lines)


@pytest.mark.parametrize("otp", ["", "   ", "abcdef", "12", "1234567890123", "123 456"])
def test_bad_authenticator_codes_are_refused_before_anything_runs(controller, otp):
    with pytest.raises(VpnError):
        controller.connect("client", otp)
    assert controller.runner.calls == []


@pytest.mark.parametrize(
    ("name", "message"),
    [
        ("../../etc/passwd", "may only contain"),
        ("client; rm -rf /", "may only contain"),
        ("unknown", "No connection named"),
    ],
)
def test_unknown_profile_is_refused_before_anything_runs(controller, name, message):
    with pytest.raises(VpnError, match=message):
        controller.connect(name, "123456")
    assert controller.runner.calls == []


def test_second_attempt_while_busy_is_refused(controller, config):
    _start(controller, config)
    with pytest.raises(VpnError, match="already in progress"):
        controller.connect("client", "123456")


def test_helper_failure_is_surfaced(controller, config):
    controller.runner.returncode = 1
    controller.runner.stderr = "sudo: a password is required"
    _make_socket(config)
    controller.connect("client", "123456")
    assert wait_for(lambda: controller.snapshot().state == FAILED)
    assert "sudoers" in controller.snapshot().error


def test_helper_timeout_is_surfaced(controller, config):
    controller.runner.side_effect = subprocess.TimeoutExpired(cmd="helper", timeout=1)
    _make_socket(config)
    controller.connect("client", "123456")
    assert wait_for(lambda: controller.snapshot().state == FAILED)
    assert "timed out" in controller.snapshot().error


def test_missing_management_socket_is_surfaced(controller, config):
    controller.connect("client", "123456")
    assert wait_for(lambda: controller.snapshot().state == FAILED, timeout=5)
    assert "never appeared" in controller.snapshot().error


def test_disconnect_prefers_the_unprivileged_management_signal(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
    assert wait_for(lambda: controller.snapshot().state == CONNECTED)

    controller.disconnect()
    assert "signal SIGTERM" in client.commands
    assert [call for call in controller.runner.calls if "stop" in call] == []


def test_disconnect_falls_back_to_the_helper(controller, config):
    controller._status.state = CONNECTED
    controller.disconnect()
    assert controller.runner.calls[-1] == [SUDO, "-n", str(config.HELPER), "stop"]
    assert controller.snapshot().state == DISCONNECTED


def test_disconnect_when_nothing_is_running(controller):
    with pytest.raises(VpnError, match="not running"):
        controller.disconnect()


def test_recent_events_are_newest_first(controller, history):
    history.record_event("UP")
    history.record_event("DOWN", "link-lost")
    assert controller.recent_events()[0].endswith("DOWN link-lost")


def test_attach_does_nothing_without_a_socket(controller, config):
    controller.attach()
    assert FakeClient.instances == []
    assert controller.snapshot().state == DISCONNECTED


def test_attach_adopts_a_running_tunnel(controller, config):
    _make_socket(config)
    controller.attach()
    assert FakeClient.latest().is_open
    assert "state on" in FakeClient.latest().commands


def test_controller_uses_real_subprocess_by_default(config, connections, history):
    """Guard against a fixture accidentally becoming the production default."""
    plain = OpenVpnController(config, connections=connections, history=history)
    assert plain._run is subprocess.run


def test_a_store_error_is_translated_to_vpn_error(controller):
    """The route layer only knows VpnError, so nothing storage-shaped may escape connect()."""
    with pytest.raises(VpnError, match="No connection named"):
        controller.connect("nope", "123456")


def test_connecting_with_a_locked_vault_fails_cleanly(
    config, history, vpn_dir, app_db, stored_connection
):
    """A signed-in session can outlive the process that held the key; say so, do not crash."""
    from app.services.connections import Connections
    from app.services.vault import VaultLocked, VaultState

    locked = Connections(app_db, VaultState(), vpn_dir)
    controller = OpenVpnController(config, connections=locked, history=history)
    with pytest.raises(VaultLocked):
        controller.connect("client", "123456")


def test_a_foreign_openvpn_process_is_reported_as_unmanaged(controller, config):
    """A tunnel started by scripts/vpn-connect.sh has its management interface elsewhere."""
    config.pid_file.write_text(f"{os.getpid()}\n")
    status = controller.snapshot()
    assert status.state == UNMANAGED
    assert status.to_dict()["controllable"] is False
    assert "did not start" in status.detail


def test_unmanaged_process_can_still_be_stopped_via_the_helper(controller, config):
    config.pid_file.write_text(f"{os.getpid()}\n")
    controller.disconnect()
    assert controller.runner.calls[-1] == [SUDO, "-n", str(config.HELPER), "stop"]


def test_a_failed_attempt_tears_down_the_stuck_daemon(controller, config):
    """OpenVPN left waiting at its credential prompt must not survive the failure."""
    client = _start(controller, config)
    client.emit("PASSWORD", "Verification Failed: 'Auth'")
    assert wait_for(lambda: controller.snapshot().state == FAILED)
    assert wait_for(lambda: "signal SIGTERM" in client.commands)


def test_teardown_falls_back_to_the_helper_when_the_socket_is_gone(controller, config):
    _make_socket(config)
    controller.connect("client", "123456")
    assert wait_for(lambda: FakeClient.instances != [])
    FakeClient.latest().close()
    FakeClient.latest().emit("DISCONNECTED", "")
    assert wait_for(lambda: controller.snapshot().state in (FAILED, DISCONNECTED), timeout=20)
    assert wait_for(
        lambda: [c for c in controller.runner.calls if c[-1] == "stop"] != [], timeout=20
    )


def test_a_connected_tunnel_is_never_torn_down_by_a_late_failure(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.0.0.2,,,,")
    assert wait_for(lambda: controller.snapshot().state == CONNECTED)
    controller._abort_daemon()
    assert "signal SIGTERM" not in client.commands


def test_routes_are_empty_while_nothing_is_running(controller):
    assert controller.routes() == []
    assert not [call for call in controller.runner.calls if "route" in call]


def test_routes_are_read_for_the_configured_device(controller, config):
    config.pid_file.write_text(f"{os.getpid()}\n")
    routes = controller.routes()
    assert [route.destination for route in routes] == [
        "5.20.0.0/14",
        "10.100.0.0/18",
        "14.70.228.6",
        "10.99.0.0/23",
    ]
    assert controller.runner.calls[-1] == ["ip", "-json", "-4", "route", "show"]


def test_routes_include_the_bypass_route_once_the_server_is_known(controller, config):
    client = _start(controller, config)  # before the pid file: connect() refuses if one is running
    config.pid_file.write_text(f"{os.getpid()}\n")
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.99.1.21,14.75.69.22,,,")
    assert wait_for(lambda: controller.snapshot().state == CONNECTED)
    assert [route.destination for route in controller.routes() if route.kind == "bypass"] == [
        "14.75.69.22"
    ]


def test_the_tun_device_comes_from_config(config, connections, history):
    """Both the address lookup and the route list must follow VPN_CONNECT_TUN_DEVICE."""
    from dataclasses import replace as _replace

    from tests.conftest import FakeClient as _FakeClient
    from tests.conftest import FakeRunner as _FakeRunner

    runner = _FakeRunner()
    instance = OpenVpnController(
        _replace(config, TUN_DEVICE="tun7"),
        connections=connections,
        history=history,
        runner=runner,
        client_factory=_FakeClient,
    )
    instance._tun_address()
    assert runner.calls[-1] == ["ip", "-brief", "-4", "addr", "show", "tun7"]


# --- notifications on state transitions ------------------------------------
#
# The reason a tunnel went down is knowable only in the controller: OpenVPN's own --down hook
# fired identically for both cases, which is what the retired marker file existed to work around.


def _connect(controller, config):
    client = _start(controller, config)
    client.emit("PASSWORD", "Need 'Auth' username/password SC:1,Enter Authenticator Code")
    client.emit("STATE", "1755600000,CONNECTED,SUCCESS,10.0.0.2,52.1.1.1,,,")
    assert wait_for(lambda: controller.snapshot().state == CONNECTED)
    return client


def test_coming_up_notifies_once(controller, config, notifier):
    _connect(controller, config)
    assert [kind for kind, _ in notifier.sent] == ["up"]


def test_the_up_notification_carries_the_tunnel_details(controller, config, notifier):
    _connect(controller, config)
    _, context = notifier.sent[0]
    assert context.tun_ip == "10.0.0.2"
    assert context.server_ip == "52.1.1.1"


def test_pressing_disconnect_notifies_as_operator_requested(controller, config, notifier):
    client = _connect(controller, config)
    controller.disconnect()
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    assert notifier.sent[1][0] == "down_manual"


def test_a_down_notification_still_knows_how_long_the_tunnel_was_up(controller, config, notifier):
    """The transition being announced is the same one that clears connected_since, so reading
    the uptime after the change reported "an unknown time" for every disconnect."""
    client = _connect(controller, config)
    controller.disconnect()
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    _, context = notifier.sent[1]
    assert context.uptime_seconds is not None
    assert context.tun_ip == "10.0.0.2"


def test_a_severed_link_notifies_as_a_drop(controller, config, notifier):
    client = _connect(controller, config)
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    assert notifier.sent[1][0] == "down_severed"


def test_a_socket_that_closes_under_a_live_tunnel_is_a_drop(controller, config, notifier):
    client = _connect(controller, config)
    client.emit("DISCONNECTED", "")
    assert wait_for(lambda: len(notifier.sent) == 2)
    assert notifier.sent[1][0] == "down_severed"


def test_a_failed_attempt_never_reports_a_tunnel_going_down(controller, config, notifier):
    """Nothing came up, so nothing went down -- the operator must not be told otherwise."""
    _start(controller, config)
    controller._fail("Authentication rejected")
    assert wait_for(lambda: controller.snapshot().state == FAILED)
    assert notifier.sent == []


def test_a_drop_is_only_reported_once(controller, config, notifier):
    client = _connect(controller, config)
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    client.emit("DISCONNECTED", "")
    assert notifier.sent[1:] == notifier.sent[1:2]


def test_reconnecting_notifies_again(controller, config, notifier):
    client = _connect(controller, config)
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    _connect(controller, config)
    assert [kind for kind, _ in notifier.sent] == ["up", "down_severed", "up"]


def test_transitions_are_written_to_the_event_log(controller, config, notifier, history):
    client = _connect(controller, config)
    controller.disconnect()
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    events = history.recent_events(limit=10)
    assert any(line.endswith(" UP") for line in events)
    assert any("DOWN operator-requested" in line for line in events)


def test_a_drop_is_logged_as_link_lost(controller, config, notifier, history):
    client = _connect(controller, config)
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: len(notifier.sent) == 2)
    assert any("DOWN link-lost" in line for line in history.recent_events())


def test_a_notifier_that_throws_cannot_break_a_disconnect(controller, config, notifier):
    """A push is an annoyance to lose; a disconnect is not."""
    client = _connect(controller, config)
    notifier.explode = True
    controller.disconnect()
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: controller.snapshot().state == DISCONNECTED)


def test_no_notification_without_a_state_change(controller, config, notifier):
    _connect(controller, config)
    controller._on_state("1755600001,CONNECTED,SUCCESS,10.0.0.2,52.1.1.1,,,")
    assert [kind for kind, _ in notifier.sent] == ["up"]


# --- traffic sampling ------------------------------------------------------


def test_a_bytecount_event_is_recorded(controller, config, history):
    """The wiring that matters: OpenVPN's counters used to be overwritten and thrown away."""
    client = _connect(controller, config)
    client.emit("BYTECOUNT", "4096,2048")
    client.emit("BYTECOUNT", "8192,4096")
    samples = history.samples(history.session_id)
    assert [(s[1], s[2]) for s in samples] == [(4096, 2048), (8192, 4096)]


def test_samples_still_update_the_live_totals(controller, config):
    client = _connect(controller, config)
    client.emit("BYTECOUNT", "4096,2048")
    assert controller.snapshot().bytes_in == 4096
    assert controller.snapshot().bytes_out == 2048


def test_a_malformed_bytecount_records_nothing(controller, config, history):
    client = _connect(controller, config)
    client.emit("BYTECOUNT", "not,numbers")
    client.emit("BYTECOUNT", "onlyone")
    assert history.samples(history.session_id) == []


def test_samples_belong_to_the_attempt_that_produced_them(controller, config, history):
    client = _connect(controller, config)
    client.emit("BYTECOUNT", "100,100")
    first = history.session_id
    client.emit("STATE", "1755600100,EXITING,exit-with-notification,,,,,")
    assert wait_for(lambda: controller.snapshot().state == DISCONNECTED)

    client = _connect(controller, config)
    client.emit("BYTECOUNT", "999,999")
    assert len(history.samples(first)) == 1
    assert history.samples(history.session_id)[0][1] == 999


def test_a_reattached_tunnel_gets_a_session_to_record_into(controller, config, history):
    """Re-adopting a running tunnel used to log and sample nowhere at all."""
    _make_socket(config)
    controller.attach()
    assert history.session_id is not None
