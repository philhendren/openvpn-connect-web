"""Inbound protection on the tunnel: the switch, and the refusal to lie about it.

The argv assertions here are the same standing defence as ``test_openvpn.py``'s: the three verbs
take no arguments at all, and a future change that starts passing one -- an interface name, a
rule, a path -- should fail a test rather than quietly widen what the app can ask root to do.
"""

from __future__ import annotations

import pytest

from app.services import firewall as fw
from app.services import store
from app.services.firewall import Firewall, FirewallUnavailable
from app.services.rooted import SUDO
from tests.conftest import FakeClient, FakeRunner, quiesce

#: Sentinel for a scripted verb that should fail rather than answer.
FAIL = "<fail>"

# -- parsing ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("disarmed", (fw.DISARMED, 0)),
        ("armed 0 0", (fw.ARMED, 0)),
        ("armed 12 30", (fw.ARMED, 42)),
        ("armed 7", (fw.ARMED, 7)),
        ("armed", (fw.ARMED, 0)),
        ("unavailable nftables is not installed", (fw.UNAVAILABLE, 0)),
        ("armed 5 3\ntrailing noise", (fw.ARMED, 8)),
        ("  armed 1 1  \n", (fw.ARMED, 2)),
    ],
)
def test_status_lines_parse(text, expected):
    assert fw.parse_status(text) == expected


@pytest.mark.parametrize("text", ["", "   ", "yes", "ARMED 5", "something else entirely"])
def test_output_that_is_not_understood_is_never_read_as_armed(text):
    """An unparseable answer must not become "protected". Unknown is the only safe reading."""
    status, drops = fw.parse_status(text)
    assert status == fw.UNKNOWN
    assert drops == 0


def test_counters_from_both_chains_are_summed():
    """One drop rule in input and one in forward, so reporting the first would under-report.

    Reading input alone on a box whose exposure is a forwarded container port would show zero
    and imply nothing had been stopped.
    """
    assert fw.parse_status("armed 4 96") == (fw.ARMED, 100)


# -- the verbs --------------------------------------------------------------


def test_the_helper_verbs_take_no_arguments(app_db, config):
    """The whole privilege argument for this feature rests on this being true."""
    runner = FakeRunner(stdout="armed 0 0")
    firewall = Firewall(app_db, config, runner=runner)

    firewall.set_intent(True)
    firewall.set_intent(False)
    firewall.state()

    assert runner.calls, "the helper was never invoked"
    for call in runner.calls:
        # sudo -n <helper> <verb>, and nothing after the verb. Four elements exactly: a fifth
        # would mean something from the app had started crossing into root.
        assert call[0] == SUDO
        assert call[1] == "-n"
        assert call[2] == str(config.HELPER)
        assert len(call) == 4, f"a verb gained an argument: {call!r}"

    verbs = [call[3] for call in runner.calls]
    assert verbs == [
        "fw-status",  # can this box do it at all? see the capability gate
        "fw-on",
        "fw-status",  # what is actually true now
        "fw-off",
        "fw-status",
        "fw-status",
    ]


def test_arming_records_intent_and_reports_what_is_actually_loaded(app_db, config):
    runner = FakeRunner(stdout="armed 0 0")
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.set_intent(True)

    assert store.get_setting(app_db, fw.SETTING) == "1"
    assert state.armed is True
    assert state.intended is True
    assert state.mismatch is False


def test_disarming_clears_intent(app_db, config):
    runner = FakeRunner(stdout="disarmed")
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.set_intent(False)

    assert store.get_setting(app_db, fw.SETTING) == "0"
    assert state.armed is False
    assert state.unprotected is False


# -- the part that must not lie ---------------------------------------------


def test_a_switch_that_is_on_while_nothing_filters_reports_unprotected(app_db, config):
    """The failure this feature must never hide: asked for, and not in force."""
    store.set_setting(app_db, fw.SETTING, "1")
    firewall = Firewall(app_db, config, runner=FakeRunner(stdout="disarmed"))

    state = firewall.state()

    assert state.intended is True
    assert state.armed is False
    assert state.unprotected is True
    assert state.mismatch is True


def test_a_failed_arm_keeps_the_intent_but_does_not_claim_success(app_db, config):
    """Intent is the operator's answer and survives; the reported state stays honest."""
    runner = _ScriptedRunner(["disarmed", FAIL])
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.set_intent(True)

    assert store.get_setting(app_db, fw.SETTING) == "1"
    assert state.armed is False
    assert state.unprotected is True
    assert "nftables rejected the ruleset" in state.detail


def test_an_uninstalled_helper_is_unknown_rather_than_disarmed(app_db, config):
    """ "We cannot tell" and "it is off" are different answers and must not be conflated."""
    runner = FakeRunner()
    runner.side_effect = FileNotFoundError("no such helper")
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.state()

    assert state.status == fw.UNKNOWN
    assert state.armed is False


def test_a_box_without_nftables_says_so(app_db, config):
    firewall = Firewall(app_db, config, runner=FakeRunner(stdout="unavailable nftables is missing"))

    state = firewall.state()

    assert state.status == fw.UNAVAILABLE
    assert "nftables is missing" in state.detail


# -- reconciling ------------------------------------------------------------


def test_reconcile_reapplies_when_intent_and_reality_disagree(app_db, config):
    """What makes the switch survive a reboot: the ruleset does not persist, the setting does."""
    store.set_setting(app_db, fw.SETTING, "1")
    runner = _ScriptedRunner(["disarmed", "disarmed", "armed 0 0", "armed 0 0"])
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.reconcile()

    assert state.armed is True
    assert runner.actions == ["fw-status", "fw-status", "fw-on", "fw-status"]


def test_reconcile_does_nothing_when_they_already_agree(app_db, config):
    store.set_setting(app_db, fw.SETTING, "1")
    runner = _ScriptedRunner(["armed 3 4"])
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.reconcile()

    assert state.drops == 7
    assert runner.actions == ["fw-status"], "a matching state must not be re-applied"


def test_reconcile_does_not_thrash_when_nftables_is_missing(app_db, config):
    """Retrying an apply on a box that cannot do it would just log the same failure forever."""
    store.set_setting(app_db, fw.SETTING, "1")
    runner = _ScriptedRunner(["unavailable nftables is missing"])
    firewall = Firewall(app_db, config, runner=runner)

    firewall.reconcile()

    assert runner.actions == ["fw-status"]


# -- the guard --------------------------------------------------------------


def test_guard_allows_a_connect_when_protection_was_never_asked_for(app_db, config):
    firewall = Firewall(app_db, config, runner=_ScriptedRunner([]))
    firewall.guard_connect()  # must not raise, and must not call the helper at all


def test_guard_allows_a_connect_once_the_filter_is_in_force(app_db, config):
    store.set_setting(app_db, fw.SETTING, "1")
    firewall = Firewall(app_db, config, runner=_ScriptedRunner(["armed 0 0"]))
    firewall.guard_connect()


def test_guard_repairs_before_it_refuses(app_db, config):
    """A restart clears the ruleset, so the common case is fixable rather than fatal."""
    store.set_setting(app_db, fw.SETTING, "1")
    runner = _ScriptedRunner(["disarmed", "disarmed", "armed 0 0", "armed 0 0"])
    firewall = Firewall(app_db, config, runner=runner)

    firewall.guard_connect()

    assert "fw-on" in runner.actions


def test_guard_refuses_when_protection_cannot_be_established(app_db, config):
    store.set_setting(app_db, fw.SETTING, "1")
    runner = _ScriptedRunner(["disarmed", "disarmed", FAIL, "disarmed"])
    firewall = Firewall(app_db, config, runner=runner)

    with pytest.raises(FirewallUnavailable) as excinfo:
        firewall.guard_connect()

    message = str(excinfo.value)
    assert "would expose this machine" in message
    assert "switch the protection off" in message, "a refusal must name the way out"


# -- helpers ----------------------------------------------------------------


class _ScriptedRunner:
    """A FakeRunner that answers a queue of stdout lines and records the verbs it was asked for.

    The order matters in these tests -- reconcile is status, then maybe apply, then status -- and
    a single canned answer cannot express that.
    """

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.actions: list[str] = []

    def __call__(self, argv, **_kwargs):
        self.actions.append(argv[-1])
        answer = self._answers.pop(0) if self._answers else ""
        if isinstance(answer, Exception):
            raise answer
        if answer == FAIL:
            return _Result("", returncode=1, stderr="nftables rejected the ruleset")
        return _Result(answer)


class _Result:
    def __init__(self, stdout: str, returncode: int = 0, stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# -- the tunnel does not come up unprotected --------------------------------


def test_connect_is_refused_before_anything_is_started(app_db, config, connections, history):
    """The guard runs before the connection is even resolved, so nothing is started at all.

    This is the assertion that matters: not just that connect() raises, but that the helper was
    never asked to start openvpn. A refusal that still brought the tunnel up would be worse than
    no check.
    """
    from app.services.openvpn import OpenVpnController, VpnError

    store.set_setting(app_db, fw.SETTING, "1")
    helper_runner = FakeRunner(stdout="started")
    controller = OpenVpnController(
        config,
        connections=connections,
        history=history,
        runner=helper_runner,
        client_factory=FakeClient,
        firewall=Firewall(
            app_db, config, runner=_ScriptedRunner(["disarmed", "disarmed", "disarmed"])
        ),
    )

    with pytest.raises(VpnError, match="would expose this machine"):
        controller.connect("client", "123456")

    assert helper_runner.calls == [], "openvpn must not be started when protection is missing"


def test_connect_proceeds_when_the_filter_is_in_force(
    app_db, config, connections, history, stored_connection
):
    """The guard must not become a way to never connect."""
    from app.services.openvpn import OpenVpnController

    store.set_setting(app_db, fw.SETTING, "1")
    controller = OpenVpnController(
        config,
        connections=connections,
        history=history,
        runner=FakeRunner(stdout="started"),
        client_factory=FakeClient,
        firewall=Firewall(app_db, config, runner=_ScriptedRunner(["armed 0 0"])),
    )
    config.MGMT_SOCKET.write_bytes(b"")

    controller.connect(stored_connection.name, "123456")

    quiesce(controller)


# -- the endpoints ----------------------------------------------------------


def test_the_endpoint_reports_state_rather_than_the_last_thing_posted(auth_client, app_db):
    """A GET must answer with what the helper says, not with the stored setting."""
    store.set_setting(app_db, fw.SETTING, "1")

    body = auth_client.get("/api/firewall").get_json()

    # The fixture runner answers "disarmed", so this is the dangerous combination.
    assert body["intended"] is True
    assert body["armed"] is False
    assert body["unprotected"] is True


def test_posting_the_switch_returns_the_state_it_actually_achieved(auth_client, firewall_runner):
    firewall_runner.stdout = "armed 0 0"

    body = auth_client.post(
        "/api/firewall",
        json={"enabled": True},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    ).get_json()

    assert body["armed"] is True
    assert body["intended"] is True


def test_the_endpoint_rejects_anything_that_is_not_a_boolean(auth_client):
    response = auth_client.post(
        "/api/firewall",
        json={"enabled": "maybe"},
        headers={"X-CSRF-Token": auth_client.csrf_token},
    )
    assert response.status_code == 400


def test_the_endpoint_needs_a_session(client):
    assert client.get("/api/firewall").status_code == 401


def test_arming_is_refused_when_the_installed_helper_cannot_do_it(app_db, config):
    """The lockout this gate exists to prevent.

    Without it, arming on a box whose helper predates these verbs would store intent=1, fail to
    apply, and then every subsequent connect would be refused by the guard -- the operator locked
    out of their own VPN by a switch that never worked. Nothing is stored, so nothing is broken.
    """
    runner = _ScriptedRunner([FileNotFoundError("helper predates fw-on")])
    firewall = Firewall(app_db, config, runner=runner)

    with pytest.raises(FirewallUnavailable, match="Nothing has been changed"):
        firewall.set_intent(True)

    assert store.get_setting(app_db, fw.SETTING, "0") == "0"
    assert runner.actions == ["fw-status"], "it must not attempt the apply"


def test_switching_off_always_works_even_when_the_helper_is_broken(app_db, config):
    """Turning it off is the documented way out of a refusal, so it can never be gated."""
    store.set_setting(app_db, fw.SETTING, "1")
    firewall = Firewall(app_db, config, runner=_ScriptedRunner([FAIL]))

    state = firewall.set_intent(False)

    assert store.get_setting(app_db, fw.SETTING) == "0"
    assert state.unprotected is False, "off and unfiltered is a consistent, safe state"


def test_reconcile_never_tears_down_protection_it_did_not_ask_for(app_db, config):
    """A loaded filter with the switch off is left alone, not removed.

    Reconciling in both directions looked symmetrical and was not: somebody may have armed the
    filter by hand, and removing it because a database row disagrees is the one repair that can
    leave this machine less protected than it was found. Only the protective direction is
    automatic; taking protection away stays a deliberate act.
    """
    store.set_setting(app_db, fw.SETTING, "0")
    runner = _ScriptedRunner(["armed 9 1"])
    firewall = Firewall(app_db, config, runner=runner)

    state = firewall.reconcile()

    assert runner.actions == ["fw-status"], "it must not run fw-off"
    assert state.armed is True
    assert state.mismatch is True, "the disagreement is still reported, just not acted on"
