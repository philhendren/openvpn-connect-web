"""Inbound protection on the tunnel interface: one switch, and the truth about whether it is on.

The rule this manages is deliberately *static*. ``iifname "tun*"`` is a per-packet string
comparison, so the ruleset loads while no tun interface exists and starts matching the moment one
appears -- which means it can be armed once and left alone rather than applied when a tunnel comes
up. Applying it on connect would leave a window in which the tunnel is up and unfiltered, which is
the exact exposure this feature exists to close, and would lose its state whenever the app
restarted. So the toggle means *armed*, not *apply now*: the same reasoning as
``connections.ignore_pushed_dns`` being a flag rather than an edit to the stored profile.

Two consequences shape this module:

* **Intent and reality are separate, and only reality may be reported.** The database stores what
  the operator asked for; :meth:`Firewall.state` asks the helper what is actually loaded. A switch
  showing "on" while nothing is filtering is the worst outcome this feature can produce, so the
  UI is fed the helper's answer and a disagreement between the two is surfaced loudly. This is the
  same "report what is actually true, not what was configured" rule the rest of the app follows,
  applied where it matters most.
* **A failure to arm is not like a failure to apply DNS rules.** There, a failed apply left DNS
  as it was and degraded to a warning. Here a failed apply leaves the box *unprotected*, so the
  warning is not cosmetic and :meth:`guard_connect` refuses to start a tunnel when the operator
  asked for protection and the helper says there is none.

Nothing here is privileged. Every root operation is one of three argument-less helper verbs --
``fw-on``, ``fw-off``, ``fw-status`` -- whose ruleset is a literal inside the root-owned helper.
The app cannot express a rule, only choose between two predefined states.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

from app.config import Config
from app.services import store
from app.services.rooted import HelperError, run_helper

log = logging.getLogger(__name__)

#: Settings key holding the operator's intent. Plain "1"/"0" in the existing key-value table --
#: this feature needs no migration.
SETTING = "block_tun_inbound"

ARMED = "armed"
DISARMED = "disarmed"
UNAVAILABLE = "unavailable"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class FirewallState:
    """What the helper says is actually loaded, plus what the operator asked for.

    ``status`` is one of ``armed``, ``disarmed``, ``unavailable`` (no nftables on the box) or
    ``unknown`` (the helper could not be reached at all -- typically not installed yet).
    """

    status: str
    intended: bool
    drops: int = 0
    detail: str = ""

    @property
    def armed(self) -> bool:
        return self.status == ARMED

    @property
    def mismatch(self) -> bool:
        """Protection was asked for and is not in force -- or is in force and was not asked for.

        The first case is the dangerous one and the reason this property exists: it is what the
        banner reads, and what :meth:`Firewall.guard_connect` refuses to connect through.
        """
        return self.intended != self.armed

    @property
    def unprotected(self) -> bool:
        """Asked for, not in force. The only combination that warrants an alarm."""
        return self.intended and not self.armed

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "armed": self.armed,
            "intended": self.intended,
            "drops": self.drops,
            "mismatch": self.mismatch,
            "unprotected": self.unprotected,
            "detail": self.detail,
        }


def parse_status(text: str) -> tuple[str, int]:
    """Read the helper's one-line ``fw-status`` answer into a status and a drop count.

    The helper prints ``armed <n> [<n>...]`` -- one counter per drop rule, since there is one in
    the input chain and one in the forward chain -- or ``disarmed``, or ``unavailable <why>``.
    Pure string work with no I/O, so every shape it can return is cheap to test.

    Unrecognised output is ``unknown`` rather than a guess: an unparseable answer must never be
    read as "armed", which would report protection that may not exist.
    """
    first, _, rest = text.strip().partition("\n")
    parts = first.split()
    if not parts:
        return UNKNOWN, 0
    head = parts[0]
    if head == DISARMED:
        return DISARMED, 0
    if head == UNAVAILABLE:
        return UNAVAILABLE, 0
    if head == ARMED:
        # Sum the chains rather than reporting the first: "how much has this dropped" is one
        # question, and splitting it per chain would invite reading input-only and calling it zero.
        total = 0
        for token in parts[1:]:
            if token.isdigit():
                total += int(token)
        return ARMED, total
    del rest
    return UNKNOWN, 0


class FirewallUnavailable(RuntimeError):
    """Raised when protection was asked for and is not actually in force."""


class Firewall:
    """The toggle, and the one place that asks the helper about the tunnel's inbound filter."""

    def __init__(self, db, config: Config, *, runner=subprocess.run) -> None:
        self._db = db
        self._config = config
        self._run = runner

    # -- intent -------------------------------------------------------------

    def intended(self) -> bool:
        return store.get_setting(self._db, SETTING, "0") == "1"

    # -- reality ------------------------------------------------------------

    def state(self) -> FirewallState:
        """Ask the helper what is loaded. Never raises: a broken check must not break the page.

        Deliberately *not* called from the polled status endpoint -- it shells out through sudo,
        and doing that every few seconds to answer a question that changes only when somebody
        touches the switch is the same reasoning that keeps ``/api/dns`` and ``/api/dns/status``
        apart.
        """
        intended = self.intended()
        try:
            result = self._helper("fw-status")
        except HelperError as exc:
            # Overwhelmingly the "installed helper predates this verb" case, which the deployment
            # self-check reports properly. Unknown, not disarmed: we genuinely do not know.
            log.info("could not read the firewall state: %s", exc)
            return FirewallState(status=UNKNOWN, intended=intended, detail=str(exc))
        status, drops = parse_status(result.stdout or "")
        detail = ""
        if status == UNAVAILABLE:
            detail = (result.stdout or "").strip()
        return FirewallState(status=status, intended=intended, drops=drops, detail=detail)

    # -- switching ----------------------------------------------------------

    def set_intent(self, on: bool) -> FirewallState:
        """Record the intent, act on it, and report back what is *actually* true afterwards.

        The intent is written first and kept even if the helper call fails, so the operator's
        answer is not silently discarded by a transient failure -- but the state returned is read
        back from the helper, so the UI never shows a switch position as though it were evidence.
        """
        if on:
            # Refuse to *record* an intent this box cannot honour. Without this check, arming on a
            # machine whose installed helper predates these verbs would store intent=1, fail to
            # arm, and then guard_connect() would refuse every connection -- locking the operator
            # out of their own VPN moments after an upgrade. Switching off is always permitted,
            # whatever state the helper is in, because that is the way out.
            capability = self.state()
            if capability.status in (UNAVAILABLE, UNKNOWN):
                raise FirewallUnavailable(
                    "Inbound protection cannot be switched on: "
                    f"{capability.detail or capability.status}. "
                    "Nothing has been changed."
                )

        store.set_setting(self._db, SETTING, "1" if on else "0")
        try:
            self._helper("fw-on" if on else "fw-off")
        except HelperError as exc:
            log.warning("could not %s the tunnel filter: %s", "arm" if on else "disarm", exc)
            return FirewallState(status=UNKNOWN, intended=on, detail=str(exc))
        return self.state()

    def reconcile(self) -> FirewallState:
        """Make reality match intent if it does not already, and return the result.

        Called when somebody looks at the page rather than on a timer. The ruleset does not
        survive a reboot on its own, and the app is what starts at boot -- so this is what makes
        the switch mean something across a restart of either the box or the service. Idempotent
        and cheap when nothing is wrong, because the common case is one ``fw-status`` call.
        """
        current = self.state()
        # Only ever in the protective direction. A filter that is loaded while the setting says
        # off is left alone: somebody may have armed it by hand, and quietly tearing down
        # protection because a database row disagrees is the one repair that can make this
        # machine less safe than it was. Removing it stays a deliberate act -- the switch.
        if not current.unprotected or current.status in (UNAVAILABLE, UNKNOWN):
            return current
        log.info("re-arming the tunnel filter, which is switched on but not in force")
        return self.set_intent(True)

    # -- the guard ----------------------------------------------------------

    def guard_connect(self) -> None:
        """Refuse to bring a tunnel up unprotected when protection was asked for.

        This is the whole point of the feature being in the app rather than a note in a runbook:
        the moment that matters is the one before the tunnel exists. One attempt to fix it first,
        because the usual cause is a restart having cleared the ruleset, and only then a refusal.
        """
        if not self.intended():
            return
        state = self.reconcile()
        if state.armed:
            return
        raise FirewallUnavailable(
            "Inbound protection on the tunnel is switched on but is not in force, so connecting "
            "would expose this machine to the remote network. "
            f"({state.detail or state.status}) "
            "Fix the filter, or switch the protection off to connect without it."
        )

    # -- plumbing -----------------------------------------------------------

    def _helper(self, action: str) -> subprocess.CompletedProcess[str]:
        return run_helper(
            helper=self._config.HELPER,
            action=action,
            runner=self._run,
            timeout=self._config.COMMAND_TIMEOUT_SECONDS,
        )
