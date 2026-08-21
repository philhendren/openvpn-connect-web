"""The one place that shells out to the root helper.

Both the tunnel controller and DNS rule application invoke the same fixed root helper
(``sudo -n <helper> <action> [args]``). The argv construction, timeout handling and
redacted-error wrapping used to live only in :class:`~app.services.openvpn.OpenVpnController`;
a second, unrelated caller needing it verbatim is a sign it belongs here rather than being
duplicated or bolted onto a class whose own docstring says it owns the tunnel's lifecycle.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from app.services.management import redact

log = logging.getLogger(__name__)

SUDO = shutil.which("sudo") or "/usr/bin/sudo"


class HelperError(RuntimeError):
    """Raised for any failure running the root helper -- missing, timed out, or non-zero exit."""


def run_helper(
    *,
    helper: Path,
    action: str,
    args: tuple[str, ...] = (),
    runner,
    timeout: float,
) -> subprocess.CompletedProcess[str]:
    """Run the fixed root helper. ``action``/``args`` are always pre-validated values."""
    argv = [SUDO, "-n", str(helper), action, *args]
    log.info("running %s", " ".join(argv))
    try:
        result = runner(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise HelperError(f"sudo or the helper is not installed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise HelperError(f"'{action}' timed out after {timeout}s.") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip().splitlines()
        hint = message[-1] if message else f"exit status {result.returncode}"
        if "password is required" in hint or "sudo:" in hint:
            hint += " -- is deploy/vpn-connect.sudoers installed?"
        raise HelperError(f"Helper '{action}' failed: {redact(hint)}")
    return result
