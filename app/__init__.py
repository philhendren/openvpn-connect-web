"""Application factory for the OpenVPN control panel."""

from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any

import click
from flask import Flask, jsonify, request

from app.auth import CsrfError, hash_password
from app.config import Config, load_config
from app.db import open_migrated
from app.services import access, vault
from app.services.connections import Connections
from app.services.dns_rules import DnsRules
from app.services.history import History
from app.services.notifications import Notifier
from app.services.openvpn import OpenVpnController
from app.services.vault import VaultState

__all__ = ["create_app"]


def create_app(overrides: Mapping[str, Any] | None = None) -> Flask:
    """Build the app.

    ``overrides`` lets tests swap in a fake :class:`~app.services.openvpn.OpenVpnController`
    (key ``CONTROLLER``) and a throwaway :class:`~app.config.Config` (key ``APP_CONFIG``) so
    nothing touches the real system.
    """
    app = Flask(__name__)
    app.config.from_mapping(load_config())
    if overrides:
        app.config.update(overrides)

    config: Config = app.config["APP_CONFIG"]
    app.config["SECRET_KEY"] = config.SECRET_KEY
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=config.SESSION_HOURS)
    app.config.setdefault("CONTROLLER", None)
    app.config.setdefault("NOTIFIER", None)
    app.config.setdefault("DB", None)
    app.config.setdefault("VAULT", None)
    # Both only ever read by the deployment self-check. SOURCE_ROOT is the checkout this process
    # was imported from, which is the thing the installed helper and the database are compared
    # against; STARTED_AT is what makes "edited after we started" answerable at all.
    app.config.setdefault("SOURCE_ROOT", Path(app.root_path).parent)
    app.config.setdefault("STARTED_AT", time.time())

    logging.basicConfig(
        level=logging.DEBUG if app.debug else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    # Parsed once, here, rather than per request: a malformed CIDR is a refusal to start with an
    # allowlist nobody can be sure of, not a 500 on whichever request happens to arrive first.
    app.config.setdefault("ALLOW_NETWORKS", access.parse_allow_from(config.ALLOW_FROM))
    app.config.setdefault(
        "TRUSTED_PROXY_NETWORKS",
        access.parse_networks(config.TRUSTED_PROXIES, "VPN_CONNECT_TRUSTED_PROXIES"),
    )
    app.logger.info("Allowing requests from %s", access.describe(app.config["ALLOW_NETWORKS"]))
    # Logged either way: "is the proxy header being believed?" is the first thing worth knowing
    # when a lockout attributes every attempt to 127.0.0.1.
    if app.config["TRUSTED_PROXY_NETWORKS"]:
        app.logger.info(
            "Trusting X-Forwarded-For from %s",
            access.describe(app.config["TRUSTED_PROXY_NETWORKS"]),
        )
    else:
        app.logger.info("Not trusting X-Forwarded-For from anywhere")

    # SQLite is opened and migrated at startup: a schema older than the code is a startup
    # failure, not something to discover on the first query. threadsafety is 3, so one
    # connection is shared across gunicorn's threads.
    if app.config["DB"] is None:
        app.config["DB"] = open_migrated(config.database)
    if app.config["VAULT"] is None:
        app.config["VAULT"] = VaultState()

    app.config.setdefault(
        "CONNECTIONS", Connections(app.config["DB"], app.config["VAULT"], config.VPN_DIR)
    )
    app.config.setdefault("HISTORY", History(app.config["DB"]))
    app.config.setdefault("DNS_RULES", DnsRules(app.config["DB"], config))

    # One notifier, shared: the controller fires it on tunnel transitions and /api/notify/test
    # sends through the same object, so a working test really does prove the live path.
    if app.config["NOTIFIER"] is None:
        app.config["NOTIFIER"] = Notifier(config, app.config["DB"])

    if app.config["CONTROLLER"] is None:
        app.config["CONTROLLER"] = OpenVpnController(
            config,
            connections=app.config["CONNECTIONS"],
            history=app.config["HISTORY"],
            notifier=app.config["NOTIFIER"],
        )
        if not app.testing:
            app.config["CONTROLLER"].attach()

    from app.routes.api import bp as api_bp
    from app.routes.ui import bp as ui_bp

    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)

    @app.before_request
    def _enforce_allowlist():
        """Refuse anything not on the allowlist, before any route sees it.

        Registered on the app rather than a blueprint so it covers every path -- static files and
        the login form included. Returning a response here short-circuits the request, so nothing
        below this point runs for a denied peer: no session load, no CSRF check, no login attempt
        and therefore no way to consume the lockout budget of a legitimate user.
        """
        if access.is_allowed(request.remote_addr, app.config["ALLOW_NETWORKS"]):
            return None
        app.logger.warning("Refused %s for %s", request.remote_addr, request.path)
        # Says how to fix it on purpose. The likely reader is the operator who just widened BIND
        # without widening this, and the alternative to naming the setting is a bare 403 that
        # looks like the app is broken. A denied peer learns an environment variable name, which
        # it cannot read, so there is nothing here worth withholding.
        return (
            "Forbidden: this address is not in VPN_CONNECT_ALLOW_FROM.\n"
            "Re-run sudo ./deploy/install.sh to change which addresses may connect.\n",
            403,
            {"Content-Type": "text/plain; charset=utf-8"},
        )

    @app.errorhandler(CsrfError)
    def _csrf_failed(exc: CsrfError):
        if request.path.startswith("/api/"):
            return jsonify(error=str(exc)), 400
        return f"{exc}", 400

    @app.after_request
    def _security_headers(response):
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.cli.command("set-password")
    @click.argument("password", required=False)
    def set_password(password: str | None) -> None:
        """Print the VPN_CONNECT_PASSWORD_HASH line for the web UI login.

        If a vault already exists, this also re-encrypts every stored secret under the new
        password -- without that the connections in the database become unreadable forever, so
        the old password is asked for rather than assumed absent.

        **Everything except the hash line goes to stderr.** The documented usage appends this
        command's output to the environment file, so a prompt, a progress line or a mistyped
        confirmation printed on stdout lands in that file as a line systemd cannot parse. That
        is not hypothetical: it is how the operator's env file ended up holding "Error: The two
        entered values do not match." as though it were a setting.
        """
        password = password or click.prompt(
            "New web UI password", hide_input=True, confirmation_prompt=True, err=True
        )
        db = app.config["DB"]
        if vault.exists(db):
            click.echo("A vault exists, so the stored connections must be re-encrypted.", err=True)
            old = click.prompt("Current web UI password", hide_input=True, err=True)
            try:
                vault.rekey(db, old, password)
            except vault.VaultError as exc:
                raise click.ClickException(f"{exc} Nothing was changed.") from exc
            click.echo("Stored connections re-encrypted.", err=True)
        click.echo(f"VPN_CONNECT_PASSWORD_HASH='{hash_password(password)}'")

    @app.cli.command("gen-secret")
    def gen_secret() -> None:
        """Print a fresh VPN_CONNECT_SECRET_KEY line."""
        import secrets

        click.echo(f"VPN_CONNECT_SECRET_KEY='{secrets.token_hex(32)}'")

    return app
