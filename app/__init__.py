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
from app.services import vault
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
