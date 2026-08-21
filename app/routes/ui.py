"""HTML pages. Views stay thin: parse input, call a service, render."""

from __future__ import annotations

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from app.auth import (
    LoginThrottle,
    csrf_token,
    is_logged_in,
    log_in,
    log_out,
    login_required,
    unlock_vault,
    validate_csrf,
    verify_password,
)
from app.services import access, store
from app.services.notify import PLACEHOLDERS, TITLES
from app.services.vault import VaultError

bp = Blueprint("ui", __name__)

_throttle: LoginThrottle | None = None


def _get_throttle() -> LoginThrottle:
    global _throttle
    config = current_app.config["APP_CONFIG"]
    if _throttle is None:
        _throttle = LoginThrottle(config.LOGIN_MAX_ATTEMPTS, config.LOGIN_LOCKOUT_SECONDS)
    return _throttle


@bp.get("/favicon.ico")
def favicon():
    """Browsers ask for this at the root whatever the <link> tags say -- serve the mark."""
    return send_from_directory(
        current_app.static_folder, "img/favicon.ico", mimetype="image/vnd.microsoft.icon"
    )


@bp.get("/manifest.webmanifest")
def manifest():
    """Web app manifest.

    This, not the favicon, is what ChromeOS's "Install this page as app" takes its icon from.
    Deliberately public: browsers fetch the manifest without credentials, so requiring a login
    here would leave an installed app with a blank icon.
    """
    return send_from_directory(
        current_app.static_folder, "manifest.webmanifest", mimetype="application/manifest+json"
    )


@bp.route("/login", methods=["GET", "POST"])
def login():
    config = current_app.config["APP_CONFIG"]
    if is_logged_in():
        return redirect(url_for("ui.index"))
    if not config.PASSWORD_HASH:
        return render_template("setup.html"), 503

    # The socket peer, unless a trusted proxy named someone else. Behind `tailscale serve` every
    # peer is 127.0.0.1, which would put every device on the tailnet in one lockout bucket: five
    # fumbled attempts on a phone would lock out the laptop too.
    client = access.client_address(
        request.remote_addr,
        request.headers.get("X-Forwarded-For"),
        current_app.config["TRUSTED_PROXY_NETWORKS"],
    )
    if request.method == "POST":
        locked = _get_throttle().seconds_remaining(client)
        if locked:
            flash(f"Too many attempts. Try again in {locked}s.", "error")
            return render_template("login.html", csrf_token=csrf_token()), 429
        validate_csrf()
        password = request.form.get("password", "")
        if verify_password(password):
            # The same password that proves who you are derives the key that decrypts your
            # connections, so signing in and unlocking are one step.
            try:
                unlock_vault(password)
            except VaultError as exc:
                current_app.logger.error("vault did not unlock after a valid login: %s", exc)
                flash(
                    "Signed in, but the stored connections could not be unlocked. If the login "
                    "password was changed, re-run set-password with the old one to re-encrypt.",
                    "error",
                )
                return render_template("login.html", csrf_token=csrf_token()), 500
            _get_throttle().reset(client)
            log_in()
            target = request.args.get("next", "")
            return redirect(target if target.startswith("/") else url_for("ui.index"))
        _get_throttle().record_failure(client)
        current_app.logger.warning("failed login from %s", client)
        flash("Incorrect password.", "error")
        return render_template("login.html", csrf_token=csrf_token()), 401

    return render_template("login.html", csrf_token=csrf_token())


@bp.post("/logout")
def logout():
    validate_csrf()
    log_out()
    return redirect(url_for("ui.login"))


@bp.get("/")
@login_required
def index():
    config = current_app.config["APP_CONFIG"]
    controller = current_app.config["CONTROLLER"]
    connections = current_app.config["CONNECTIONS"]
    db = current_app.config["DB"]

    entries = connections.list()
    selected = connections.default()
    topic = store.notify_topic(db)
    return render_template(
        "index.html",
        csrf_token=csrf_token(),
        connections=entries,
        selected=selected.name if selected else None,
        challenge_text=selected.static_challenge if selected else config.STATIC_CHALLENGE,
        # Rendered server-side as well as toggled in JS, so the first paint is already right for
        # the pre-selected connection rather than flickering a code box that is not wanted.
        challenge_needed=selected.requires_mfa if selected else True,
        status=controller.snapshot().to_dict(),
        events=controller.recent_events(),
        notify_topic=topic,
        notify_url=f"{config.NTFY_SERVER.rstrip('/')}/{topic}" if topic else None,
        notify_titles=TITLES,
        notify_bodies=store.notify_bodies(db),
        notify_placeholders=PLACEHOLDERS,
    )
