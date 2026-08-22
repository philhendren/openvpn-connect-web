"""JSON endpoints the page polls. State changes are POST + CSRF, never GET."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request

from app.auth import login_required, validate_csrf
from app.db import MIGRATIONS_DIR, schema_version
from app.services import deploy, sessions, store
from app.services.dns import DnsError
from app.services.notifications import NotifyDeliveryError
from app.services.notify import (
    DEFAULT_BODIES,
    MESSAGE_KINDS,
    PLACEHOLDERS,
    TITLES,
    NotifyError,
    validate_topic,
)
from app.services.openvpn import VpnError
from app.services.store import StoreError
from app.services.traffic import DEFAULT_POINTS, series
from app.services.vault import VaultError
from app.services.whois import MAX_BATCH as WHOIS_MAX_BATCH

bp = Blueprint("api", __name__, url_prefix="/api")


def _truthy(value) -> bool:
    """Checkbox semantics: multipart sends "on", JSON sends true, absent means off."""
    return str(value).lower() in {"1", "true", "on", "yes"}


def _controller():
    return current_app.config["CONTROLLER"]


def _notifier():
    return current_app.config["NOTIFIER"]


def _connections():
    return current_app.config["CONNECTIONS"]


def _dns_rules():
    return current_app.config["DNS_RULES"]


def _db():
    return current_app.config["DB"]


@bp.get("/status")
@login_required
def status():
    controller = _controller()
    snapshot = controller.snapshot()
    payload = snapshot.to_dict()
    payload["events"] = controller.recent_events()
    payload["log"] = snapshot.log_lines[-40:]
    return jsonify(payload)


@bp.get("/routes")
@login_required
def routes():
    """The routes installed for the tunnel device.

    Kept out of /api/status on purpose: status is polled every few seconds and this list runs to
    hundreds of rows on a split tunnel.  The page fetches it when the tunnel changes state.
    """
    controller = _controller()
    entries = [route.to_dict() for route in controller.routes()]
    device = current_app.config["APP_CONFIG"].TUN_DEVICE
    return jsonify(device=device, count=len(entries), routes=entries)


@bp.post("/connect")
@login_required
def connect():
    validate_csrf()
    data = request.get_json(silent=True) or request.form
    profile = str(data.get("profile", "")).strip()
    otp = str(data.get("otp", "")).strip()
    try:
        _controller().connect(profile, otp)
    except (VpnError, VaultError) as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(_controller().snapshot().to_dict()), 202


def _notify_payload() -> dict:
    """Titles ship as read-only labels: the UI shows them, but only bodies can be saved."""
    config = current_app.config["APP_CONFIG"]
    topic = store.notify_topic(_db())
    return {
        "topic": topic,
        "enabled": bool(topic),
        "url": f"{config.NTFY_SERVER.rstrip('/')}/{topic}" if topic else None,
        "titles": TITLES,
        "bodies": store.notify_bodies(_db()),
        "default_bodies": DEFAULT_BODIES,
        "placeholders": list(PLACEHOLDERS),
    }


@bp.get("/notify")
@login_required
def notify_settings():
    return jsonify(_notify_payload())


@bp.post("/notify")
@login_required
def update_notify():
    """Save the topic, the message bodies, or both, in one transaction."""
    validate_csrf()
    data = request.get_json(silent=True) or request.form

    topic = None
    bodies = None
    try:
        if "topic" in data:
            topic = validate_topic(str(data.get("topic", "")))
        if "bodies" in data:
            supplied = data.get("bodies")
            if not isinstance(supplied, dict):
                raise NotifyError("Expected an object of message bodies.")
            bodies = {kind: str(supplied[kind]) for kind in MESSAGE_KINDS if kind in supplied}
    except NotifyError as exc:
        return jsonify(error=str(exc)), 400

    store.save_notify(_db(), topic=topic, bodies=bodies)
    return jsonify(_notify_payload())


@bp.post("/notify/test")
@login_required
def notify_test():
    """Send a real notification so a saved topic can be proved before the next tunnel event.

    Synchronous and allowed to fail loudly, unlike tunnel notifications: the operator asked for
    this one and is waiting on the answer.
    """
    validate_csrf()
    try:
        url = _notifier().send_test()
    except NotifyDeliveryError as exc:
        return jsonify(error=str(exc)), 502
    return jsonify(sent=True, url=url)


@bp.get("/connections")
@login_required
def list_connections():
    entries = [c.to_dict() for c in _connections().list()]
    return jsonify(connections=entries, count=len(entries))


@bp.post("/connections")
@login_required
def save_connection():
    """Create or replace a connection.

    Accepts a multipart upload (the .ovpn as a file) or JSON with the profile inline, so the
    same endpoint serves the browser form and a script.
    """
    validate_csrf()
    data = request.get_json(silent=True) or request.form

    profile = str(data.get("profile", ""))
    upload = request.files.get("profile_file")
    if upload is not None and upload.filename:
        raw = upload.read()
        try:
            profile = raw.decode("utf-8")
        except UnicodeDecodeError:
            return jsonify(error="That file is not text -- expected an .ovpn profile."), 400

    try:
        connection = _connections().save(
            name=str(data.get("name", "")),
            label=str(data.get("label", "")),
            profile=profile,
            username=str(data.get("username", "")),
            password=str(data.get("password", "")),
            static_challenge=str(data.get("static_challenge", "Enter Authenticator Code")),
            make_default=_truthy(data.get("make_default")),
            ignore_pushed_dns=_truthy(data.get("ignore_pushed_dns")),
        )
    except (StoreError, VaultError) as exc:
        return jsonify(error=str(exc)), 400
    except OSError as exc:
        return jsonify(error=f"Could not write the profile file: {exc}"), 500
    return jsonify(connection.to_dict()), 200


@bp.post("/connections/<name>/default")
@login_required
def make_default(name: str):
    validate_csrf()
    try:
        _connections().set_default(name)
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(ok=True)


@bp.post("/connections/<name>/toggle-dns")
@login_required
def toggle_pushed_dns(name: str):
    """Refuse, or stop refusing, the DNS servers this connection's server pushes.

    A row action rather than part of the save form: saving replaces a connection outright and so
    needs the profile and password again, which is far too much ceremony for one checkbox.
    """
    validate_csrf()
    try:
        enabled = _connections().toggle_ignore_pushed_dns(name)
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(ok=True, ignore_pushed_dns=enabled)


@bp.post("/connections/<name>/delete")
@login_required
def delete_connection(name: str):
    """POST rather than DELETE, to stay consistent with the CSRF-guarded form posts."""
    validate_csrf()
    controller = _controller()
    if controller.snapshot().profile == name and controller.snapshot().busy:
        return jsonify(error="That connection is in use -- disconnect first."), 409
    try:
        _connections().delete(name)
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(ok=True)


@bp.get("/whois")
@login_required
def whois():
    """Who registered a public destination the tunnel is routing.

    Every requested destination is checked against the *live* route table before being passed
    to ``whois`` -- a signed-in session can only ask about what this tunnel is actually carrying
    right now, never an arbitrary address, so this cannot become a general whois relay.
    """
    requested = request.args.getlist("dest")[:WHOIS_MAX_BATCH]
    known = {route.destination for route in _controller().routes()}
    destinations = [d for d in requested if d in known]
    results = [r.to_dict() for r in _controller().whois(destinations)]
    return jsonify(results=results)


@bp.get("/scope")
@login_required
def scope():
    """Whether the tunnel is carrying everything, some of it, or nothing.

    Separate from /api/routes because it answers a different question -- routes are the detail,
    this is the verdict -- and because it also consults the IPv6 table, which the routes view
    deliberately does not.
    """
    return jsonify(_controller().scope().to_dict())


def _dns_payload(domain_rules, fallback_rules, *, warning: str | None = None, **extra) -> dict:
    payload = {
        "domain_rules": [r.to_dict() for r in domain_rules],
        "fallback_rules": [r.to_dict() for r in fallback_rules],
        "warning": warning,
    }
    payload.update(extra)
    return payload


@bp.get("/dns")
@login_required
def dns_rules():
    """Domain-scoped forwarders and fallback servers, plus a legacy-file import preview.

    The preview only ever appears while nothing has been saved yet -- see
    DnsRules.legacy_preview().
    """
    rules = _dns_rules()
    domain_rules, fallback_rules = rules.list()
    preview = rules.legacy_preview()
    return jsonify(
        _dns_payload(domain_rules, fallback_rules, legacy=preview.to_dict() if preview else None)
    )


@bp.get("/dns/status")
@login_required
def dns_status():
    """Who is actually resolving what, and whether the rules below still matter.

    Kept out of /api/dns so that listing the rules stays a pure database read: this one shells
    out to resolvectl. The page fetches it when the DNS panel opens, after any rule changes, and
    when the tunnel changes state -- the three moments the answer can differ.
    """
    report = _dns_rules().status(log_lines=_controller().snapshot().log_lines)
    return jsonify(report.to_dict())


@bp.get("/deploy")
@login_required
def deploy_status():
    """Whether what is running matches what is in the checkout.

    Polled with the status, because the answer changes without anyone touching the page -- an
    edit, an install, a restart. Purely advisory: it reads files and reports, and every fix it
    names needs a privilege the app deliberately does not have.
    """
    report = deploy.report(
        config=current_app.config["APP_CONFIG"],
        schema_version=schema_version(current_app.config["DB"]),
        source_root=current_app.config["SOURCE_ROOT"],
        migrations_dir=MIGRATIONS_DIR,
        started_at=current_app.config["STARTED_AT"],
    )
    return jsonify(report.to_dict())


@bp.post("/dns")
@login_required
def add_dns_rule():
    """Add a domain forwarder or a fallback server.

    Re-adding an existing domain replaces its address rather than erroring -- see
    store.add_dns_rule(). Validation happens before anything is written to disk or the helper is
    invoked: a bad domain or address never reaches dns-apply.
    """
    validate_csrf()
    data = request.get_json(silent=True) or request.form
    kind = str(data.get("kind", "")).strip()
    try:
        rule, warning = _dns_rules().add(
            kind=kind,
            domain=data.get("domain"),
            address=str(data.get("address", "")),
        )
    except (DnsError, StoreError) as exc:
        return jsonify(error=str(exc)), 400
    domain_rules, fallback_rules = _dns_rules().list()
    return jsonify(_dns_payload(domain_rules, fallback_rules, warning=warning, rule=rule.to_dict()))


@bp.post("/dns/<int:rule_id>/delete")
@login_required
def delete_dns_rule(rule_id: int):
    validate_csrf()
    try:
        warning = _dns_rules().delete(rule_id)
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    domain_rules, fallback_rules = _dns_rules().list()
    return jsonify(_dns_payload(domain_rules, fallback_rules, warning=warning, ok=True))


@bp.post("/dns/<int:rule_id>/move")
@login_required
def move_dns_rule(rule_id: int):
    validate_csrf()
    data = request.get_json(silent=True) or request.form
    direction = str(data.get("direction", ""))
    try:
        warning = _dns_rules().move(rule_id, direction)
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    domain_rules, fallback_rules = _dns_rules().list()
    return jsonify(_dns_payload(domain_rules, fallback_rules, warning=warning))


@bp.post("/dns/import")
@login_required
def import_dns_rules():
    """Import every rule parsed from the legacy file in one transaction, then apply once."""
    validate_csrf()
    try:
        domain_rules, fallback_rules, warning, imported, skipped = _dns_rules().import_legacy()
    except StoreError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(
        _dns_payload(
            domain_rules, fallback_rules, warning=warning, imported=imported, skipped=skipped
        )
    )


@bp.get("/traffic")
@login_required
def traffic():
    """Throughput for one connection attempt, as a series ready to draw.

    Kept off /api/status for the same reason routes are: the page polls status constantly, and
    this is only wanted while the graph panel is open.  The series is bucketed server-side, so
    the payload stays the same size whether the tunnel has been up for a minute or a day.
    """
    history = current_app.config["HISTORY"]
    requested = request.args.get("session", type=int)
    if requested is None:
        sessions = history.recent_sessions(limit=1)
        requested = int(sessions[0]["id"]) if sessions else None
    if requested is None:
        return jsonify(session=None, live=False, **series([]).to_dict())

    points = request.args.get("points", type=int) or DEFAULT_POINTS
    points = max(10, min(points, 2000))
    payload = series(history.samples(requested), points).to_dict()
    return jsonify(session=requested, live=requested == history.session_id, **payload)


@bp.get("/sessions")
@login_required
def session_history():
    """Connection attempts inside the retention window, searchable and paged by session.

    There is no date filter and no ``from``/``to``, on purpose. The question this panel exists
    to answer -- does this tunnel stay up? -- is asked in attempts ("the last twenty-five", "the
    ones that dropped"), and a date range on a machine that was switched off for two of the
    seven days answers it with an empty table and no explanation.

    The summary always covers the whole retained window rather than the page or the search:
    "three drops" means nothing without three out of how many, and a total that changed as you
    typed would be worse than no total at all.
    """
    history = current_app.config["HISTORY"]
    entries = sessions.from_rows(history.sessions(), live_id=history.session_id)
    query = str(request.args.get("q") or "").strip()
    matched = sessions.search(entries, query)
    window, following = sessions.page(
        matched,
        before=request.args.get("before", type=int),
        limit=request.args.get("limit", type=int) or sessions.DEFAULT_LIMIT,
    )
    return jsonify(
        window_days=store.RETENTION_DAYS,
        retained=len(entries),
        matched=len(matched),
        query=query,
        summary=sessions.summarise(entries).to_dict(),
        sessions=[session.to_dict() for session in window],
        next=following,
    )


@bp.get("/logs")
@login_required
def logs():
    """Past connection attempts, including failed ones whose process has long exited."""
    history = current_app.config["HISTORY"]
    sessions = history.recent_sessions(limit=20)
    requested = request.args.get("session", type=int)
    session_id = (
        requested if requested is not None else (int(sessions[0]["id"]) if sessions else None)
    )
    lines = history.session_lines(session_id) if session_id is not None else []
    return jsonify(sessions=sessions, session=session_id, lines=lines)


@bp.post("/disconnect")
@login_required
def disconnect():
    validate_csrf()
    try:
        _controller().disconnect()
    except VpnError as exc:
        return jsonify(error=str(exc)), 400
    return jsonify(_controller().snapshot().to_dict()), 202
