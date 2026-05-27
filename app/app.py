import os
import time
import socket
import threading
import queue
import logging
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
    Response,
    send_from_directory,
)
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sophos_api import SophosXGAPI, SophosAPIError
from mac_auth import get_mac_for_ip, normalize_mac
from config import ConfigManager

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

_secret_key = os.environ.get("SECRET_KEY")
if not _secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set. Add it to your .env file.\n"
        "Generate one with: python -c \"import secrets; print(secrets.token_hex(32))\""
    )
app.secret_key = _secret_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

config = ConfigManager("/data/config.json")

limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri="memory://",
    default_limits=[],
)

# Module-level API singleton — env vars read once at startup
_api = SophosXGAPI(
    host=os.environ.get("XG_HOST", ""),
    port=int(os.environ.get("XG_PORT", "4444")),
    username=os.environ.get("XG_USERNAME", ""),
    password=os.environ.get("XG_PASSWORD", ""),
)

_rules_cache: list[dict] | None = None
_rules_cache_ts: float = 0.0
_RULES_CACHE_TTL: float = 10.0

# SSE broadcast state — shared across threads within the single worker
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()

_MAX_LOG = 50


def _get_cached_rules() -> list[dict]:
    global _rules_cache, _rules_cache_ts
    now = time.monotonic()
    if _rules_cache is not None and (now - _rules_cache_ts) < _RULES_CACHE_TTL:
        return _rules_cache
    rules = _api.get_firewall_rules()
    _rules_cache = rules
    _rules_cache_ts = now
    return rules


def _invalidate_rules_cache() -> None:
    global _rules_cache
    _rules_cache = None


def _broadcast_rule_change(rule: str, status: str) -> None:
    import json
    payload = json.dumps({"type": "rule_change", "rule": rule, "status": status})
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)


def _log_activity(rule: str, action: str, by: str) -> None:
    log: list = config.get("activity_log", [])
    log.append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rule": rule,
        "action": action,
        "by": by,
    })
    config.set("activity_log", log[-_MAX_LOG:])


def _allowed_macs() -> list[str]:
    macs: list[str] = []
    for env_var in ("MY_MAC", "WIFE_MAC"):
        normalized = normalize_mac(os.environ.get(env_var, ""))
        if normalized:
            macs.append(normalized)
    for mac in config.get("allowed_macs", []):
        normalized = normalize_mac(mac)
        if normalized and normalized not in macs:
            macs.append(normalized)
    return macs


def require_mac_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        allowed = _allowed_macs()

        if not allowed:
            # No MACs configured yet — let through for initial setup
            session["authenticated"] = True
            session["client_mac"] = "setup-mode"
            return f(*args, **kwargs)

        cached_mac = session.get("client_mac")
        if session.get("authenticated") and cached_mac in allowed:
            return f(*args, **kwargs)

        client_ip = request.remote_addr or ""

        if client_ip in ("127.0.0.1", "::1"):
            session["authenticated"] = True
            session["client_mac"] = "localhost"
            return f(*args, **kwargs)

        client_mac = normalize_mac(get_mac_for_ip(client_ip))
        logger.info(f"Auth check — IP: {client_ip}  MAC: {client_mac}  Allowed: {allowed}")

        if client_mac and client_mac in allowed:
            session["authenticated"] = True
            session["client_mac"] = client_mac
            return f(*args, **kwargs)

        return render_template("denied.html", client_ip=client_ip, client_mac=client_mac), 403

    return wrapper


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
@require_mac_auth
def index():
    allowed = _allowed_macs()
    kid_rules: list[str] = config.get("kid_rules", [])
    rule_statuses: dict = {}
    error: str | None = None

    if kid_rules:
        try:
            all_rules = _get_cached_rules()
            by_name = {r["name"]: r for r in all_rules}
            for name in kid_rules:
                rule_statuses[name] = by_name.get(name, {"name": name, "status": "unknown"})
        except SophosAPIError as e:
            error = str(e)
            logger.error(f"Failed to fetch rules: {e}")

    return render_template(
        "index.html",
        kid_rules=kid_rules,
        rule_statuses=rule_statuses,
        error=error,
        setup_mode=not allowed,
        activity_log=list(reversed(config.get("activity_log", []))),
    )


@app.route("/toggle/<path:rule_name>", methods=["POST"])
@require_mac_auth
@limiter.limit("10 per minute")
def toggle_rule(rule_name: str):
    kid_rules: list[str] = config.get("kid_rules", [])
    if rule_name not in kid_rules:
        return jsonify({"error": "Rule not in managed list"}), 404

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in ("enable", "disable"):
        return jsonify({"error": "action must be enable or disable"}), 400

    try:
        _api.set_rule_status(rule_name, action == "enable")
        _invalidate_rules_cache()
        by = session.get("client_mac", "unknown")
        _log_activity(rule_name, action, by)
        _broadcast_rule_change(rule_name, action)
        logger.info(f"Rule '{rule_name}' set to {action} by {by}")
        return jsonify({"success": True, "rule": rule_name, "status": action})
    except SophosAPIError as e:
        logger.error(f"Toggle failed for '{rule_name}': {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/api/rules")
@require_mac_auth
def api_rules():
    try:
        return jsonify(_get_cached_rules())
    except SophosAPIError as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/stream")
@require_mac_auth
def api_stream():
    client_q: queue.Queue = queue.Queue(maxsize=20)
    with _sse_lock:
        _sse_clients.append(client_q)

    def generate():
        import json
        try:
            yield f"data: {json.dumps({'type': 'connected'})}\n\n"
            while True:
                try:
                    data = client_q.get(timeout=25)
                    yield f"data: {data}\n\n"
                except queue.Empty:
                    yield ": ping\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                try:
                    _sse_clients.remove(client_q)
                except ValueError:
                    pass

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.route("/settings", methods=["GET", "POST"])
@require_mac_auth
def settings():
    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "add_rule":
            name = request.form.get("rule_name", "").strip()
            if name:
                rules: list[str] = config.get("kid_rules", [])
                if name not in rules:
                    rules.append(name)
                    config.set("kid_rules", rules)
                    flash(f'Rule "{name}" added to managed list.', "success")
                else:
                    flash(f'Rule "{name}" is already in the list.', "warning")

        elif action == "remove_rule":
            name = request.form.get("rule_name", "").strip()
            rules = config.get("kid_rules", [])
            if name in rules:
                rules.remove(name)
                config.set("kid_rules", rules)
                flash(f'Rule "{name}" removed.', "success")

        elif action == "update_macs":
            my_mac = normalize_mac(request.form.get("my_mac", ""))
            wife_mac = normalize_mac(request.form.get("wife_mac", ""))
            combined = [m for m in [my_mac, wife_mac] if m]
            config.set("allowed_macs", combined)
            flash("Allowed MAC addresses updated.", "success")

        return redirect(url_for("settings"))

    all_rules: list[dict] = []
    fw_error: str | None = None
    try:
        all_rules = _get_cached_rules()
    except SophosAPIError as e:
        fw_error = str(e)

    stored_macs: list[str] = config.get("allowed_macs", [])
    my_mac_stored = stored_macs[0] if len(stored_macs) > 0 else ""
    wife_mac_stored = stored_macs[1] if len(stored_macs) > 1 else ""

    return render_template(
        "settings.html",
        kid_rules=config.get("kid_rules", []),
        all_rules=all_rules,
        fw_error=fw_error,
        my_mac=my_mac_stored or os.environ.get("MY_MAC", ""),
        wife_mac=wife_mac_stored or os.environ.get("WIFE_MAC", ""),
    )


@app.route("/health")
def health():
    try:
        with socket.create_connection((_api.host, _api.port), timeout=3):
            pass
    except OSError:
        return jsonify({"status": "degraded", "reason": "firewall unreachable"}), 503
    return jsonify({"status": "ok"})


@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(app.static_folder, "sw.js")
    resp.headers["Service-Worker-Allowed"] = "/"
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded. Try again in a moment."}), 429


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
