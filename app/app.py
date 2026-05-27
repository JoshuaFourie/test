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
    level=logging.DEBUG,
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
_RULES_CACHE_TTL: float = 60.0

_allowed_macs_cache: list[str] | None = None
_allowed_macs_cache_ts: float = 0.0
_ALLOWED_MACS_CACHE_TTL: float = 30.0

_mac_lookup_cache: dict[str, str] = {}
_mac_lookup_cache_ts: dict[str, float] = {}
_MAC_LOOKUP_CACHE_TTL: float = 300.0

# SSE broadcast state — shared across threads within the single worker
_sse_clients: list[queue.Queue] = []
_sse_lock = threading.Lock()

_activity_log_buffer: list[dict] = []
_activity_log_flush_interval: float = 5.0
_activity_log_last_flush: float = 0.0
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
    global _activity_log_buffer, _activity_log_last_flush
    _activity_log_buffer.append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "rule": rule,
        "action": action,
        "by": by,
    })
    now = time.monotonic()
    if len(_activity_log_buffer) >= 10 or (now - _activity_log_last_flush) > _activity_log_flush_interval:
        _flush_activity_log()
        _activity_log_last_flush = now


def _flush_activity_log() -> None:
    global _activity_log_buffer
    if not _activity_log_buffer:
        return
    log: list = config.get("activity_log", [])
    log.extend(_activity_log_buffer)
    config.set("activity_log", log[-_MAX_LOG:])
    _activity_log_buffer = []


def _get_allowed_macs_cached() -> list[str]:
    global _allowed_macs_cache, _allowed_macs_cache_ts
    now = time.monotonic()
    if _allowed_macs_cache is not None and (now - _allowed_macs_cache_ts) < _ALLOWED_MACS_CACHE_TTL:
        return _allowed_macs_cache
    _allowed_macs_cache = _allowed_macs()
    _allowed_macs_cache_ts = now
    return _allowed_macs_cache


def _allowed_macs() -> list[str]:
    macs: list[str] = []
    for env_var in ("MY_MAC", "WIFE_MAC", "PC_MAC"):
        normalized = normalize_mac(os.environ.get(env_var, ""))
        if normalized:
            macs.append(normalized)

    # Check allowed_macs first
    allowed_macs = config.get("allowed_macs", [])
    if allowed_macs:
        for mac in allowed_macs:
            normalized = normalize_mac(mac)
            if normalized and normalized not in macs:
                macs.append(normalized)
    else:
        # Fallback to authorized_devices if allowed_macs is not set
        authorized_devices = config.get("authorized_devices", [])
        for device in authorized_devices:
            mac = device.get("mac", "")
            normalized = normalize_mac(mac)
            if normalized and normalized not in macs:
                macs.append(normalized)

    return macs


def _get_cached_mac_for_ip(client_ip: str) -> str:
    global _mac_lookup_cache, _mac_lookup_cache_ts
    now = time.monotonic()
    if client_ip in _mac_lookup_cache:
        if (now - _mac_lookup_cache_ts.get(client_ip, 0)) < _MAC_LOOKUP_CACHE_TTL:
            return _mac_lookup_cache[client_ip]

    mac = normalize_mac(get_mac_for_ip(client_ip))
    _mac_lookup_cache[client_ip] = mac
    _mac_lookup_cache_ts[client_ip] = now
    return mac


def require_mac_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        allowed = _get_allowed_macs_cached()

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

        client_mac = _get_cached_mac_for_ip(client_ip)
        logger.info(f"Auth check — IP: {client_ip}  MAC: {client_mac}  Allowed: {allowed}")

        if client_mac and client_mac in allowed:
            session["authenticated"] = True
            session["client_mac"] = client_mac
            return f(*args, **kwargs)

        return render_template("denied.html", client_ip=client_ip, client_mac=client_mac), 403

    return wrapper


def _get_managed_rules() -> list[str]:
    rules = config.get("managed_rules", [])
    if not rules:
        rules = config.get("kid_rules", [])
    return rules


def _is_setup_complete() -> bool:
    return bool(
        os.environ.get("XG_HOST") or config.get("xg_host")
    ) and bool(
        os.environ.get("XG_USERNAME") or config.get("xg_username")
    )


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if _is_setup_complete() and request.method == "GET":
        return redirect(url_for("index"))

    if request.method == "POST":
        xg_host = request.form.get("xg_host", "").strip()
        xg_port = request.form.get("xg_port", "4444").strip()
        xg_username = request.form.get("xg_username", "").strip()
        xg_password = request.form.get("xg_password", "").strip()

        if xg_host and xg_username and xg_password:
            config.set("xg_host", xg_host)
            config.set("xg_port", xg_port)
            config.set("xg_username", xg_username)
            config.set("xg_password", xg_password)
            flash("Firewall credentials saved successfully!", "success")
            return redirect(url_for("index"))
        else:
            flash("Please fill in all firewall fields.", "error")

    return render_template("setup.html")


@app.route("/")
@require_mac_auth
def index():
    if not _is_setup_complete():
        return redirect(url_for("setup"))

    managed_rules: list[str] = _get_managed_rules()
    allowed = _get_allowed_macs_cached()
    rule_statuses: dict = {}
    error: str | None = None

    if managed_rules:
        try:
            all_rules = _get_cached_rules()
            by_name = {r["name"]: r for r in all_rules}
            for name in managed_rules:
                rule_statuses[name] = by_name.get(name, {"name": name, "status": "unknown"})
        except SophosAPIError as e:
            error = str(e)
            logger.error(f"Failed to fetch rules: {e}")

    return render_template(
        "index.html",
        managed_rules=managed_rules,
        rule_statuses=rule_statuses,
        error=error,
        setup_mode=not allowed,
        activity_log=list(reversed(config.get("activity_log", []))),
    )


@app.route("/toggle/<path:rule_name>", methods=["POST"])
@require_mac_auth
@limiter.limit("10 per minute")
def toggle_rule(rule_name: str):
    managed_rules: list[str] = _get_managed_rules()
    logger.debug(f"Toggle request for '{rule_name}'. Managed rules: {managed_rules}")

    if rule_name not in managed_rules:
        logger.error(f"Rule '{rule_name}' not in managed list")
        return jsonify({"error": f"Rule '{rule_name}' not in managed list"}), 404

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    logger.debug(f"Action received: '{action}' (type: {type(action)})")

    if action not in ("enable", "disable"):
        logger.error(f"Invalid action: '{action}'")
        return jsonify({"error": f"Invalid action '{action}'. Must be 'enable' or 'disable'"}), 400

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
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")
        return jsonify({"error": f"Firewall error: {str(e)}"}), 400


@app.route("/api/rules")
@require_mac_auth
def api_rules():
    try:
        resp = jsonify(_get_cached_rules())
        resp.headers["Cache-Control"] = "max-age=60, must-revalidate"
        return resp
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

        if action == "add_device":
            device_name = request.form.get("device_name", "").strip()
            device_mac = normalize_mac(request.form.get("device_mac", ""))
            if device_name and device_mac:
                devices = config.get("authorized_devices", [])
                if not any(d.get("name") == device_name for d in devices):
                    devices.append({"name": device_name, "mac": device_mac})
                    config.set("authorized_devices", devices)
                    flash(f'Device "{device_name}" added.', "success")
                else:
                    flash(f'Device "{device_name}" already exists.', "warning")
            else:
                flash("Please fill in device name and MAC.", "error")

        elif action == "remove_device":
            device_name = request.form.get("device_name", "").strip()
            devices = config.get("authorized_devices", [])
            devices = [d for d in devices if d.get("name") != device_name]
            config.set("authorized_devices", devices)
            flash(f'Device "{device_name}" removed.', "success")

        elif action == "update_firewall":
            xg_host = request.form.get("xg_host", "").strip()
            xg_port = request.form.get("xg_port", "4444").strip()
            xg_username = request.form.get("xg_username", "").strip()
            xg_password = request.form.get("xg_password", "").strip()
            fw_name = request.form.get("fw_name", "").strip()

            if xg_host and xg_username:
                config.set("xg_host", xg_host)
                config.set("xg_port", xg_port)
                config.set("xg_username", xg_username)
                if xg_password:
                    config.set("xg_password", xg_password)
                if fw_name:
                    config.set("fw_name", fw_name)
                flash("Firewall settings updated.", "success")
            else:
                flash("Please fill in firewall IP and username.", "error")

        elif action == "add_rule":
            name = request.form.get("rule_name", "").strip()
            if name:
                rules: list[str] = _get_managed_rules()
                if name not in rules:
                    rules.append(name)
                    config.set("managed_rules", rules)
                    flash(f'Rule "{name}" added to managed list.', "success")
                else:
                    flash(f'Rule "{name}" is already in the list.', "warning")

        elif action == "remove_rule":
            name = request.form.get("rule_name", "").strip()
            rules = _get_managed_rules()
            if name in rules:
                rules.remove(name)
                config.set("managed_rules", rules)
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

    # If no allowed_macs, try to get from authorized_devices
    if not stored_macs:
        authorized_devices = config.get("authorized_devices", [])
        stored_macs = [d.get("mac", "") for d in authorized_devices if d.get("mac")]

    my_mac_stored = stored_macs[0] if len(stored_macs) > 0 else ""
    wife_mac_stored = stored_macs[1] if len(stored_macs) > 1 else ""

    xg_host = os.environ.get("XG_HOST") or config.get("xg_host", "")
    xg_port = os.environ.get("XG_PORT") or config.get("xg_port", "4444")
    xg_username = os.environ.get("XG_USERNAME") or config.get("xg_username", "")
    xg_password = os.environ.get("XG_PASSWORD") or config.get("xg_password", "")
    fw_name = config.get("fw_name", "")

    authorized_devices = config.get("authorized_devices", [])
    for device in authorized_devices:
        device["mac"] = normalize_mac(device.get("mac", ""))

    return render_template(
        "settings.html",
        managed_rules=_get_managed_rules(),
        all_rules=all_rules,
        fw_error=fw_error,
        authorized_devices=authorized_devices,
        xg_host=xg_host,
        xg_port=xg_port,
        xg_username=xg_username,
        xg_password=xg_password,
        fw_name=fw_name,
    )


@app.route("/export-config")
@require_mac_auth
def export_config():
    export_data = {
        "firewall": {
            "name": config.get("fw_name", ""),
            "host": config.get("xg_host", ""),
            "port": config.get("xg_port", "4444"),
            "username": config.get("xg_username", ""),
            "password": "***ENCRYPTED***",
        },
        "authorized_devices": config.get("authorized_devices", []),
        "managed_rules": _get_managed_rules(),
    }
    return jsonify(export_data)


@app.route("/import-config", methods=["POST"])
@require_mac_auth
def import_config():
    try:
        data = request.get_json() or {}
        fw = data.get("firewall", {})

        if fw.get("host") and fw.get("username"):
            config.set("fw_name", fw.get("name", ""))
            config.set("xg_host", fw.get("host", ""))
            config.set("xg_port", fw.get("port", "4444"))
            config.set("xg_username", fw.get("username", ""))
            if fw.get("password") and fw.get("password") != "***ENCRYPTED***":
                config.set("xg_password", fw.get("password", ""))

        devices = data.get("authorized_devices", [])
        if devices:
            config.set("authorized_devices", devices)

        rules = data.get("managed_rules", []) or data.get("kid_rules", [])
        if rules:
            config.set("managed_rules", rules)

        return jsonify({"success": True, "message": "Config imported successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


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


@app.before_request
def flush_activity_log_before_request():
    global _activity_log_last_flush
    now = time.monotonic()
    if _activity_log_buffer and (now - _activity_log_last_flush) > _activity_log_flush_interval:
        _flush_activity_log()
        _activity_log_last_flush = now


def shutdown_handler(signum=None, frame=None):
    _flush_activity_log()


import atexit
import signal
atexit.register(shutdown_handler)
signal.signal(signal.SIGTERM, shutdown_handler)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9000, debug=False)
