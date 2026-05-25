import os
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
)
from dotenv import load_dotenv
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
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

config = ConfigManager("/data/config.json")


def _api() -> SophosXGAPI:
    return SophosXGAPI(
        host=os.environ.get("XG_HOST", ""),
        port=int(os.environ.get("XG_PORT", "4444")),
        username=os.environ.get("XG_USERNAME", ""),
        password=os.environ.get("XG_PASSWORD", ""),
    )


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
    kid_rules: list[str] = config.get("kid_rules", [])
    rule_statuses: dict = {}
    error: str | None = None

    if kid_rules:
        try:
            all_rules = _api().get_firewall_rules()
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
        setup_mode=not _allowed_macs(),
    )


@app.route("/toggle/<path:rule_name>", methods=["POST"])
@require_mac_auth
def toggle_rule(rule_name: str):
    kid_rules: list[str] = config.get("kid_rules", [])
    if rule_name not in kid_rules:
        return jsonify({"error": "Rule not in managed list"}), 404

    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action not in ("enable", "disable"):
        return jsonify({"error": "action must be enable or disable"}), 400

    try:
        _api().set_rule_status(rule_name, action == "enable")
        logger.info(f"Rule '{rule_name}' set to {action} by {session.get('client_mac')}")
        return jsonify({"success": True, "rule": rule_name, "status": action})
    except SophosAPIError as e:
        logger.error(f"Toggle failed for '{rule_name}': {e}")
        return jsonify({"error": str(e)}), 502


@app.route("/api/rules")
@require_mac_auth
def api_rules():
    try:
        return jsonify(_api().get_firewall_rules())
    except SophosAPIError as e:
        return jsonify({"error": str(e)}), 502


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
        all_rules = _api().get_firewall_rules()
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
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
