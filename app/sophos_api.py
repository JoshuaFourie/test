import requests
import xml.etree.ElementTree as ET
import logging
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

# Shared session for connection pooling across API calls
_http_session = requests.Session()


class SophosAPIError(Exception):
    pass


class SophosXGAPI:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}/webconsole/APIController"

    def _xml_request(self, body_xml: str) -> ET.Element:
        payload = f"""<Request>
  <Login>
    <Username>{self.username}</Username>
    <Password>{self.password}</Password>
  </Login>
  {body_xml}
</Request>"""
        try:
            resp = _http_session.post(
                self.base_url,
                data={"reqxml": payload},
                verify=False,
                timeout=15,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise SophosAPIError(f"Network error contacting XG firewall: {e}") from e

        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            raise SophosAPIError(f"Invalid XML response from firewall: {e}") from e

        login_el = root.find("Login/status")
        if login_el is not None and "Successful" not in (login_el.text or ""):
            raise SophosAPIError(f"Authentication failed: {login_el.text}")

        return root

    def get_firewall_rules(self) -> list[dict]:
        root = self._xml_request("<Get><FirewallRule></FirewallRule></Get>")
        rules = []
        for rule_el in root.findall("FirewallRule"):
            name = rule_el.findtext("Name", "").strip()
            if not name:
                continue
            rules.append(
                {
                    "name": name,
                    "status": rule_el.findtext("Status", "").strip(),
                    "description": rule_el.findtext("Description", "").strip(),
                    "position": rule_el.findtext("Position", "").strip(),
                    "action": rule_el.findtext("NetworkPolicy/Action", rule_el.findtext("Action", "")).strip(),
                }
            )
        return rules

    def set_rule_status(self, rule_name: str, enabled: bool) -> bool:
        status = "Enable" if enabled else "Disable"
        body = f"""<Set operation="update">
  <FirewallRule>
    <Name>{rule_name}</Name>
    <Status>{status}</Status>
  </FirewallRule>
</Set>"""
        root = self._xml_request(body)
        result_el = root.find("FirewallRule/Status")
        if result_el is not None:
            text = (result_el.text or "").lower()
            if "success" in text or "applied" in text or text in ("enable", "disable"):
                return True
            raise SophosAPIError(f"Unexpected response setting rule status: {result_el.text}")
        return True
