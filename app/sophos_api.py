import requests
import xml.etree.ElementTree as ET
import xml.sax.saxutils as saxutils
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

    def _xml_request(self, body_xml: str, timeout: int = 30) -> ET.Element:
        payload = f"""<Request>
  <Login>
    <Username>{self.username}</Username>
    <Password>{self.password}</Password>
  </Login>
  {body_xml}
</Request>"""
        logger.debug(f"Sending XML request: {body_xml[:200]}")
        try:
            resp = _http_session.post(
                self.base_url,
                data={"reqxml": payload},
                verify=False,
                timeout=timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            raise SophosAPIError(f"Network error contacting XG firewall: {e}") from e

        try:
            root = ET.fromstring(resp.text)
        except ET.ParseError as e:
            raise SophosAPIError(f"Invalid XML response from firewall: {e}") from e

        full_response = ET.tostring(root, encoding="unicode")
        logger.debug(f"Firewall response: {full_response[:800]}")

        login_el = root.find("Login/status")
        logger.debug(f"Login status: {login_el.text if login_el is not None else 'NOT FOUND'}")

        # Check for error messages
        for el in root.iter():
            if el.text and ("validation" in (el.text or "").lower() or "error" in (el.text or "").lower()):
                logger.debug(f"Found error/validation element {el.tag}: {el.text}")

        if login_el is not None and "Successful" not in (login_el.text or ""):
            raise SophosAPIError(f"Authentication failed: {login_el.text}")

        return root

    def _get_rule_xml(self, rule_name: str) -> ET.Element | None:
        # Try to fetch the specific rule first
        body = f"""<Get>
  <FirewallRule>
    <Name>{rule_name}</Name>
  </FirewallRule>
</Get>"""
        try:
            root = self._xml_request(body)
            rule_el = root.find("FirewallRule")
            if rule_el is not None:
                found_name = rule_el.findtext("Name", "").strip()
                if found_name == rule_name:
                    logger.debug(f"Found rule '{rule_name}' in specific Get response")
                    return rule_el
        except Exception as e:
            logger.debug(f"Specific Get request failed: {e}, trying all rules")

        # Fallback: fetch all rules
        root = self._xml_request("<Get><FirewallRule></FirewallRule></Get>")
        found_rules = []
        for rule_el in root.findall("FirewallRule"):
            name = rule_el.findtext("Name", "").strip()
            found_rules.append(name)
            if name == rule_name:
                logger.debug(f"Found rule '{rule_name}' in all-rules response")
                return rule_el
        logger.debug(f"Rule '{rule_name}' not found. Available rules: {found_rules}")
        return None

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

    def _apply_changes(self) -> bool:
        """Commit/apply pending changes to the firewall"""
        body = """<Apply>
  <Configuration />
</Apply>"""
        try:
            logger.debug("Sending Apply request to commit changes")
            root = self._xml_request(body, timeout=60)

            # Check for success
            response_status = root.find(".//Status")
            if response_status is not None:
                status_code = response_status.get("code")
                logger.debug(f"Apply response: code={status_code}")
                return status_code != "error"
            return True
        except Exception as e:
            logger.warning(f"Apply request failed: {e}, changes may require manual commit on firewall")
            return False

    def set_rule_status(self, rule_name: str, enabled: bool) -> bool:
        status_value = "Enable" if enabled else "Disable"

        # Get the full rule to preserve all settings
        rule_el = self._get_rule_xml(rule_name)
        if rule_el is None:
            raise SophosAPIError(f"Rule '{rule_name}' not found on firewall")

        # Update Status in the rule
        status_el = rule_el.find("Status")
        if status_el is not None:
            status_el.text = status_value
        else:
            status_el = ET.SubElement(rule_el, "Status")
            status_el.text = status_value

        # Remove transactionid attribute
        if "transactionid" in rule_el.attrib:
            del rule_el.attrib["transactionid"]

        # Serialize the complete rule with updated status
        rule_xml = ET.tostring(rule_el, encoding="unicode")

        # Build Set request with full rule
        body = f"""<Set operation="update">
  {rule_xml}
</Set>"""

        logger.debug(f"Sending Set request: Status={status_value}")
        root = self._xml_request(body, timeout=45)

        # Check for success status
        response_status = root.find(".//Configuration/Status")
        if response_status is not None:
            status_code = response_status.get("code")
            status_text = (response_status.text or "").lower()

            logger.debug(f"Configuration status: code={status_code}, text={status_text}")

            if status_code == "200" or "success" in status_text:
                # Apply the changes to make them active in the firewall
                self._apply_changes()
                return True
            else:
                raise SophosAPIError(f"Firewall returned error: {status_code} {response_status.text}")

        # Check for direct error messages
        error_el = root.find(".//Error")
        if error_el is not None:
            raise SophosAPIError(f"Firewall API error: {error_el.text}")

        # If response has FirewallRule, operation succeeded
        if root.find("FirewallRule") is not None:
            # Apply the changes to make them active in the firewall
            self._apply_changes()
            return True

        # No explicit error, assume success
        return True
