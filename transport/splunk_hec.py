import json

import requests

from core.config import Settings
from core.logger import get_logger
from core.models import Finding
from transport.base_transport import BaseTransport, TransportResult

log = get_logger(__name__)


class SplunkHECTransport(BaseTransport):
    destination_name = "splunk"

    def __init__(self, settings: Settings):
        self._url = settings.splunk_hec_url
        self._token = settings.splunk_hec_token
        self._index = settings.splunk_index
        self._verify_ssl = settings.splunk_verify_ssl
        self._sourcetype = "shodan:scan"

        if not self._verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def send(self, findings: list[Finding]) -> TransportResult:
        if not findings:
            return TransportResult(success=True, sent_count=0, message="No findings to send.")

        headers = {"Authorization": f"Splunk {self._token}"}
        body = "\n".join(
            json.dumps({
                "event": f.to_dict(),
                "index": self._index,
                "sourcetype": self._sourcetype,
                "source": "EASM_collector",
            })
            for f in findings
        )

        try:
            resp = requests.post(
                self._url, headers=headers, data=body,
                timeout=30, verify=self._verify_ssl,
            )
        except requests.exceptions.SSLError:
            msg = "SSL certificate validation failed -- set SPLUNK_VERIFY_SSL=false for a self-signed lab instance."
            log.error(f"[{self.destination_name}] {msg}")
            return TransportResult(success=False, sent_count=0, message=msg)
        except requests.exceptions.ConnectionError:
            msg = f"Unable to connect to Splunk at {self._url}"
            log.error(f"[{self.destination_name}] {msg}")
            return TransportResult(success=False, sent_count=0, message=msg)
        except requests.exceptions.Timeout:
            msg = "Splunk HEC request timed out."
            log.error(f"[{self.destination_name}] {msg}")
            return TransportResult(success=False, sent_count=0, message=msg)
        except requests.RequestException as e:
            msg = f"Unexpected request error: {e}"
            log.error(f"[{self.destination_name}] {msg}")
            return TransportResult(success=False, sent_count=0, message=msg)

        if resp.status_code == 200:
            log.info(f"[{self.destination_name}] sent {len(findings)} events to index '{self._index}'")
            return TransportResult(success=True, sent_count=len(findings))

        error_messages = {
            400: "Bad request -- invalid event payload.",
            401: "Invalid HEC token.",
            403: "Access forbidden.",
            404: "HEC endpoint not found -- check SPLUNK_HEC_URL.",
            429: "Too many requests -- rate limited.",
            500: "Splunk internal server error.",
            503: "Splunk service unavailable.",
        }
        msg = error_messages.get(resp.status_code, f"Unexpected response ({resp.status_code}): {resp.text}")
        log.error(f"[{self.destination_name}] {msg}")
        return TransportResult(success=False, sent_count=0, message=msg)
