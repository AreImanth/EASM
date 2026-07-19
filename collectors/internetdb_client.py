from collectors.base_collector import BaseCollector
from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)

BASE_URL = "https://internetdb.shodan.io"


class InternetDBCollector(BaseCollector):
    source_name = "internetdb"

    def is_configured(self) -> bool:
        return True  # no credentials needed

    def collect(self, ip: str) -> list[Finding]:
        findings = []
        resp = self._safe_get(f"{BASE_URL}/{ip}")

        if resp is None:
            log.info(f"{ip}: no InternetDB data available")
            return findings

        data = resp.json()
        ports = data.get("ports", [])
        hostnames = data.get("hostnames", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])

        for port in ports:
            findings.append(Finding(
                ip=ip,
                collector_source=self.source_name,
                port=port,
                hostnames=hostnames,
                vulns=vulns,
                tags=tags,
            ))

        return findings
