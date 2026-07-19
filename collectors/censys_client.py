from collectors.base_collector import BaseCollector
from core.config import Settings
from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)

BASE_URL = "https://api.platform.censys.io/v3/global/asset/host"


class CensysCollector(BaseCollector):
    source_name = "censys"

    def __init__(self, settings: Settings):
        self._pat = settings.censys_pat
        self._org_id = settings.censys_org_id  # optional -- free tier often has none

    def is_configured(self) -> bool:
        return bool(self._pat)

    def collect(self, ip: str) -> list[Finding]:
        findings = []

        if not self.is_configured():
            return findings 

        headers = {
            "Authorization": f"Bearer {self._pat}",
            "Accept": "application/vnd.censys.api.v3.host.v1+json",
        }
        if self._org_id:
            headers["X-Organization-ID"] = self._org_id
       
        resp = self._safe_get(f"{BASE_URL}/{ip}", headers=headers)

        if resp is None:
            log.info(f"{ip}: no Censys data available")
            return findings

        data = resp.json()
        resource = data.get("result", {}).get("resource", {})
        services = resource.get("services", [])

        for svc in services:
            labels = svc.get("labels", [])
            label_str = ", ".join(l.get("value", "") for l in labels) if labels else ""

            findings.append(Finding(
                ip=ip,
                collector_source=self.source_name,
                port=svc.get("port"),
                product=label_str,
                hostnames=[],
            ))

        return findings