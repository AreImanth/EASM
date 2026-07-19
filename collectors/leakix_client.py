from collectors.base_collector import BaseCollector
from core.config import Settings
from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)

BASE_URL = "https://leakix.net/host"


class LeakIXCollector(BaseCollector):
    source_name = "leakix"

    def __init__(self, settings: Settings):
        self._api_key = settings.leakix_api_key

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def collect(self, ip: str) -> list[Finding]:
        findings = []

        if not self.is_configured():
            return findings

        resp = self._safe_get(
            f"{BASE_URL}/{ip}",
            headers={"api-key": self._api_key, "accept": "application/json"},
        )

        if resp is None:
            log.info(f"{ip}: no LeakIX data available")
            return findings

        data = resp.json()
        services = data.get("services") or []

        for svc in services:
            software = svc.get("software") or {}
            product = software.get("name", "") or ""
            version = software.get("version", "") or ""

            findings.append(Finding(
                ip=ip,
                collector_source=self.source_name,
                port=svc.get("port"),
                product=f"{product} {version}".strip(),
                hostnames=[svc.get("hostname")] if svc.get("hostname") else [],
            ))

        return findings