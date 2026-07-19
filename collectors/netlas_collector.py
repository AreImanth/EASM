from urllib.parse import urlparse

from collectors.base_collector import BaseCollector
from core.config import Settings
from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)

BASE_URL = "https://app.netlas.io/api/host"
FREE_TIER_DAILY_LIMIT = 50


def _extract_software_by_port(software_list: list) -> dict[int, str]:
    """
    Netlas nests version info under a key matching the tag's own
    'name' -- e.g. {"name": "nginx", "nginx": {"version": "1.18.0"}}.
    """
    port_products: dict[int, list[str]] = {}

    for entry in software_list or []:
        uri = entry.get("uri", "")
        port = None
        try:
            parsed = urlparse(uri)
            if parsed.port:
                port = parsed.port
            elif parsed.scheme == "https":
                port = 443
            elif parsed.scheme == "http":
                port = 80
        except ValueError:
            pass

        if port is None:
            continue

        for tag in entry.get("tag", []):
            name = tag.get("fullname") or tag.get("name", "")
            tag_key = tag.get("name")
            version = ""
            if tag_key and isinstance(tag.get(tag_key), dict):
                version = tag[tag_key].get("version", "")

            label = f"{name} {version}".strip()
            if label:
                port_products.setdefault(port, []).append(label)

    return {port: ", ".join(labels) for port, labels in port_products.items()}


class NetlasCollector(BaseCollector):
    source_name = "netlas"

    def __init__(self, settings: Settings):
        self._api_key = settings.netlas_api_key
        self.calls_made = 0

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def collect(self, ip: str) -> list[Finding]:
        findings = []

        if not self.is_configured():
            return findings 

        if self.calls_made >= FREE_TIER_DAILY_LIMIT:
            log.warning(f"[{self.source_name}] daily free-tier limit reached -- skipping {ip}")
            return findings

        self.calls_made += 1
        resp = self._safe_get(
            f"{BASE_URL}/{ip}/",
            headers={"Authorization": f"Bearer {self._api_key}"},
        )

        if resp is None:
            log.info(f"{ip}: no Netlas data available")
            return findings

        data = resp.json()
        hostnames = data.get("domains") or data.get("ptr", [])
        ports = data.get("ports", [])
        software = data.get("software", [])

        product_by_port = _extract_software_by_port(software)

        for p in ports:
            port_num = p.get("port")
            findings.append(Finding(
                ip=ip,
                collector_source=self.source_name,
                port=port_num,
                product=product_by_port.get(port_num, p.get("protocol", "")),
                hostnames=hostnames,
            ))

        return findings