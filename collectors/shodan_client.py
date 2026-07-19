from core.config import Settings
from core.logger import get_logger
from core.models import Finding
from collectors.base_collector import BaseCollector

log = get_logger(__name__)

HOST_URL = "https://api.shodan.io/shodan/host"
SEARCH_URL = "https://api.shodan.io/shodan/host/search"


class ShodanCollector(BaseCollector):
    source_name = "shodan"

    def __init__(self, settings: Settings):
        self._api_key = settings.shodan_api_key

    def is_configured(self) -> bool:
        return bool(self._api_key)

    def collect(self, ip: str) -> list[Finding]:
        """
        Direct host lookup for a single IP -- GET /shodan/host/{ip}.
        Requires a paid Shodan Membership key; consumes 1 query credit.
        Returns [] (not an error) if not configured, matching every
        other collector's graceful-skip behavior.
        """
        findings = []

        if not self.is_configured():
            return findings

        resp = self._safe_get(
            f"{HOST_URL}/{ip}",
            params={"key": self._api_key},
        )

        if resp is None:
            log.info(f"{ip}: no Shodan host data available")
            return findings

        data = resp.json()
        for item in data.get("data", []):
            findings.append(Finding(
                ip=ip,
                source=self.source_name,
                port=item.get("port"),
                product=item.get("product", "") or "",
                version=item.get("version", "") or "",
                hostnames=data.get("hostnames", []),
            ))

        return findings

    def collect_org(self, org_or_net_query: str) -> list[Finding]:
    
        findings = []

        if not self.is_configured():
            log.warning(
                f"[{self.source_name}] not configured (no SHODAN_API_KEY) -- "
                f"skipping org query: {org_or_net_query}"
            )
            return findings

        resp = self._safe_get(
            SEARCH_URL,
            params={"key": self._api_key, "query": org_or_net_query},
        )

        if resp is None:
            return findings

        data = resp.json()
        for match in data.get("matches", []):
            findings.append(Finding(
                ip=match.get("ip_str", ""),
                collector_source=self.source_name,
                port=match.get("port"),
                product=match.get("product", "") or "",
                version=match.get("version", "") or "",
                hostnames=match.get("hostnames", []),
            ))

        return findings