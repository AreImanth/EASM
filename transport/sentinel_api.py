from core.models import Finding
from transport.base_transport import BaseTransport, TransportResult


class SentinelTransport(BaseTransport):
    destination_name = "sentinel"

    def send(self, findings: list[Finding]) -> TransportResult:
        raise NotImplementedError(
            "Sentinel transport is planned but not yet implemented. "
        )
