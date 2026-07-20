from core.models import Finding
from transport.base_transport import BaseTransport, TransportResult


class ELKTransport(BaseTransport):
    destination_name = "elk"

    def send(self, findings: list[Finding]) -> TransportResult:
        raise NotImplementedError(
            "ELK transport is planned but not yet implemented. "
        )
