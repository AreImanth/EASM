from core.models import Finding
from transport.base_transport import BaseTransport, TransportResult


class WazuhTransport(BaseTransport):
    destination_name = "wazuh"

    def send(self, findings: list[Finding]) -> TransportResult:
        raise NotImplementedError(
            "Wazuh transport is planned but not yet implemented. "
        )
