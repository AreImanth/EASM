"""
transport/base_transport.py
-------------------------------------------------------------
Every destination (Splunk, and later Sentinel/Wazuh/ELK) implements
this interface. Collectors and the risk engine never know which
transport is in use -- main.py wires whichever one is configured.
-------------------------------------------------------------
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass

from core.models import Finding


@dataclass
class TransportResult:
    success: bool
    sent_count: int
    message: str = ""


class BaseTransport(ABC):
    destination_name: str = "base"

    @abstractmethod
    def send(self, findings: list[Finding]) -> TransportResult:
        """Send a batch of findings to the destination. Must not raise --
        catch and return a failed TransportResult instead, so one bad
        transport doesn't crash the whole run."""
        ...
