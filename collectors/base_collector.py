from abc import ABC, abstractmethod

import requests

from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)


class BaseCollector(ABC):
    source_name: str = "base"

    def _safe_get(self, url: str, **kwargs) -> requests.Response | None:
      
        try:
            resp = requests.get(url, timeout=kwargs.pop("timeout", 15), **kwargs)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            log.error(f"[{self.source_name}] request to {url} failed: {e}")
            return None

    class BaseCollector(ABC):
        source_name: str = "base"

    def _safe_get(self, url: str, **kwargs) -> requests.Response | None:
      
        try:
            resp = requests.get(url, timeout=kwargs.pop("timeout", 15), **kwargs)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            log.error(f"[{self.source_name}] request to {url} failed: {e}")
            return None

    def _safe_post(self, url: str, **kwargs) -> requests.Response | None:
       
        try:
            resp = requests.post(url, timeout=kwargs.pop("timeout", 15), **kwargs)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            log.error(f"[{self.source_name}] request to {url} failed: {e}")
            return None

    @abstractmethod
    def is_configured(self) -> bool:
        """Whether this collector has the credentials it needs to run."""
        ...

    @abstractmethod
    def collect(self, ip: str) -> list[Finding]:
        """Look up a single IP and return normalized Finding objects."""
        ...
    @abstractmethod
    def is_configured(self) -> bool:
        """Whether this collector has the credentials it needs to run."""
        ...

    @abstractmethod
    def collect(self, ip: str) -> list[Finding]:
        """Look up a single IP and return normalized Finding objects."""
        ...
