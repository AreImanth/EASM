import ipaddress
from pathlib import Path

import yaml

from core.logger import get_logger
from core.models import Target

log = get_logger(__name__)


class AssetLoadError(Exception):
    """Raised when assets.yaml is missing, empty, or malformed."""


def load_targets(path: str = "assets.yaml") -> list[Target]:
    """Reads assets.yaml and returns a validated list of Target objects."""
    file_path = Path(path)

    if not file_path.exists():
        raise AssetLoadError(f"Asset inventory file not found: {path}")

    with file_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if not data:
        raise AssetLoadError("assets.yaml is empty.")

    if "targets" not in data:
        raise AssetLoadError("'targets' section is missing from assets.yaml.")

    if not isinstance(data["targets"], list):
        raise AssetLoadError("'targets' must be a list.")

    organization = data.get("organization", "")

    targets = [
        Target(type=t["type"], value=t["value"], organization=organization)
        for t in data["targets"]
    ]
    log.info(f"Loaded {len(targets)} targets from {path}")
    return targets


def expand_target(target: Target) -> list[str]:

    if target.type == "ip":
        return [target.value]

    if target.type == "cidr":
        try:
            network = ipaddress.ip_network(target.value, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError as e:
            log.error(f"Invalid CIDR range '{target.value}': {e}")
            return []

    if target.type == "org":
        log.info(f"Target '{target.value}' is type 'org' -- handled directly by ShodanCollector, not expanded here.")
        return []

    log.warning(f"Unknown target type: {target.type}")
    return []
