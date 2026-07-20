"""
utils/local_baseline.py
-------------------------------------------------------------
Local, file-based "is this new" check -- runs entirely inside
main.py, synchronously, every time the script executes. This is
what makes alerting independent of Splunk's own scheduler or any
OS-level task scheduler: the check happens the moment the script
runs, not on a separate clock.
-------------------------------------------------------------
"""

import csv
from datetime import datetime, timezone
from pathlib import Path

from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)


def load_known(path: str = "data/known_exposures.csv") -> dict[tuple[str, int], dict]:
    known = {}
    file_path = Path(path)
    if not file_path.exists():
        return known

    with file_path.open("r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                known[(row["ip"], int(row["port"]))] = row
            except (KeyError, ValueError):
                continue
    return known


def find_new_findings(findings: list[Finding], known: dict) -> list[Finding]:
    """Returns only findings whose (ip, port) isn't already in the baseline."""
    return [
        f for f in findings
        if f.port is not None and (f.ip, f.port) not in known
    ]


def update_baseline(findings: list[Finding], path: str = "data/known_exposures.csv") -> None:
    """Merges today's findings into the local baseline file."""
    known = load_known(path)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for f in findings:
        if f.port is None:
            continue
        key = (f.ip, f.port)
        if key in known:
            known[key]["last_seen"] = today
        else:
            known[key] = {"ip": f.ip, "port": str(f.port), "first_seen": today, "last_seen": today}

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "port", "first_seen", "last_seen"])
        writer.writeheader()
        writer.writerows(known.values())

    log.info(f"Baseline updated: {len(known)} total known exposures tracked.")