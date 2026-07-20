import csv
from pathlib import Path

from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)

DEFAULT_SEVERITY = "Low"

class RiskEngine:
    def __init__(self, rules_path: str = "data/severity_rules.csv"):
        self.rules_path = Path(rules_path)
        self._rules: dict[int, str] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        if not self.rules_path.exists():
            log.warning(f"Severity rules file not found at {self.rules_path} -- all findings will use default severity '{DEFAULT_SEVERITY}'.")
            return

        with self.rules_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    port = int(row["port"])
                    self._rules[port] = row["severity"]
                except (KeyError, ValueError) as e:
                    log.warning(f"Skipping malformed row in {self.rules_path}: {row} ({e})")

        log.info(f"Loaded {len(self._rules)} severity rules from {self.rules_path}")

    def score(self, finding: Finding) -> str:
        """Returns a severity string for a single Finding."""
        if finding.status == "clean" or finding.port is None:
            return "N/A"
        return self._rules.get(finding.port, DEFAULT_SEVERITY)

    def score_all(self, findings: list[Finding]) -> list[Finding]:
        for f in findings:
            f.severity = self.score(f)
        return findings
