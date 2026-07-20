from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)


def dedup_findings(findings: list[Finding]) -> list[Finding]:
    """
    Removes exact duplicate (ip, port, source) results within a single
    run -- e.g. if a CIDR range and an individually-listed IP overlap
    in assets.yaml.
    """
    seen = set()
    unique = []
    for f in findings:
        key = (f.ip, f.port, f.collector_source)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    dropped = len(findings) - len(unique)
    if dropped:
        log.info(f"Deduped {dropped} exact-duplicate finding(s) from this run.")
    return unique


def add_clean_status(findings: list[Finding], ip: str) -> list[Finding]:
   # If no collector found anything for this IP, append a single line - clean run
    if findings:
        return findings

    from datetime import datetime, timezone
    return [Finding(
        ip=ip,
        collector_source="easm_collector",
        status="clean",
        message=f"No exposed ports discovered for {ip} as of {datetime.now(timezone.utc).isoformat()}",
    )]
