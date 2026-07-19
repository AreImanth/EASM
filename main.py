import collectors
from core.assets import load_targets, expand_target, AssetLoadError
from core.config import get_settings
from core.logger import get_logger
from core.models import Target
from core.risk_engine import RiskEngine

from collectors.internetdb_client import InternetDBCollector
from collectors.censys_client import CensysCollector
from collectors.shodan_client import ShodanCollector
from collectors.netlas_collector import NetlasCollector
from collectors.leakix_client import LeakIXCollector

from transport.splunk_hec import SplunkHECTransport

from utils.processors import dedup_findings, add_clean_status

log = get_logger(__name__)


def build_collectors(settings) -> list:

    collectors = [InternetDBCollector()]

    censys = CensysCollector(settings)
    if censys.is_configured():
        collectors.append(censys)
    else:
        log.info("Censys not configured -- running without it (InternetDB only for IP/CIDR targets).")
    
    netlas = NetlasCollector(settings)
    if netlas.is_configured():
        collectors.append(netlas)
    else:
        log.info("Netlas not configured -- running without it.")

    leakix = LeakIXCollector(settings)
    if leakix.is_configured():
        collectors.append(leakix)
    else:
        log.info("LeakIX not configured -- running without it.")

    shodan = ShodanCollector(settings)
    if shodan.is_configured():
        collectors.append(shodan)       
    else:
        log.info("Shodan not configured -- running without it (org targets also skipped).")

    return collectors


def build_transports(settings) -> list:
  #so far splunk is the oly tool which is configured, sentinel, wazuh, elk will be configured later
    return [SplunkHECTransport(settings)]


def process_target(target: Target, collectors: list, shodan: ShodanCollector) -> list:
    findings = []

    if target.type == "org":
        # Only Shodan's filtered search can handle org-wide queries.
        query = f'org:"{target.value}"'
        findings.extend(shodan.collect_org(query))
        findings = add_clean_status(findings, target.value)
        return findings

    ip_list = expand_target(target)
    for ip in ip_list:
        ip_findings = []
        for collector in collectors:
            try:
                ip_findings.extend(collector.collect(ip))
            except Exception as e:
                log.error(f"[{collector.source_name}] unexpected failure on {ip}: {e}")
                continue
        ip_findings = add_clean_status(ip_findings, ip)
        findings.extend(ip_findings)

    return findings


def main():
    log.info("=== EASM Collector run started ===")
    settings = get_settings()

    try:
        targets = load_targets("assets.yaml")
    except AssetLoadError as e:
        log.error(f"Cannot proceed: {e}")
        return

    if not targets:
        log.warning("No targets loaded -- exiting.")
        return

    collectors = build_collectors(settings)
    shodan = ShodanCollector(settings)
    if not shodan.is_configured():
        log.info("Shodan (paid filtered search) not configured -- 'org' type targets will be skipped.")

    risk_engine = RiskEngine("data/severity_rules.csv")
    transports = build_transports(settings)

    all_findings = []
    for target in targets:
        target_findings = process_target(target, collectors, shodan)
        all_findings.extend(target_findings)

    all_findings = dedup_findings(all_findings)
    all_findings = risk_engine.score_all(all_findings)

    log.info(f"Total findings this run: {len(all_findings)}")

    for transport in transports:
        try:
            result = transport.send(all_findings)
            if not result.success:
                log.error(f"[{transport.destination_name}] send failed: {result.message}")
        except Exception as e:
            log.error(f"[{transport.destination_name}] unexpected failure: {e}")

    log.info("=== EASM Collector run finished ===")


if __name__ == "__main__":
    main()
