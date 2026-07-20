import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(dotenv_path=_PROJECT_ROOT / ".env", override=True)


@dataclass(frozen=True)
class Settings:
    # --- Collectors (all optional -- each source degrades gracefully if unset) ---
    shodan_api_key: str | None
    censys_pat: str | None
    censys_org_id: str | None
    netlas_api_key: str | None
    leakix_api_key: str | None


    # --- Transport: Splunk (required for now -- the only working transport) ---
    splunk_hec_url: str
    splunk_hec_token: str
    splunk_index: str
    splunk_verify_ssl: bool

    # --- Paths ---
    project_root: Path

   # -- smtp used for sending the email---
    smtp_host: str | None
    smtp_port: int
    smtp_user: str | None
    smtp_password: str | None
    soc_email_to: str | None


def _require(var_name: str) -> str:
    value = os.getenv(var_name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable: {var_name}. "
            f"Check your .env file (see .env.example)."
        )
    return value


def get_settings() -> Settings:
    return Settings(
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        censys_pat=os.getenv("CENSYS_PAT"),
        censys_org_id=os.getenv("CENSYS_ORG_ID"),
        netlas_api_key=os.getenv("NETLAS_API_KEY"), 
        leakix_api_key=os.getenv("LEAKIX_API_KEY"),
        splunk_hec_url=_require("SPLUNK_HEC_URL"),
        splunk_hec_token=_require("SPLUNK_HEC_TOKEN"),
        splunk_index=os.getenv("SPLUNK_INDEX", "as_index"),
        splunk_verify_ssl=os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true",
        project_root=_PROJECT_ROOT,
        smtp_host=os.getenv("SMTP_HOST"),
        smtp_port=int(os.getenv("SMTP_PORT", "587")),
        smtp_user=os.getenv("SMTP_USER"),
        smtp_password=os.getenv("SMTP_PASSWORD"),
        soc_email_to=os.getenv("SOC_EMAIL_TO"),
    )
