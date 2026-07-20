import smtplib
from email.mime.text import MIMEText

from core.config import Settings
from core.logger import get_logger
from core.models import Finding

log = get_logger(__name__)


def send_new_exposure_email(findings: list[Finding], settings: Settings) -> bool:
    if not findings:
        return True

    if not (settings.smtp_host and settings.smtp_user and settings.smtp_password and settings.soc_email_to):
        log.warning("SMTP not fully configured -- skipping email alert.")
        return False

    lines = [
        f"{f.ip}:{f.port}  severity={f.severity}  source={f.collector_source}"
        for f in findings
    ]
    body = "New exposures detected:\n\n" + "\n".join(lines)

    msg = MIMEText(body)
    msg["Subject"] = f"[EASM] {len(findings)} New Exposure(s) Detected"
    msg["From"] = settings.smtp_user
    msg["To"] = settings.soc_email_to

    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_user, [settings.soc_email_to], msg.as_string())
        log.info(f"Email alert sent for {len(findings)} new exposure(s).")
        return True
    except Exception as e:
        log.error(f"Failed to send email alert: {e}")
        return False