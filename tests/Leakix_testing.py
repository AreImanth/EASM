import requests
from core.config import get_settings
from collectors.leakix_client import LeakIXCollector

TEST_IP = "<testing_ip>"  

settings = get_settings()

print("=== RAW REQUEST TEST ===")
headers = {
    "api-key": settings.leakix_api_key,
    "accept": "application/json",
}
url = f"https://leakix.net/host/{TEST_IP}"

print("URL:", url)
print("Headers:", {k: (v[:6] + "...") if k == "<api_key>" and v else v for k, v in headers.items()})

resp = requests.get(url, headers=headers, timeout=15)
print("Status code:", resp.status_code)
print("Response body (first 500 chars):", resp.text[:500])

print("\n=== COLLECTOR TEST ===")
collector = LeakIXCollector(settings)
print("Configured:", collector.is_configured())

if not collector.is_configured():
    print("LEAKIX_API_KEY is missing or empty in your .env -- stopping here.")
else:
    findings = collector.collect(TEST_IP)
    print(f"\nGot {len(findings)} finding(s) for {TEST_IP}:")
    for f in findings:
        print(f)