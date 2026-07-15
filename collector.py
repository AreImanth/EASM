from pprint import pprint

from core.splunk_client import SplunkClient


def main():
    client = SplunkClient()

    result = client.send_event({
        "message": "Hello from Python - 2nd attempt",
        "source": "collector.py"
    })

    pprint(result)


if __name__ == "__main__":
    main()