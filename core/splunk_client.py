import os

import requests
import urllib3
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()


class SplunkClient:
    """
    Client for interacting with Splunk HTTP Event Collector (HEC).
    """
    def __init__(self):
        self.url = os.getenv("SPLUNK_URL")
        self.token = os.getenv("SPLUNK_HEC_TOKEN")

        if not self.url:
            raise ValueError("SPLUNK_URL is not configured.")

        if not self.token:
            raise ValueError("SPLUNK_HEC_TOKEN is not configured.")

    def send_event(self, event: dict) -> dict:
        """
    Sends a single event to Splunk HEC.

    Args:
        event (dict): Event payload.

    Returns:
        dict: Standardized response object.
    """
        headers = {
            "Authorization": f"Splunk {self.token}"
        }

        payload = {
            "event": event
        }

        try:
            response = requests.post(
                url=self.url,
                headers=headers,
                json=payload,
                verify=False,
                timeout=10
            )

            if response.status_code == 200:
                return {
                    "success": True,
                    "status_code": 200,
                    "message": "Event sent successfully.",
                    "data": response.json(),
                    "error": None
                }

            error_messages = {
                400: "Bad request. Invalid event payload.",
                401: "Invalid HEC token.",
                403: "Access forbidden.",
                404: "HEC endpoint not found.",
                429: "Too many requests.",
                500: "Splunk internal server error.",
                503: "Splunk service unavailable."
            }

            return {
                "success": False,
                "status_code": response.status_code,
                "message": error_messages.get(
                    response.status_code,
                    "Unexpected response received from Splunk."
                ),
                "data": None,
                "error": response.text
            }

        except requests.exceptions.ConnectTimeout:
            return {
                "success": False,
                "status_code": None,
                "message": "Connection to Splunk timed out.",
                "data": None,
                "error": "ConnectTimeout"
            }

        except requests.exceptions.ReadTimeout:
            return {
                "success": False,
                "status_code": None,
                "message": "Splunk response timed out.",
                "data": None,
                "error": "ReadTimeout"
            }

        except requests.exceptions.ConnectionError:
            return {
                "success": False,
                "status_code": None,
                "message": "Unable to connect to Splunk.",
                "data": None,
                "error": "ConnectionError"
            }

        except requests.exceptions.SSLError:
            return {
                "success": False,
                "status_code": None,
                "message": "SSL certificate validation failed.",
                "data": None,
                "error": "SSLError"
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "status_code": None,
                "message": "Unexpected HTTP request error.",
                "data": None,
                "error": str(e)
            }

        except Exception as e:
            return {
                "success": False,
                "status_code": None,
                "message": "Unexpected application error.",
                "data": None,
                "error": str(e)
            }