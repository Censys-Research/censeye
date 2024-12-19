import logging
from typing import Any

import backoff
import requests
from requests.utils import default_user_agent

from censeye.gadget import HostLabelerGadget


def fatal_code(e: requests.exceptions.RequestException) -> bool:
    assert isinstance(e, requests.exceptions.RequestException)
    assert e.response is not None
    assert isinstance(e.response, requests.Response)
    assert e.response.status_code is not None
    assert isinstance(e.response.status_code, int)
    return 400 <= e.response.status_code < 500


class ThreatFoxClient:
    """
    Client for the ThreatFox API.

    Documentation: https://threatfox.abuse.ch/api/

    Example usage:
    >>> from threatfox_censys.threatfox.api import ThreatFoxClient
    >>> client = ThreatFoxClient(api_key="YOUR_API_KEY")
    """

    api_key: str
    base_url: str
    timeout: int

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://threatfox-api.abuse.ch/api/v1/",
        timeout: int = 30,
    ) -> None:
        """
        Initialize the ThreatFoxClient with the given parameters.

        :param api_key: API key for threatfox.
        :param base_url: Base URL for the API (default is their v1 endpoint).
        :param timeout: Timeout for requests (in seconds).
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")  # Remove trailing slash if it exists
        self.timeout = timeout
        self.headers = {
            "Auth-Key": self.api_key,
            "Accept": "application/json",
            "User-Agent": (
                f"{default_user_agent()} (Censeye;"
                " +https://github.com/Censys-Research/censeye)"
            ),
        }

    @backoff.on_exception(
        backoff.expo,
        requests.exceptions.RequestException,
        max_time=60,
        giveup=fatal_code,  # type: ignore[arg-type]
    )
    def _send_request(
        self, endpoint: str, method: str = "GET", data: Any = None
    ) -> dict:
        """
        Internal method to send requests to the API.

        :param endpoint: Endpoint for the API call.
        :param method: HTTP method (GET or POST).
        :param data: Dictionary with data to send (only for POST requests).
        :return: Response from the server.
        """
        url = f"{self.base_url}/{endpoint}"
        if method == "GET":
            if data:
                raise ValueError("GET requests cannot have a data parameter")
            response = requests.get(
                url, headers=self.headers, timeout=self.timeout
            )  # pragma: no cover
        elif method == "POST":
            response = requests.post(
                url, headers=self.headers, json=data, timeout=self.timeout
            )
        else:
            raise ValueError("Unsupported HTTP method")

        # Check for HTTP errors
        if not response.ok:
            # Log the error
            logging.error(
                f"Error sending request to {url}. Status code: {response.status_code}."
            )
            # Log the data if it exists
            if data:
                logging.error(f"Data: {data}")
            raise requests.HTTPError(response=response)

        return response.json()

    def get_recent_iocs(self, days: int = 3) -> dict:
        """
        Get recent IOCs on ThreatFox.

        :param days: Number of days to look back.
        :return: Response from the server.
        """
        data = {"query": "get_iocs", "days": days}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def get_ioc_by_id(self, ioc_id: str) -> dict:
        """
        Get an IOC by its ID.

        :param ioc_id: ID of the IOC.
        :return: Response from the server.
        """
        data = {"query": "ioc", "id": ioc_id}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response

    def search_iocs(self, search_term: str) -> dict:
        """
        Search for an IOC on ThreatFox.

        :param search_term: The IOC you want to search for.
        :return: Response from the server.
        """
        data = {"query": "search_ioc", "search_term": search_term}
        response = self._send_request(endpoint="", method="POST", data=data)
        return response


class ThreatFoxGadget(HostLabelerGadget):
    """Gadget to label hosts that are present in ThreatFox."""

    def __init__(self):
        super().__init__("threatfox", aliases=["tf"])
        self.api_key = self.get_env("THREATFOX_API_KEY")

    def label_host(self, host: dict) -> None:
        ip = host["ip"]

        client = ThreatFoxClient(api_key=self.api_key)
        cache_file = self.get_cache_file(f"{ip}.json")
        response = self.load_json(cache_file)

        # If the cache is empty, get the recent IOCs
        if not response:
            # Get search for IOCs related to the IP
            response = client.search_iocs(ip)
            self.save_json(cache_file, response)

        query_status = response.get("query_status", "")
        if query_status != "ok":
            return

        iocs = response.get("data", [])

        if iocs:
            self.add_label(
                host,
                "in-threatfox",
                style="bold red",
                link=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}",
            )


__gadget__ = ThreatFoxGadget()
