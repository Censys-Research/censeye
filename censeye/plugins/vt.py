import requests

from ..plugin import HostLabelerPlugin


class VT:
    """silly little VT client"""

    def __init__(self, key):
        self.key = key

    def fetch_ip(self, ip) -> dict | None:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": self.key}

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        return response.json()


class VTPlugin(HostLabelerPlugin):
    def __init__(self):
        super().__init__("vt", "virustotal")
        self.api_key = self.get_env("VT_API_KEY")

    def is_malicious(self, response: dict):
        # just return true/false based on what other people say
        if response:
            stats = (
                response.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            suspicious = stats.get("suspicious", 0)
            malicious = stats.get("malicious", 0)
            return suspicious > 0 or malicious > 0
        return False

    def label_host(self, host: dict) -> None:
        # Get the IP address of the host
        ip = host["ip"]

        # Initialize the VirusTotal client
        vt = VT(self.api_key)

        # Check the cache
        cache_file = self.get_cache_file(f"{ip}.json")

        # If the cache exists, load it
        response = self.load_json(cache_file)

        # If the cache is empty, fetch the data
        if not response:
            # Fetch the data
            response = vt.fetch_ip(ip)
            # Save the response to the cache
            self.save_json(cache_file, response)

        # Check if the host is malicious
        if self.is_malicious(response):
            self.add_label(
                host,
                "in-virustotal",
                style="bold red",
                link=f"https://www.virustotal.com/gui/ip-address/{ip}",
            )


__plugin__ = VTPlugin()
