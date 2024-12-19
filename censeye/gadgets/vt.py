from typing import Optional

import requests

from censeye.gadget import HostLabelerGadget


class VT:
    def __init__(self, key):
        self.key = key

    def fetch_ip(self, ip) -> Optional[dict]:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": self.key}

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        return response.json()


class VTGadget(HostLabelerGadget):
    """A simple VirusTotal API client which will label the host if it is found to be malicious.

    Configuration:
     - VT_API_KEY: *ENVVAR* VirusTotal API key
    """

    def __init__(self):
        super().__init__("virustotal", aliases=["vt"])
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
        ip = host["ip"]
        vt = VT(self.api_key)
        cache_file = self.get_cache_file(f"{ip}.json")
        response = self.load_json(cache_file)

        if not response:
            response = vt.fetch_ip(ip)
            if not response:
                return None
            self.save_json(cache_file, response)

        if self.is_malicious(response):
            self.add_label(
                host,
                "in-virustotal",
                style="bold red",
                link=f"https://www.virustotal.com/gui/ip-address/{ip}",
            )


__gadget__ = VTGadget()
