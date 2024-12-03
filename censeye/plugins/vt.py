import json
import os
import warnings

import requests
from appdirs import user_cache_dir
from ..plugin import Plugin


class VT:
    """silly little VT client"""

    def __init__(self, key=None, cache_dir=None):
        if cache_dir is None:
            cache_dir = user_cache_dir("censys/vt")
        if key is None:
            key = os.getenv("VT_API_KEY")
        os.makedirs(cache_dir, exist_ok=True)
        self.cache_dir = cache_dir
        self.key = key

    def _fetch_ip(self, ip):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": self.key}

        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            return None
        return response.json()

    def fetch_ip(self, ip):
        cache_file = os.path.join(self.cache_dir, f"{ip}.json")
        if cache_file and os.path.exists(cache_file):
            with open(cache_file, "r") as f:
                return json.load(f)
        else:
            dat = self._fetch_ip(ip)
            if dat:
                with open(cache_file, "w") as f:
                    json.dump(dat, f)
            return dat

    def is_malicious(self, ip):
        # just return true/false based on what other people say
        dat = self.fetch_ip(ip)
        if dat:
            stats = (
                dat.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            return stats.get("suspicious", 0) > 0 or stats.get("malicious", 0) > 0
        return False


class VTPlugin(Plugin):
    def __init__(self):
        super().__init__("vt")

    def run(self, host):
        vt = VT()
        if vt.is_malicious(host["ip"]):
            host["labels"].append("[bold red]in-virustotal[/bold red]")


__plugin__ = VTPlugin()
