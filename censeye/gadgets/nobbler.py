from typing import Optional

from censeye.gadget import QueryGeneratorGadget


class NobblerGadget(QueryGeneratorGadget):
    """When the service_name is UNKNOWN, it is often more effective to search the first N bytes of the response rather than analyzing the entire response.

    Many services include a fixed header or a "magic number" at the beginning of their responses, followed by dynamic data at a later offset. This feature generates queries that focus on the initial N bytes of the response at various offsets while using wildcards for the remaining data.

    The goal is to make the search more generalizable: analyzing the full UNKNOWN response might only match a specific host, whereas examining just the initial N bytes is likely to match similar services across multiple hosts.

    Configuration:
    - iterations: A list of integers specifying the number of bytes to examine at the start of the response.
    - default: [4, 8, 16, 32]
    - services.banner_hex=XXXXXXXX*
    - services.banner_hex=XXXXXXXXXXXXXXXX*
    - services.banner_hex=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*
    - services.banner_hex=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX*

    "If a nibble is to bits, then a nobble is to bytes." - Aristotle
    """

    def __init__(self):
        super().__init__("nobbler", aliases=["nob", "nblr"])

        if not self.config.get("iterations"):
            self.config["iterations"] = [4, 8, 16, 32]

    def generate_query(self, host: dict) -> Optional[set[tuple[str, str]]]:
        queries = set()
        for service in host.get("services", []):
            if service.get("service_name") == "UNKNOWN":
                banner_hex = service.get("banner_hex", "")

                for i in self.config["iterations"]:
                    if len(banner_hex) > i:
                        nobbled = banner_hex[:i]
                        queries.add(
                            (
                                "nobbler",
                                f"services.banner_hex={nobbled}*",
                            )
                        )
        return queries


__gadget__ = NobblerGadget()
