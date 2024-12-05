from censeye.gadget import QueryGeneratorGadget


class NobblerGadget(QueryGeneratorGadget):
    """
    When we see UNKNOWN service types it means Censys couldn't detect the underlying protocol, but
    recv'd some data from the service. Sometimes this data is some binary encoded format that has
    a specific structure to it, but simply searching for the entirety of the response may not net
    the best results, so this gadget will generate queries that search for the first N bytes of the
    response. This is useful for protocols that have a fixed header, or a specific magic number at the
    beginning of the response.

    "If a nibble is to bits, then a nobble is to bytes." - Aristotle
    """

    def __init__(self):
        super().__init__("nblr", "nobbler")
        self.config["iterations"] = [4, 8, 16, 32]

    def generate_query(self, host: dict) -> set[tuple[str, str]] | None:
        ret = set()
        for service in host.get("services", []):
            if service.get("service_name") == "UNKNOWN":
                banner_hex = service.get("banner_hex", "")

                for i in self.config["iterations"]:
                    if len(banner_hex) > i:
                        nobbled = banner_hex[:i]
                        ret.add(
                            (
                                "nobbler",
                                f"services.banner_hex={nobbled}*",
                            )
                        )
        return ret


__gadget__ = NobblerGadget()
