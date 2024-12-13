from bs4 import BeautifulSoup
from censeye.gadget import QueryGeneratorGadget


class OpenDirectoryGadget(QueryGeneratorGadget):
    """When a service is found with an open directory listing, this gadget will attempt to parse out the file names from the HTTP response body and generate queries for each file found.

This is useful for finding additional hosts with the same specific files.

Configuration
 - max_files: The maximum number of files to generate queries for.
   default: 32
 - min_chars: The minimum number of characters a file name must have to be considered.
   default: 2
"""

    def __init__(self):
        super().__init__("open-directory", aliases=["odir", "open-dir"])

        self.config["max_files"] = 32
        self.config["min_chars"] = 2

    def _parse_files(self, body: str) -> list[str]:
        parser = BeautifulSoup(body, "html.parser")
        files = []
        for a_tag in parser.find_all("a", href=True):
            href = a_tag["href"]
            if "?" not in href and not href.startswith(
                "."
            ):  # do more filtering as we come across weirdness
                files.append(href)
        return files

    def generate_query(self, host: dict) -> set[tuple[str, str]] | None:
        ret = set()
        for service in host.get("services", []):
            if "open-dir" not in service.get("labels", []):
                continue

            body = service.get("http", {}).get("response", {}).get("body", "")
            if not body:
                continue

            files = self._parse_files(body)

            for file in files:
                if len(file) < self.config["min_chars"]:
                    continue

                if len(ret) >= self.config["max_files"]:
                    break

                ret.add(
                    (
                        "open-directory",
                        f"services:(labels=open-dir and http.response.body='*{file}*')",
                    )
                )

        return ret


__gadget__ = OpenDirectoryGadget()
