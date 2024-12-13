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

        if not self.config.get("max_files"):
            self.config["max_files"] = 32
        if not self.config.get("min_chars"):
            self.config["min_chars"] = 2

    def _valid_file(self, file: str) -> bool:
        # do more filtering as we come across weirdness
        return (
            "?" not in file
            and not file.startswith(".")
            and not file == "/.."
            and len(file) >= self.config["min_chars"]
        )

    def _parse_files(self, body: str) -> set[str]:
        parser = BeautifulSoup(body, "html.parser")
        files: set[str] = set()
        for a_tag in parser.find_all("a", href=True):
            href: str = a_tag["href"]
            if self._valid_file(href):
                files.add(href)
        return files

    def generate_query(self, host: dict) -> set[tuple[str, str]] | None:
        queries: set[tuple[str, str]] = set()
        for service in host.get("services", []):
            if "open-dir" not in service.get("labels", []):
                continue

            body = service.get("http", {}).get("response", {}).get("body")
            if not body:
                continue

            files = self._parse_files(body)

            for file in files:
                if len(queries) >= self.config["max_files"]:
                    break

                queries.add(
                    (
                        "open-directory",
                        f"services:(labels=open-dir and http.response.body='*{file}*')",
                    )
                )

        return queries


__gadget__ = OpenDirectoryGadget()
