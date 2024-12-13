import json
import os
from abc import ABC, abstractmethod
from typing import Any, Dict

from appdirs import user_cache_dir

GADGET_NAMESPACE = "gadget.censeye"


class Gadget(ABC):
    name: str
    aliases: list[str]
    cache_dir: str
    config: Dict[str, Any] = {}

    Namespace = GADGET_NAMESPACE

    def __init__(
        self,
        name: str,
        aliases: list[str] = [],
        config: Dict[str, Any] = {},
    ):
        self.name = name
        self.aliases = aliases
        self.cache_dir = self.get_cache_dir()
        self.config = config

    @abstractmethod
    def run(self, host: dict) -> None:
        pass

    def set_config(self, config: Dict[str, Any] | None) -> None:
        self.config = config or self.config

    def get_env(self, key: str, default=None):
        return os.getenv(key, default)

    def get_cache_dir(self) -> str:
        cache_dir = user_cache_dir(f"censys/{self.name}")
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def get_cache_file(self, filename: str) -> str:
        return os.path.join(self.cache_dir, filename)

    def load_json(self, filename: str) -> dict:
        try:
            with open(self.get_cache_file(filename), "r") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_json(self, filename: str, data: dict) -> None:
        with open(self.get_cache_file(filename), "w") as f:
            json.dump(data, f)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.name})"

    def __repr__(self) -> str:
        return str(self)


class HostLabelerGadget(Gadget):
    @abstractmethod
    def label_host(self, host: dict) -> None:
        pass

    def run(self, host: dict) -> None:
        self.label_host(host)

    def add_label(
        self, host: dict, label: str, style: str | None = None, link: str | None = None
    ) -> None:
        if style:
            label = f"[{style}]{label}[/{style}]"
        if link:
            label = f"[link={link}]{label}[/link]"
        host["labels"].append(label)


class QueryGeneratorGadget(Gadget):
    @abstractmethod
    def generate_query(self, host: dict) -> set[tuple[str, str]] | None:
        pass

    def run(self, host: dict) -> set[tuple[str, str]] | None:
        ret = set()
        q = self.generate_query(host)

        if not q:
            return None

        for k, v in q:
            if not k.endswith(self.Namespace):
                k = f"{k}.{self.Namespace}"
            ret.add((k, v))

        return ret
