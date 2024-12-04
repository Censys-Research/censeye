import json
import os
from abc import ABC, abstractmethod

from appdirs import user_cache_dir


class Plugin(ABC):
    short_name: str
    cache_dir: str

    def __init__(self, short_name: str):
        self.short_name = short_name
        self.cache_dir = self.get_cache_dir()

    @abstractmethod
    def run(self, host: dict) -> None:
        pass

    # Helper methods
    def get_env(self, key: str, default=None):
        return os.getenv(key, default)

    def get_cache_dir(self) -> str:
        cache_dir = user_cache_dir(f"censys/{self.short_name}")
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
        return f"{self.__class__.__name__}({self.short_name})"

    def __repr__(self) -> str:
        return str(self)
