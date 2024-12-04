import json
import os
from abc import ABC, abstractmethod
import logging

from appdirs import user_cache_dir


class Plugin(ABC):
    short_name: str

    def __init__(self, short_name: str):
        self.short_name = short_name

    @abstractmethod
    def run(self, host: dict) -> None:
        pass

    # Helper methods
    def get_env(self, key: str, default=None):
        return os.getenv(key, default)

    def get_cache_dir(self) -> str:
        cache_dir = user_cache_dir(f"censys/{self.short_name}")
        os.makedirs(cache_dir, exist_ok=True)
        logging.debug(f"Cache dir: {cache_dir}")
        return cache_dir

    def get_cache_file(self, filename: str) -> str:
        logging.debug(f"Cache file: {filename}")
        return os.path.join(self.get_cache_dir(), filename)

    def load_json(self, filename: str) -> dict:
        try:
            logging.debug(f"Loading JSON from {filename}")
            with open(self.get_cache_file(filename), "r") as f:
                return json.load(f)
        except FileNotFoundError:
            logging.debug(f"File not found: {filename}")
            return {}

    def save_json(self, filename: str, data: dict) -> None:
        with open(self.get_cache_file(filename), "w") as f:
            json.dump(data, f)

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.short_name})"

    def __repr__(self) -> str:
        return str(self)
