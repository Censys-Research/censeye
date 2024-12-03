from abc import ABC, abstractmethod


class Plugin(ABC):
    short_name: str

    def __init__(self, short_name: str):
        self.short_name = short_name

    @abstractmethod
    def run(self, host: dict) -> None:
        pass

    def __str__(self) -> str:
        return f"{self.__class__.__name__}({self.short_name})"

    def __repr__(self) -> str:
        return str(self)
