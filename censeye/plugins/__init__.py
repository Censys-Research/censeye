import importlib
from pathlib import Path

from ..plugin import Plugin


def load_plugins():
    plugins = {}
    for file in Path(__file__).parent.glob("*.py"):
        if file.stem == "__init__":
            continue
        module = importlib.import_module(f"censeye.plugins.{file.stem}")
        plugin: Plugin = module.__plugin__
        plugins[plugin.short_name] = plugin
        plugins[plugin.long_name] = plugin
    return plugins


plugins = load_plugins()
