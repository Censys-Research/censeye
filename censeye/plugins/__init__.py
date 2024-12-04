import importlib
from pathlib import Path


def load_plugins():
    plugins = {}
    for file in Path(__file__).parent.glob("*.py"):
        if file.stem == "__init__":
            continue
        module = importlib.import_module(f"censeye.plugins.{file.stem}")
        plugin = module.__plugin__
        plugins[plugin.short_name] = plugin
    return plugins


plugins = load_plugins()
