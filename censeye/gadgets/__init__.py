import importlib
from pathlib import Path

from censeye.gadget import Gadget


def load_gadgets() -> dict[str, Gadget]:
    gadgets = {}
    for file in Path(__file__).parent.glob("*.py"):
        if file.stem == "__init__":
            continue
        module = importlib.import_module(f"censeye.gadgets.{file.stem}")
        gadget: Gadget = module.__gadget__
        gadgets[gadget.name] = gadget
    return gadgets


unarmed_gadgets = load_gadgets()
