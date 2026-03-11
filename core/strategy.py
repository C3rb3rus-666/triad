import pkgutil
import importlib
from typing import Dict, Any, List, Optional


class StrategyEngine:
    """Decision matrix for mapping radar output to suggested exploit."""

    def __init__(self):
        self._exploits = []
        self._load_exploits()

    def _load_exploits(self) -> None:
        # iterate through core.exploits package
        try:
            import core.exploits as expkg

            pkgpath = list(expkg.__path__)[0]
            for finder, name, ispkg in pkgutil.iter_modules([pkgpath]):
                if name.startswith("_"):
                    continue
                mod = importlib.import_module(f"core.exploits.{name}")
                # expect module to provide metadata dict
                if hasattr(mod, "metadata"):
                    self._exploits.append(mod.metadata)
        except Exception:
            pass

    def suggest(self, radar_data: Dict[str, Any]) -> Optional[str]:
        """Return the name of the most appropriate exploit based on OS/ports."""
        os_name = radar_data.get("os", "Unknown")
        ports = radar_data.get("ports", {}).keys()
        for meta in self._exploits:
            if (
                os_name in meta.get("os", [])
                and any(p in ports for p in meta.get("ports", []))
            ):
                return meta.get("name")
        return None
