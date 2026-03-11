import os
import threading

_last_loot_lock = threading.Lock()
_last_loot_path: str = ""
# maintain a history of all loot files
_loot_list: list[str] = []


def set_last_loot(path: str) -> None:
    global _last_loot_path, _loot_list
    with _last_loot_lock:
        _last_loot_path = path
        # append to history
        try:
            _loot_list.append(path)
        except Exception:
            pass


def add_loot(path: str) -> None:
    """Explicitly record a loot item in the history."""
    global _loot_list
    with _last_loot_lock:
        _loot_list.append(path)


def get_last_loot() -> str:
    with _last_loot_lock:
        return _last_loot_path


def get_all_loot() -> list[str]:
    """Return a copy of the recorded list of loot file paths."""
    with _last_loot_lock:
        return list(_loot_list)
