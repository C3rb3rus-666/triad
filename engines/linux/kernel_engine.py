import os
import asyncio
from typing import Dict, Any, Optional, List
from core.interfaces import BaseEngine, TriadMemoryError

class LinuxEngine(BaseEngine):
    """Lightweight Linux execution engine.

    Provides minimal analogues to the Windows engine for enumeration and memory
    operations using /proc.  Full remote code injection is not implemented but
    the interfaces are satisfied so that the orchestrator and modules can
    operate without import errors on Linux hosts.
    """

    async def get_system_context(self) -> Dict[str, Any]:
        return {"os": "Linux", "release": os.uname().release}

    async def enumerate_processes(self) -> List[int]:
        pids: List[int] = []
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                try:
                    pids.append(int(entry))
                except ValueError:
                    continue
        return pids

    async def open_process(self, pid: int) -> Optional[object]:
        # return a file handle to /proc/<pid>/mem for read/write operations
        try:
            return open(f"/proc/{pid}/mem", "rb+")
        except Exception:
            return None

    async def allocate_memory(self, hproc: object, size: int) -> Optional[int]:
        # no easy cross-process allocation; return None
        return None

    async def write_memory(
        self, hproc: object, addr: int, data: bytes
    ) -> bool:
        try:
            hproc.seek(addr)
            hproc.write(data)
            return True
        except Exception:
            return False

    async def protect_memory(
        self, hproc: object, addr: int, size: int, new_protect: int
    ) -> Optional[int]:
        # not supported; return None to indicate failure
        return None

    async def create_remote_thread(
        self, hproc: object, entry_point: int
    ) -> Optional[int]:
        # executing remote code requires ptrace; not implemented here
        return None

    async def escalate_token_privileges(self) -> Optional[int]:
        # on Linux, privileges are tied to uid; nothing to escalate
        return None

    async def inject_memory(self, pid: int, payload: bytes) -> Dict[str, Any]:
        # best-effort attempt: open mem and write at 0 (will likely fail)
        ctx: Dict[str, Any] = {"pid": pid}
        proc = await self.open_process(pid)
        if not proc:
            ctx["error"] = "unable to open process memory"
            return ctx
        try:
            proc.write(payload)
            ctx["written"] = len(payload)
        except Exception as e:
            ctx["error"] = str(e)
        return ctx
