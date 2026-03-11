from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import os

# abstract away Windows-specific wintypes: on Linux provide simple integer
if os.name == 'nt':
    from ctypes import wintypes
else:
    class _Wintypes:
        HANDLE = int
        DWORD = int
        LONG = int
        WORD = int

    wintypes = _Wintypes()


class BaseEngine(ABC):
    @abstractmethod
    async def get_system_context(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def enumerate_processes(self) -> List[int]:
        pass

    @abstractmethod
    async def open_process(self, pid: int) -> Optional[wintypes.HANDLE]:
        pass

    @abstractmethod
    async def allocate_memory(self, hproc: wintypes.HANDLE, size: int) -> Optional[int]:
        pass

    @abstractmethod
    async def write_memory(
        self, hproc: wintypes.HANDLE, addr: int, data: bytes
    ) -> bool:
        pass

    @abstractmethod
    async def protect_memory(
        self, hproc: wintypes.HANDLE, addr: int, size: int, new_protect: int
    ) -> Optional[int]:
        pass

    @abstractmethod
    async def create_remote_thread(
        self, hproc: wintypes.HANDLE, entry_point: int
    ) -> Optional[wintypes.HANDLE]:
        pass

    @abstractmethod
    async def escalate_token_privileges(self) -> Optional[wintypes.HANDLE]:
        pass

    @abstractmethod
    async def inject_memory(self, pid: int, payload: bytes) -> Dict[str, Any]:
        pass


class BaseModule(ABC):
    def __init__(self, engine: BaseEngine):
        self.engine = engine
        self.results: Dict[str, Any] = {}

    @abstractmethod
    async def run(self) -> None:
        pass
