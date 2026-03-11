import asyncio
import json
import time
from typing import Dict, Any, List
from enum import Enum
from dataclasses import dataclass


class LogLevel(Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class LogEntry:
    level: str
    timestamp: float
    module: str
    message: str
    data: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "timestamp": self.timestamp,
            "module": self.module,
            "message": self.message,
            "data": self.data,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class StructuredLogger:
    def __init__(self, max_entries: int = 10000):
        self._log_buffer: List[LogEntry] = []
        self._max_entries = max_entries
        self._lock = asyncio.Lock()

    async def log(
        self, level: LogLevel, module: str, message: str, data: Dict[str, Any] = None
    ):
        if data is None:
            data = {}

        entry = LogEntry(
            level=level.value,
            timestamp=time.time(),
            module=module,
            message=message,
            data=data,
        )

        async with self._lock:
            self._log_buffer.append(entry)
            if len(self._log_buffer) > self._max_entries:
                self._log_buffer.pop(0)

    async def debug(self, module: str, message: str, data: Dict[str, Any] = None):
        await self.log(LogLevel.DEBUG, module, message, data)

    async def info(self, module: str, message: str, data: Dict[str, Any] = None):
        await self.log(LogLevel.INFO, module, message, data)

    async def warning(self, module: str, message: str, data: Dict[str, Any] = None):
        await self.log(LogLevel.WARNING, module, message, data)

    async def error(self, module: str, message: str, data: Dict[str, Any] = None):
        await self.log(LogLevel.ERROR, module, message, data)

    async def critical(self, module: str, message: str, data: Dict[str, Any] = None):
        await self.log(LogLevel.CRITICAL, module, message, data)

    def get_logs(
        self, level: LogLevel = None, module: str = None, limit: int = None
    ) -> List[Dict[str, Any]]:
        filtered = self._log_buffer

        if level:
            filtered = [e for e in filtered if e.level == level.value]

        if module:
            filtered = [e for e in filtered if e.module == module]

        if limit:
            filtered = filtered[-limit:]

        return [e.to_dict() for e in filtered]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_entries": len(self._log_buffer),
            "by_level": {
                level.value: len(
                    [e for e in self._log_buffer if e.level == level.value]
                )
                for level in LogLevel
            },
        }
