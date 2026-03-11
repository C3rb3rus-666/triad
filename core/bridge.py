import asyncio
import traceback
import time
import json
import os
import ctypes
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from core.logger import StructuredLogger


class EventType(Enum):
    TARGET_DISCOVERED = "TARGET_DISCOVERED"
    TARGET_COMPROMISED = "TARGET_COMPROMISED"
    INJECTION_INITIATED = "INJECTION_INITIATED"
    INJECTION_COMPLETE = "INJECTION_COMPLETE"
    PAYLOAD_EXECUTED = "PAYLOAD_EXECUTED"
    UI_MANIPULATION_SUCCESS = "UI_MANIPULATION_SUCCESS"
    ERROR_OCCURRED = "ERROR_OCCURRED"
    ENGINE_EXCEPTION = "ENGINE_EXCEPTION"
    MODULE_FAILURE = "MODULE_FAILURE"


@dataclass(frozen=True)
class TelemetryEvent:
    event_type: EventType
    timestamp: float
    target_id: str
    metadata: Dict[str, Any]
    source_module: str
    exception_type: Optional[str] = None
    error_code: Optional[int] = None
    stacktrace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "target_id": self.target_id,
            "metadata": self.metadata,
            "source_module": self.source_module,
            "exception_type": self.exception_type,
            "error_code": f"{self.error_code:#x}" if self.error_code else None,
            "stacktrace": self.stacktrace,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class EventSubscriber:
    def __init__(
        self, callback: Callable[[TelemetryEvent], Any], event_types: Set[EventType]
    ):
        self.callback = callback
        self.event_types = event_types

    async def notify(self, event: TelemetryEvent) -> None:
        if event.event_type in self.event_types:
            try:
                result = self.callback(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                # swallowed at bridge level; caller can inspect logs
                raise


class CommunicationBridge:
    """Single point of data exchange for modules and engines.

    - Uses asyncio.Queue for event passing
    - Records structured telemetry (JSON)
    - Subscribers may be sync/async callables
    """

    def __init__(self) -> None:
        self._target_map: Dict[str, Dict[str, Any]] = {}
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._subscribers: List[EventSubscriber] = []
        self._event_log: List[TelemetryEvent] = []
        self._lock: asyncio.Lock = asyncio.Lock()
        self._logger = StructuredLogger()
        # register default history subscriber to capture key events
        try:
            self.subscribe(self._history_subscriber)
        except Exception:
            # do not raise during initialization
            pass

    def _history_file_path(self) -> Path:
        # repository root (two levels up from core)
        root = Path(__file__).resolve().parents[1]
        return root / '.triad_history'

    def _ensure_hidden(self, p: Path) -> None:
        try:
            if os.name == 'nt':
                ctypes.windll.kernel32.SetFileAttributesW(str(p), 0x02)
        except Exception:
            # best-effort only
            pass

    def _append_history(self, record: Dict[str, Any]) -> None:
        p = self._history_file_path()
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            with p.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + '\n')
            # mark hidden on Windows
            self._ensure_hidden(p)
        except Exception:
            # silently ignore IO failures to avoid breaking bridge
            pass

    def _history_subscriber(self, event: TelemetryEvent) -> None:
        # Synchronous subscriber — EventSubscriber will await if needed
        try:
            et = event.event_type
            rec = event.to_dict()
            # write to hidden history file for key events
            if et in (EventType.UI_MANIPULATION_SUCCESS, EventType.INJECTION_COMPLETE, EventType.ENGINE_EXCEPTION):
                self._append_history(rec)

            # concise operator messages
            proc = rec.get('metadata', {}).get('process_name') or rec.get('target_id')
            try:
                if et == EventType.INJECTION_COMPLETE:
                    if proc:
                        print(f"[+] target hit: {proc}")
                elif et == EventType.UI_MANIPULATION_SUCCESS:
                    if proc:
                        print(f"[*] uia_mod success: {proc}")
                elif et == EventType.ENGINE_EXCEPTION:
                    md = rec.get('metadata', {})
                    msg = str(md.get('message', '') or md.get('stdout', '') or md.get('stderr', ''))
                    if 'v_qry' in msg or 'VirtualQueryEx' in msg:
                        print("[!] v_qry fail")
            except Exception:
                pass
        except Exception:
            # swallow subscriber errors
            pass

    def subscribe(
        self,
        callback: Callable[[TelemetryEvent], Any],
        event_types: Optional[Set[EventType]] = None,
    ) -> None:
        if event_types is None:
            event_types = set(EventType)
        self._subscribers.append(EventSubscriber(callback, event_types))

    async def publish_event(
        self,
        event_type: EventType,
        target_id: str,
        metadata: Dict[str, Any],
        source_module: str,
        exception_type: Optional[str] = None,
        error_code: Optional[int] = None,
        stacktrace: Optional[str] = None,
    ) -> None:
        event = TelemetryEvent(
            event_type=event_type,
            timestamp=time.time(),
            target_id=target_id,
            metadata=metadata,
            source_module=source_module,
            exception_type=exception_type,
            error_code=error_code,
            stacktrace=stacktrace,
        )

        async with self._lock:
            self._event_log.append(event)

        # log structured telemetry
        await self._logger.info(
            "bridge", f"telemetry.{event.event_type.value}", event.to_dict()
        )

        await self._event_queue.put(event)

        for subscriber in list(self._subscribers):
            try:
                await subscriber.notify(event)
            except Exception:
                # Do not allow subscriber failures to propagate
                await self._logger.error(
                    "bridge",
                    "subscriber_notify_failed",
                    {
                        "subscriber": repr(subscriber),
                        "event": event.to_dict(),
                        "trace": traceback.format_exc(),
                    },
                )

    async def register_target(self, identifier: str, metadata: Dict[str, Any]) -> None:
        async with self._lock:
            if identifier not in self._target_map:
                self._target_map[identifier] = {
                    "id": identifier,
                    "discovered_at": time.time(),
                    "metadata": metadata,
                    "status": "DISCOVERED",
                }
            else:
                self._target_map[identifier]["metadata"].update(metadata)

        await self.publish_event(
            EventType.TARGET_DISCOVERED, identifier, metadata, "bridge.register_target"
        )

    async def mark_compromised(
        self, identifier: str, compromise_data: Dict[str, Any]
    ) -> None:
        async with self._lock:
            if identifier in self._target_map:
                self._target_map[identifier]["status"] = "COMPROMISED"
                self._target_map[identifier]["compromised_at"] = time.time()
                self._target_map[identifier]["compromise_data"] = compromise_data

        await self.publish_event(
            EventType.TARGET_COMPROMISED,
            identifier,
            compromise_data,
            "bridge.mark_compromised",
        )

    async def publish_engine_error(
        self,
        target_id: str,
        exception_type: str,
        error_code: Optional[int],
        metadata: Dict[str, Any],
    ) -> None:
        stack = metadata.get("stacktrace") if isinstance(metadata, dict) else None
        await self.publish_event(
            EventType.ENGINE_EXCEPTION,
            target_id,
            metadata,
            "bridge.engine_error",
            exception_type=exception_type,
            error_code=error_code,
            stacktrace=stack,
        )

    async def publish_module_error(
        self,
        module_name: str,
        target_id: str,
        error_message: str,
        metadata: Dict[str, Any],
    ) -> None:
        stack = metadata.get("stacktrace") if isinstance(metadata, dict) else None
        await self.publish_event(
            EventType.MODULE_FAILURE,
            target_id,
            {**metadata, "module": module_name, "error": error_message},
            f"bridge.module_error[{module_name}]",
            exception_type=(
                metadata.get("exception_type") if isinstance(metadata, dict) else None
            ),
            error_code=(
                metadata.get("error_code") if isinstance(metadata, dict) else None
            ),
            stacktrace=stack,
        )

    def get_targets(
        self, filter_attr: Optional[str] = None, filter_value: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        targets = list(self._target_map.values())
        if filter_attr and filter_value:
            targets = [t for t in targets if t.get(filter_attr) == filter_value]
        return targets

    def get_target(self, identifier: str) -> Optional[Dict[str, Any]]:
        return self._target_map.get(identifier)

    async def pull_event(
        self, timeout: Optional[float] = None
    ) -> Optional[TelemetryEvent]:
        try:
            return await asyncio.wait_for(self._event_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    def get_event_log(self, since: Optional[float] = None) -> List[Dict[str, Any]]:
        if since is None:
            return [e.to_dict() for e in self._event_log]
        return [e.to_dict() for e in self._event_log if e.timestamp >= since]

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "total_targets": len(self._target_map),
            "compromised_targets": len(
                [
                    t
                    for t in self._target_map.values()
                    if t.get("status") == "COMPROMISED"
                ]
            ),
            "total_events": len(self._event_log),
            "active_subscribers": len(self._subscribers),
            "queue_size": self._event_queue.qsize(),
        }
