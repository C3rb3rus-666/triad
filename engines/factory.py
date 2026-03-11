import platform
from typing import Optional
from core.interfaces import BaseEngine
from engines.windows.vx_eng import WinEngine

try:
    from engines.linux.kernel_engine import LinuxEngine

    _LINUX_AVAILABLE = True
except ImportError:
    _LINUX_AVAILABLE = False

try:
    from engines.android.adb_eng import AdbEngine

    _ANDROID_AVAILABLE = True
except ImportError:
    _ANDROID_AVAILABLE = False


class EngineFactory:
    """
    Abstraction Factory for OS-specific execution engines.
    Resolves the required backend based on host telemetry or explicit override.
    """

    @staticmethod
    def get_engine(os_type: Optional[str] = None) -> BaseEngine:
        """
        Returns an initialized instance of the requested OS engine.
        Defaults to current host OS if no type is provided.
        """
        target_os = os_type or platform.system()
        target_norm = target_os.lower()

        if target_norm == "linux":
            if _LINUX_AVAILABLE:
                return LinuxEngine()
            else:
                raise NotImplementedError(
                    "Linux engine is not available in this deployment"
                )

        if target_norm in ("windows", "microsoft"):
            return WinEngine()

        if target_norm in ("android", "adb"):
            if _ANDROID_AVAILABLE:
                return AdbEngine()
            raise NotImplementedError(
                "Android ADB engine is not available in this deployment"
            )

        raise NotImplementedError(
            f"Engine core for {target_os} is not supported in this version."
        )
