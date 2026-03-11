import os

if os.name == 'nt':
    import ctypes
    from ctypes import wintypes
    import msvcrt
else:
    ctypes = None
    wintypes = None
    msvcrt = None


def spawn_pipe_shell(pipe_name: str):
    """Create a hidden cmd.exe whose stdio are redirected to a named pipe."""
    if os.name != 'nt':
        raise OSError("spawn_pipe_shell is only available on Windows")

    k32 = ctypes.windll.kernel32

    # open pipe for read/write
    hpipe = k32.CreateFileW(
        pipe_name,
        0xC0000000,  # GENERIC_READ | GENERIC_WRITE
        0,
        None,
        3,  # OPEN_EXISTING
        0,
        None,
    )
    if hpipe == wintypes.HANDLE(-1).value:
        raise OSError("Failed to open pipe")

    # create anonymous pipes for stdio
    sa = wintypes.SECURITY_ATTRIBUTES()
    sa.nLength = ctypes.sizeof(sa)
    sa.bInheritHandle = True

    hStdinRd = wintypes.HANDLE()
    hStdinWr = wintypes.HANDLE()
    hStdoutRd = wintypes.HANDLE()
    hStdoutWr = wintypes.HANDLE()
    hStderrWr = wintypes.HANDLE()

    k32.CreatePipe(ctypes.byref(hStdinRd), ctypes.byref(hStdinWr), ctypes.byref(sa), 0)
    k32.CreatePipe(ctypes.byref(hStdoutRd), ctypes.byref(hStdoutWr), ctypes.byref(sa), 0)
    k32.CreatePipe(ctypes.byref(hStdoutRd), ctypes.byref(hStderrWr), ctypes.byref(sa), 0)

    # set handles to be inherited by child
    k32.SetHandleInformation(hStdinWr, 1, 1)
    k32.SetHandleInformation(hStdoutRd, 1, 1)
    k32.SetHandleInformation(hStderrWr, 1, 1)

    # prepare STARTUPINFO
    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", ctypes.c_short),
            ("cbReserved2", ctypes.c_short),
            ("lpReserved2", ctypes.LPBYTE),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    si.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
    si.hStdInput = hpipe
    si.hStdOutput = hpipe
    si.hStdError = hpipe

    pi = ctypes.Structure()
    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]
    pi = PROCESS_INFORMATION()

    cmd = "cmd.exe"
    k32.CreateProcessW(None, cmd, None, None, True, 0x08000000, None, None, ctypes.byref(si), ctypes.byref(pi))
    return pi
