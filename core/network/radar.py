import socket
import importlib
import pkgutil
from pathlib import Path
from typing import List, Dict, Any, Optional
import subprocess
import time
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor


# internal mapping of simple banners to vulnerability ids
VULN_DB: Dict[bytes, str] = {
    b"Microsoft-HTTPAPI/2.0": "CVE-2015-1635",
    b"SMB": "CVE-2020-0796",
}


def _load_plugins() -> List[Any]:
    """Discover and import all modules under core.auxiliary that define a
    `check(host, port, banner)` function.  Plugins return an identifier when
    they detect a vulnerability or None otherwise.
    """
    plugins = []
    try:
        import core.auxiliary as auxpkg

        pkgpath = list(auxpkg.__path__)[0]
        for finder, name, ispkg in pkgutil.iter_modules([pkgpath]):
            if name.startswith("_"):
                continue
            mod = importlib.import_module(f"core.auxiliary.{name}")
            if hasattr(mod, "check"):
                plugins.append(mod)
    except Exception:
        pass
    return plugins


_PLUGINS = _load_plugins()


def _detect_os_from_ttl_window(ttl: int, window: int) -> str:
    """Basic heuristic mapping TTL/window to Windows family.

    - TTL >= 128 is treated as modern (Win10/11/Server2022)
    - TTL < 128 treated as legacy (Win7/Server2008)
    """
    if ttl >= 128 or window >= 65535:
        return "Modern Windows"
    return "Windows Legacy"


def _get_local_subnet() -> str:
    """Query the local interface and return a CIDR string (e.g. '192.168.1.0/24')."""
    # try ipconfig parse
    try:
        out = subprocess.check_output("ipconfig", shell=True, text=True, errors="ignore")
        last_ip = None
        last_mask = None
        for line in out.splitlines():
            if "IPv4 Address" in line or "Dirección IPv4" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    last_ip = parts[1].strip()
            if "Subnet Mask" in line or "Máscara de subred" in line:
                parts = line.split(":")
                if len(parts) >= 2:
                    last_mask = parts[1].strip()
            if last_ip and last_mask:
                break
        if last_ip and last_mask:
            net = ipaddress.IPv4Network(f"{last_ip}/{last_mask}", strict=False)
            return str(net)
    except Exception:
        pass
    # fallback to /24 on host ip
    try:
        host = socket.gethostbyname(socket.gethostname())
        return f"{host}/24"
    except Exception:
        return "127.0.0.1/32"


def auto_discover_network(timeout: float = 0.1) -> List[Dict[str, Any]]:
    """Discover live hosts on the local subnet with OS estimates.

    Performs a fast ICMP sweep using `ping` bursts interleaved with small
    sleeps to avoid triggering aggressive firewall rate‑limiting.  For each
    responsive address we perform a quick TCP connect to common ports to
    capture TTL/window for an OS guess.
    """
    cidr = _get_local_subnet()
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []

    hosts = list(network.hosts())
    discovered: List[Dict[str, Any]] = []
    lock = threading.Lock()

    def probe(ip):
        ipstr = str(ip)
        # ICMP ping
        try:
            p = subprocess.run(["ping", "-n", "1", "-w", str(int(timeout*1000)), ipstr],
                               capture_output=True, text=True)
            if "TTL=" not in p.stdout:
                return
        except Exception:
            return
        # resolved hostname
        try:
            hn = socket.gethostbyaddr(ipstr)[0]
        except Exception:
            hn = ""
        # perform a dummy TCP connect to extract ttl/window
        ttl = 0
        window = 0
        for port in (80, 445, 3389):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                res = s.connect_ex((ipstr, port))
                if res == 0:
                    try:
                        ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                    except Exception:
                        ttl = 0
                    try:
                        window = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                    except Exception:
                        window = 0
                    break
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        osstr = _detect_os_from_ttl_window(ttl, window)
        rec = {"ip": ipstr, "hostname": hn, "os": osstr, "status": "up"}
        with lock:
            discovered.append(rec)

    # burst/pausing loop
    with ThreadPoolExecutor(max_workers=64) as exe:
        for idx, ip in enumerate(hosts):
            exe.submit(probe, ip)
            # insert a tiny pause every 20 probes to stay stealthy
            if idx % 20 == 0:
                time.sleep(0.02)
        exe.shutdown(wait=True)
    return discovered


def grab_banner(sock: socket.socket, port: int) -> str:
    """Attempt a lightweight banner grab; avoid full protocol exchanges."""
    banner = b""
    sock.settimeout(0.5)
    try:
        if port == 80 or port == 8080:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            # FTP will send banner immediately
            pass
        # read up to 1024 bytes
        banner = sock.recv(1024)
    except Exception:
        pass
    return banner.decode("latin1", errors="ignore")


def scan_target(ip: str, ports: Optional[List[int]] = None) -> Dict[str, Any]:
    """Scan a host for open ports; perform OS fingerprint and vuln checks.

    Returns a dictionary with keys:
        "os": detected OS string
        "ports": {port: {"banner": str, "vulns": [str, ...]}}
    """
    if ports is None:
        # common service ports
        ports = [21, 22, 23, 25, 53, 80, 139, 445, 3389]

    results: Dict[int, Dict[str, Any]] = {}
    detected_os = "Unknown"

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        try:
            res = s.connect_ex((ip, port))
            if res == 0:
                # capture some socket options for OS fingerprint
                try:
                    ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                except Exception:
                    ttl = 0
                try:
                    window = s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                except Exception:
                    window = 0
                if detected_os == "Unknown":
                    detected_os = _detect_os_from_ttl_window(ttl, window)
                banner = grab_banner(s, port)
                vulns = []
                for signature, vid in VULN_DB.items():
                    if signature.decode(errors="ignore") in banner:
                        vulns.append(vid)
                for plugin in _PLUGINS:
                    try:
                        found = plugin.check(ip, port, banner)
                        if found:
                            vulns.append(found)
                    except Exception:
                        continue
                results[port] = {"banner": banner.strip(), "vulns": vulns}
        except Exception:
            pass
        finally:
            s.close()
    return {"os": detected_os, "ports": results}
