import threading
import socket
import os

if os.name == 'nt':
    import ctypes
else:
    ctypes = None


def _create_named_pipe(name: str):
    if os.name != 'nt':
        raise OSError("Named pipes are only available on Windows")
    CNP = ctypes.windll.kernel32.CreateNamedPipeW
    return CNP(name, 0x00000003, 0, 1, 4096, 4096, 0, None)


def start_tunnel(local_port: int, remote_host: str, remote_port: int):
    """Start a simple port forwarder that uses a named pipe for transport.

    Connections to local_port are forwarded through a pipe (\\.\pipe\shadow)
    to a remote socket at remote_host:remote_port. The pipe can itself be
    mounted over SMB (\127.0.0.1\pipe\shadow) enabling pivoting via port 445.
    """

    def _worker(client_sock):
        # connect to remote
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.connect((remote_host, remote_port))
        # relay data
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
        t1 = threading.Thread(target=pump, args=(client_sock, s2), daemon=True)
        t2 = threading.Thread(target=pump, args=(s2, client_sock), daemon=True)
        t1.start(); t2.start()

    # listening socket on local_port
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("", local_port))
    listener.listen(5)

    def accept_loop():
        while True:
            cli, _ = listener.accept()
            threading.Thread(target=_worker, args=(cli,), daemon=True).start()

    threading.Thread(target=accept_loop, daemon=True).start()
    return listener
