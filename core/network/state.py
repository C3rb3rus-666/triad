import threading

# shared receiver state (avoids circular imports)
sessions = {}
lock = threading.Lock()
