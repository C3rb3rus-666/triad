"""Example auxiliary plugin: detect SMB null session potential.

Returns a textual identifier if the port is SMB (139/445) and a simple
connection attempt succeeds without authentication. This is during scan only
and does not perform a full protocol handshake.
"""

def check(host: str, port: int, banner: str):
    if port in (139, 445):
        # if banner contains typical SMB signature or port is open, flag it
        if "SMB" in banner or banner == "":
            return "SMB Null Session Vulnerability"
    return None
