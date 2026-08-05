"""stdlib sd_notify helper (READY / WATCHDOG / STATUS). No-op without NOTIFY_SOCKET."""

from __future__ import annotations

import os
import socket
from typing import Optional


def _send(msg: str) -> bool:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return False
    try:
        # abstract namespace sockets start with @
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(addr)
            sock.sendall(msg.encode("utf-8"))
        finally:
            sock.close()
        return True
    except OSError:
        return False


def ready(status: Optional[str] = None) -> bool:
    parts = ["READY=1"]
    if status:
        parts.append(f"STATUS={status}")
    return _send("\n".join(parts))


def watchdog() -> bool:
    return _send("WATCHDOG=1")


def status(text: str) -> bool:
    return _send(f"STATUS={text}")


def stopping() -> bool:
    return _send("STOPPING=1")
