"""Wake-on-LAN helpers shared by the agent's relay and scripts/wol_tool.py. Standard library only.

A relay is an agent that re-broadcasts a wake request on its own subnet for a server that cannot reach it.
The request arrives as a bare UDP datagram, so everything in it is untrusted: the MAC is validated before it
is used for anything, requests are only taken from the server (or addresses the operator names), and the
rate is limited so the relay cannot be turned into a broadcast generator."""
import re
import socket
import threading
import time
from collections import defaultdict, deque
from typing import Iterable, Optional, Set
from urllib.parse import urlsplit

RELAY_PORT = 9999
WOL_PORTS = (7, 9)

_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}([:-]))(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$")


def parse_mac(text) -> Optional[str]:
    """Returns the MAC as AA:BB:CC:DD:EE:FF, or None if the text is not exactly one MAC address.
    Nothing else gets through - not extra characters, not a second address, not a shell fragment."""
    if isinstance(text, bytes):
        try:
            text = text.decode("ascii")
        except UnicodeDecodeError:
            return None
    if not isinstance(text, str):
        return None
    text = text.strip()  # a trailing newline is normal (echo, nc); anything else around the address is not
    if len(text) > 17 or not _MAC.match(text):
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", text).upper()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def magic_packet(mac: str) -> bytes:
    parsed = parse_mac(mac)
    if parsed is None:
        raise ValueError("not a MAC address")
    return b"\xff" * 6 + bytes.fromhex(parsed.replace(":", "")) * 16


def broadcast_magic_packet(mac: str, targets: Iterable[str] = ("255.255.255.255",), ports=WOL_PORTS, repeats: int = 3,
                           pause: float = 0.04) -> int:
    """Sends the packet (a few times, UDP being lossy) to each broadcast address. Returns datagrams sent."""
    packet = magic_packet(mac)
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for _ in range(repeats):
            for target in targets:
                for port in ports:
                    try:
                        sock.sendto(packet, (target, port))
                        sent += 1
                    except OSError:
                        pass
            time.sleep(pause)
    return sent


def resolve_sources(server_url: str, extra: str = "") -> Set[str]:
    """The addresses a wake request may come from: the server the agent reports to, plus any the operator
    lists (comma separated) in RELAY_ALLOWED_SOURCES."""
    allowed = {s.strip() for s in (extra or "").split(",") if s.strip()}
    host = urlsplit(server_url).hostname
    if host:
        try:
            for info in socket.getaddrinfo(host, None, socket.AF_INET):
                allowed.add(info[4][0])
        except OSError:
            pass
    return allowed


class RelayPolicy:
    """Decides whether one datagram may be acted on."""

    def __init__(self, allowed_sources: Optional[Set[str]], per_source_per_minute: int = 10, total_per_minute: int = 30):
        self.allowed_sources = allowed_sources  # None = anyone (explicitly opted into)
        self.per_source = per_source_per_minute
        self.total = total_per_minute
        self._hits = defaultdict(deque)
        self._all = deque()
        self._lock = threading.Lock()

    def update_sources(self, allowed_sources: Optional[Set[str]]) -> None:
        with self._lock:
            self.allowed_sources = allowed_sources

    def check(self, source_ip: str, payload, now: Optional[float] = None) -> Optional[str]:
        """Returns the normalised MAC to wake, or None if the datagram must be ignored."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if self.allowed_sources is not None and source_ip not in self.allowed_sources:
                return None
            mac = parse_mac(payload)
            if mac is None:
                return None
            for q in (self._hits[source_ip], self._all):
                while q and now - q[0] > 60:
                    q.popleft()
            if len(self._hits[source_ip]) >= self.per_source or len(self._all) >= self.total:
                return None
            self._hits[source_ip].append(now)
            self._all.append(now)
            if len(self._hits) > 1000:
                for k in [k for k, q in self._hits.items() if not q]:
                    del self._hits[k]
            return mac
