"""Small, FastAPI-free helpers for deciding who is calling and what may be scanned."""
import ipaddress
from typing import List, Tuple

from backend.app.core.config import settings


def _networks(entries) -> list:
    nets = []
    for entry in entries or []:
        try:
            nets.append(ipaddress.ip_network(str(entry).strip(), strict=False))
        except ValueError:
            continue  # a typo in the list must not widen what is trusted
    return nets


def _is_trusted_proxy(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in net for net in _networks(settings.TRUSTED_PROXIES))


def client_ip(request) -> str:
    """The address of the caller. X-Forwarded-For is only believed when the connection itself comes
    from a proxy listed in TRUSTED_PROXIES, and then the right-most entry that is not itself a trusted
    proxy is used: that is the one our own proxy appended, whatever the client wrote to its left."""
    peer = request.client.host if getattr(request, "client", None) else ""
    forwarded = request.headers.get("x-forwarded-for")
    if not forwarded or not _is_trusted_proxy(peer):
        return peer
    for hop in reversed([h.strip() for h in forwarded.split(",")]):
        if not hop:
            continue
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed header: do not guess
        if not _is_trusted_proxy(hop):
            return hop
    return peer


def is_internal_address(address: str) -> bool:
    """Private (RFC 1918 / ULA) or loopback: a caller that can only be inside the network."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def parse_scan_target(spec: str, max_hosts: int, allow_public: bool = False) -> Tuple[List[str], str]:
    """Turns "10.0.0.0/24", "10.0.0.5-10.0.0.40" or "10.0.0.5-40" into the list of addresses to probe.

    The size is worked out from the numbers before any list is built, so a /8 is refused instead of
    exhausting memory. Only addresses inside the private ranges are accepted unless allow_public is set,
    and loopback, link-local (cloud metadata lives there), multicast and reserved addresses never are."""
    spec = (spec or "").strip()
    if not spec or len(spec) > 100:
        raise ValueError("Enter a subnet like 192.168.1.0/24 or a range like 192.168.1.10-192.168.1.50.")

    if "-" in spec:
        a, b = (part.strip() for part in spec.split("-", 1))
        if "." not in b:
            b = a.rsplit(".", 1)[0] + "." + b
        first, last = ipaddress.IPv4Address(a), ipaddress.IPv4Address(b)
        start, end = sorted((int(first), int(last)))
        count = end - start + 1
        label = f"{ipaddress.IPv4Address(start)} - {ipaddress.IPv4Address(end)}"
        first_host, last_host = start, end
    else:
        net = ipaddress.IPv4Network(spec, strict=False)
        usable = max(net.num_addresses - 2, 1) if net.prefixlen < 31 else net.num_addresses
        count = usable
        label = str(net)
        first_host = int(net.network_address) + (1 if net.prefixlen < 31 else 0)
        last_host = first_host + count - 1

    if count > max_hosts:
        raise ValueError(f"{label} covers {count} addresses; the limit is {max_hosts}. Scan a smaller range "
                         f"(SCAN_MAX_HOSTS raises the limit).")

    hosts = [ipaddress.IPv4Address(i) for i in range(first_host, last_host + 1)]
    for ip in hosts:
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise ValueError(f"{ip} cannot be scanned (loopback, link-local, multicast or reserved address).")
        if not allow_public and not ip.is_private:
            raise ValueError(f"{ip} is not a private address; scanning outside your own network is disabled "
                             f"(SCAN_ALLOW_PUBLIC).")
    return [str(ip) for ip in hosts], label
