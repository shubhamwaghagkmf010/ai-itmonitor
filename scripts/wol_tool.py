#!/usr/bin/env python3
"""Send a Wake-on-LAN packet by hand, or ask a relay agent to send it. Replaces the old test_wol.py,
test_relay_listener.py and trigger_relay.py scripts, which had addresses hard-coded and (the listener) passed
text received from the network into a PowerShell command line. The agent's own relay does that job now.

    python scripts/wol_tool.py send AA:BB:CC:DD:EE:FF --to 192.168.1.255
    python scripts/wol_tool.py relay AA:BB:CC:DD:EE:FF --via 192.168.1.20

`send` broadcasts the packet from this machine (to 255.255.255.255 unless --to is given).
`relay` asks an agent on the target's subnet to broadcast it; the agent only obeys the server it reports to
(or addresses in its RELAY_ALLOWED_SOURCES), so run this from the server."""
import argparse
import os
import socket
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from agent.wol import RELAY_PORT, WOL_PORTS, broadcast_magic_packet, parse_mac


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    send = sub.add_parser("send", help="broadcast a magic packet from this machine")
    send.add_argument("mac")
    send.add_argument("--to", action="append", dest="targets", help="broadcast address (repeatable)")
    send.add_argument("--port", action="append", type=int, dest="ports", help="UDP port (default 7 and 9)")

    relay = sub.add_parser("relay", help="ask a relay agent to broadcast it")
    relay.add_argument("mac")
    relay.add_argument("--via", required=True, help="address of the relay agent")
    relay.add_argument("--port", type=int, default=RELAY_PORT)

    args = parser.parse_args(argv)
    mac = parse_mac(args.mac)
    if mac is None:
        print(f"'{args.mac}' is not a MAC address (expected AA:BB:CC:DD:EE:FF).", file=sys.stderr)
        return 2

    if args.command == "send":
        sent = broadcast_magic_packet(mac, args.targets or ["255.255.255.255"], tuple(args.ports or WOL_PORTS))
        print(f"Sent {sent} datagram(s) for {mac}.")
        return 0 if sent else 1

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(mac.encode("ascii"), (args.via, args.port))
    print(f"Asked the relay at {args.via}:{args.port} to wake {mac}. (UDP gives no reply; check the machine.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
