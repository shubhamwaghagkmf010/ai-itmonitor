import socket

# Target Configuration
TARGET_MAC = "70:5A:0F:4C:47:D5"
TARGETS = ["192.0.2.255", "192.0.2.11", "255.255.255.255"]
PORTS = [9, 7]

clean_mac = TARGET_MAC.replace(":", "").replace("-", "").strip()
mac_bytes = bytes.fromhex(clean_mac)
magic_packet = (b'\xff' * 6) + (mac_bytes * 16)

print(f"[*] Dispatching Magic Packet for MAC: {TARGET_MAC}")
print(f"[*] Packet Size: {len(magic_packet)} Bytes")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for target in TARGETS:
        for port in PORTS:
            try:
                sent = sock.sendto(magic_packet, (target, port))
                print(f"[+] Successfully sent {sent} bytes to {target}:{port}")
            except Exception as e:
                print(f"[-] Error sending to {target}:{port} -> {e}")

print("[✓] All Magic Packets Dispatched!")
