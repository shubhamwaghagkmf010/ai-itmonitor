import socket

relay_ip = "192.0.2.10"  # set to your relay IP
target_mac = "70:5A:0F:4C:47:D5"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(target_mac.encode("utf-8"), (relay_ip, 9999))
print(f"[+] Wake trigger dispatched to Relay Host {relay_ip}:9999 for Target MAC {target_mac}")
