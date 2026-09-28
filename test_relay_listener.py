# Machine B (192.0.2.10) par run karein
import socket
import subprocess

RELAY_PORT = 9999

def trigger_powershell_wol(mac_str):
    ps_cmd = (
        f'$mac="{mac_str}";'
        f'$m=($mac -split \'[:-]\'|%{{[Convert]::ToByte($_,16)}});'
        f'$p=[byte[]]((0..5|%{{255}})+(1..16|%{{$m}}));'
        f'$c=New-Object Net.Sockets.UdpClient;'
        f'$c.EnableBroadcast=$true;'
        f'$c.Send($p,$p.Length,"255.255.255.255",9);'
        f'$c.Send($p,$p.Length,"192.0.2.255",9);'
        f'$c.Close();'
        f'Write-Host "WoL sent via PowerShell to $mac"'
    )
    res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True)
    print(f"[⚡] PowerShell Dispatch Output: {res.stdout.strip() or res.stderr.strip()}")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", RELAY_PORT))
print(f"[*] Native PowerShell WOL Relay listening on Port {RELAY_PORT}...")

while True:
    data, addr = sock.recvfrom(1024)
    target_mac = data.decode('utf-8').strip()
    print(f"\n[+] Received Wake Request from {addr[0]} for MAC: {target_mac}")
    trigger_powershell_wol(target_mac)
