import sys
from scapy.all import rdpcap, ICMP, Raw

pcap = sys.argv[1] if len(sys.argv) > 1 else sys.exit("Uso: python3 mitm_sin_ranking.py cap.pcapng [0x0F]")
OFF  = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x0F  # offset del byte oculto (por defecto 0x0F)

# 1) Extraer (seq, byte) de todos los Echo Request con payload suficiente.
pairs = []
for p in rdpcap(pcap):
    if p.haslayer(ICMP) and p[ICMP].type == 8 and p.haslayer(Raw):
        data = bytes(p[Raw].load)
        if len(data) > OFF:
            pairs.append((p[ICMP].seq, data[OFF]))

# 2) Reconstruir texto cifrado ordenando por seq
pairs.sort(key=lambda t: t[0])
cipher = bytes(b for _, b in pairs).decode("utf-8", "ignore")
print(f"Palabra cifrada: {cipher}")

# 3) Mostrar los 26 desplazamientos de César (sin ranking)
def dec(s, k):
    r=[]
    for ch in s:
        if 'A'<=ch<='Z': r.append(chr((ord(ch)-65-k)%26+65))
        elif 'a'<=ch<='z': r.append(chr((ord(ch)-97-k)%26+97))
        else: r.append(ch)
    return "".join(r)

for k in range(26):
    print(f"{k:2d}  {dec(cipher, k)}")
