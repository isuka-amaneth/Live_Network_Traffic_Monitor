from scapy.all import sniff, IP, TCP, UDP

def describe(pkt):
    if IP in pkt:
        src, dst = pkt[IP].src, pkt[IP].dst
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "other"
        print(f"{proto:5} {src:>15} -> {dst:<15} {len(pkt)} bytes")

print("Listening for 50 live packets... open a browser and load a page. (Ctrl+C to stop early)")
sniff(prn=describe, store=False, count=50)