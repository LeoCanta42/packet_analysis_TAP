from scapy.all import *

while True:
    # Define packet parameters
    packet = IP(dst="127.0.0.1") / UDP(sport=444,dport=1111) / Raw(b"AnomalyPacket")

    # Send the packet
    send(packet)
