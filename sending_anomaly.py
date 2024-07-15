from scapy.all import *

while True:
    # Define packet parameters (modify as per your anomaly criteria)
    packet = IP(dst="127.0.0.1") / UDP(dport=1111) / Raw(b"AnomalyPacket")

    # Send the packet
    send(packet)
