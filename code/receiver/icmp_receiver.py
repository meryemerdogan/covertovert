"""
This program is part of an ICMP packet communication system as the receiver side.
"""
from scapy.all import *

# Processes incoming ICMP packets
def recievePacket(packet):
    """
    Checks if the packet exists (with “packet”), contains an ICMP layer (with “packet.haslayer(ICMP)” ), has a TTL of 1 (with “packet.ttl == 1”),
    and has an ICMP type of 8 (with “packet[ICMP].type == 8” which means echo requests).
    """
    if packet and packet.haslayer(ICMP) and packet.ttl == 1 and packet[ICMP].type == 8:
        packet.show()  # Displays packet details


if __name__ == "__main__":
    # Waits for the packets when they arrive sent them to recievePacket(packet) and stops after receiving one.
    sniff(filter="icmp", prn=recievePacket, count=1)  
