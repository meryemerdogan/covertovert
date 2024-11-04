"""
This program is part of an ICMP packet communication system as the sender side.
This sender constructs and transmits an ICMP packet to a specified destination.
"""
from scapy.all import *


def sendPacket():
    #Sender for packets
 

    """
    Defines the destination IP address
    """
    ip = 'receiver'  # docker automatically replaces ‘receiver’ with receivers actual ip address

    # Makes the ICMP packet with IP (destination ip and time to live value), ICMP (Echo Request), and payload ("deneme")
    packet = IP(dst = ip, ttl=1) / ICMP() / "deneme"
    send(packet)


if __name__ == "__main__":
    sendPacket()   # Calls the sendPacket function to send the ICMP packet
