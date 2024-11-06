#may need to download scapy
from scapy.all import Ether, ARP, srp
import socket

#used to find the MAC address of every device connected to the network

if __name__ == "__main__":
    broadcast = "FF:FF:FF:FF:FF:FF" #  broadcast address. universal broadcast address. when a packet is sent to this address it is sent all over the network
    ether_layer = Ether(dst = broadcast) #creates ethernet layer with destination as broadcast address
    ip_range = input("Give the IP range to scan (ex: 192.168.4.1/24): ") # range of Ip. /24 specifies the range if Ip's from 1-254
    arp_layer = ARP(pdst = ip_range) # creates ARP layer with ip_range as target addresses

    packet = ether_layer / arp_layer # combvines ethernet layer and arp layers

    ans, unans = srp(packet, iface = "en0", timeout=2) # sends and recieve packet at layer 2
    # contains packets that got a resposne and thos that did not get a response

    for snd, rcv in ans:
        ip = rcv[ARP].psrc
        mac = rcv[Ether].src
        print("IP= ", ip, "MAC= ", mac)
# snd is the packet sent and rcv is the packet recieved, 
# rcv[ARP].psrc extracts the soruce address form the ARP response
# rcv[Ether].src extracts the source MAC address from the ethernet frame