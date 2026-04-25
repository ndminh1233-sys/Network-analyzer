from scapy.all import *
from scapy.layers.inet import *


count = 0
def main():
    packet_count = int(input("Enter how many packets you want to read: "))
    sniff(prn= packet_analysis, count=packet_count)

def packet_analysis(packet):
    global count
    if(packet.haslayer(IP)):
        count += 1
        if(packet. haslayer(TCP)):
            print("Packet " + str(count) + " | " + "TCP " + packet[IP].src + ": " + str(packet[TCP].sport) + " -> " + packet[IP].dst + ": " + str(packet[TCP].dport))
        elif(packet. haslayer(UDP)):
            print("Packet " + str(count) + " | " + "UDP " + packet[IP].src + ": " + str(packet[UDP].sport) + " -> " + packet[IP].dst + ": " + str(packet[UDP].dport))
        elif(packet.haslayer(ICMP)):
            print("Packet " + str(count) + " | " + "ICMP " + packet[IP].src + " -> " + packet[IP].dst)
        else:
            print("Other IP Packet")


if __name__ == "__main__":
    main()