from scapy.all import *
from scapy.layers.inet import *


tcp_count = 0
udp_count = 0
icmp_count = 0
total_count = 0

def main():
    packet_count = int(input("Enter how many packets you want to read: "))
    sniff(prn= packet_analysis, count=packet_count)

    print("Summary")
    print("TCP: " + str(tcp_count))
    print("UDP: " + str(udp_count))
    print("ICMP: " + str(icmp_count))
    print("Total: " + str(tcp_count + udp_count + icmp_count))

def packet_analysis(packet):
    global tcp_count, udp_count, icmp_count
    if(packet.haslayer(IP)):
        if(packet. haslayer(TCP)):
            print("Packet " + str(tcp_count + 1) + " | " + "TCP " + packet[IP].src + ": " + str(packet[TCP].sport) + " -> " + packet[IP].dst + ": " + str(packet[TCP].dport))
            tcp_count+=1
        elif(packet. haslayer(UDP)):
            print("Packet " + str(udp_count + 1) + " | " + "UDP " + packet[IP].src + ": " + str(packet[UDP].sport) + " -> " + packet[IP].dst + ": " + str(packet[UDP].dport))
            udp_count+=1
        elif(packet.haslayer(ICMP)):
            print("Packet " + str(icmp_count + 1) + " | " + "ICMP " + packet[IP].src + " -> " + packet[IP].dst)
            icmp_count+=1
        else:
            print("Other IP Packet\n")


if __name__ == "__main__":
    main()