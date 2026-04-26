from scapy.all import *
from scapy.layers.inet import *
from datetime import datetime
import time


tcp_count = 0
udp_count = 0
icmp_count = 0
total_count = 0
newfile_info = []

def main():
    global newfile_info
    packet_count = int(input("Enter how many packets you want to read: "))
    sniff(prn= packet_analysis, count=packet_count)

    newfile_info.append("TCP: " + str(tcp_count))
    newfile_info.append("UDP: " + str(udp_count))
    newfile_info.append("ICMP: " + str(icmp_count))
    newfile_info.append("Total: " + str(tcp_count + udp_count + icmp_count))


    with open("result.txt", "w") as file:
        file.write((str("\n".join(newfile_info))))


def packet_analysis(packet):
    result  = datetime.fromtimestamp(packet.time)
    global tcp_count, udp_count, icmp_count
    global newfile_info
    if(packet.haslayer(IP)):
        if(packet. haslayer(TCP)):
            line = result.strftime("[%H:%M:%S] ") + "Packet " + str(tcp_count + 1) + " | " + "TCP " + packet[IP].src + ": " + str(packet[TCP].sport) + " -> " + packet[IP].dst + ": " + str(packet[TCP].dport)
            tcp_count+=1
        elif(packet. haslayer(UDP)):
            line = result.strftime("[%H:%M:%S] ") + " Packet " + str(udp_count + 1) + " | " + "UDP " + packet[IP].src + ": " + str(packet[UDP].sport) + " -> " + packet[IP].dst + ": " + str(packet[UDP].dport)
            udp_count+=1
        elif(packet.haslayer(ICMP)):
            line = result.strftime("[%H:%M:%S] ") + " Packet " + str(icmp_count + 1) + " | " + "ICMP " + packet[IP].src + " -> " + packet[IP].dst
            icmp_count+=1
        else:
            line = "Other IP Packet"

        newfile_info.append(line)

    print("")

if __name__ == "__main__":
    main()