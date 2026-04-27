from scapy.all import *
from scapy.layers.inet import *
from datetime import datetime
import argparse


tcp_count = 0
udp_count = 0
icmp_count = 0
total_count = 0
last_seen_ip = None
newfile_info = []
ANOMALY_THRESHOLD = 10
ip_count = {}

def main():
    global newfile_info
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count" , type=int, required=True, help="Number of packet")
    parser.add_argument("-o", "--output", type=str, default="result.txt", help="Output file name")
    args = parser.parse_args()

    sniff(prn= packet_analysis, count=args.count)

    print("TCP: " + str(tcp_count))
    print("UDP: " + str(udp_count))
    print("ICMP: " + str(icmp_count))
    print("Total: " + str(tcp_count + udp_count + icmp_count))

    user = input('Do you want to print the result into your file? ').lower().startswith('y')

    if(user == True):
        user_inter()
        with open(args.output, "w") as file:
            file.write("\n".join(newfile_info))

def packet_analysis(packet):
    result  = datetime.fromtimestamp(packet.time)
    global tcp_count, udp_count, icmp_count
    global newfile_info
    anomaly_detection(packet)
    if(packet.haslayer(IP)):
        if(packet. haslayer(TCP)):
            
            line = result.strftime("[%H:%M:%S] ") + "Packet " + str(tcp_count + 1) + " | " + "TCP " + packet[IP].src + ": " + str(packet[TCP].sport) + " -> " + packet[IP].dst + ": " + str(packet[TCP].dport)
            print(line)
            tcp_count+=1
        elif(packet. haslayer(UDP)):
            line = result.strftime("[%H:%M:%S] ") + " Packet " + str(udp_count + 1) + " | " + "UDP " + packet[IP].src + ": " + str(packet[UDP].sport) + " -> " + packet[IP].dst + ": " + str(packet[UDP].dport)
            print(line)
            udp_count+=1
        elif(packet.haslayer(ICMP)):
            line = result.strftime("[%H:%M:%S] ") + " Packet " + str(icmp_count + 1) + " | " + "ICMP " + packet[IP].src + " -> " + packet[IP].dst
            icmp_count+=1
            print(line)
        else:
            line = "Other IP Packet"
            print(line)

        newfile_info.append(line)

    print("")

def user_inter():
    newfile_info.append("TCP: " + str(tcp_count))
    newfile_info.append("UDP: " + str(udp_count))
    newfile_info.append("ICMP: " + str(icmp_count))
    newfile_info.append("Total: " + str(tcp_count + udp_count + icmp_count))
    
def anomaly_detection(packet):
    global last_seen_ip
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip == last_seen_ip:
        ip_count[src_ip] += 1 
    else:
        ip_count[src_ip] = 1
        last_seen_ip = src_ip

    if ip_count[src_ip] == ANOMALY_THRESHOLD:
        alert = f"[⚠️  ALERT] {src_ip} appeared {ANOMALY_THRESHOLD} times consecutively — possible scan!"
        print(alert)
        newfile_info.append(alert)




if __name__ == "__main__":
    main()