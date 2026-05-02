from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from datetime import datetime
import argparse

ANOMALY_THRESHOLD = 10

QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 12: "PTR",
    15: "MX", 28: "AAAA", 33: "SRV", 255: "ANY"
}

QCLASS_MAP = {
    1: "IN", 3: "CH", 255: "ANY"
}

tcp_count = 0
udp_count = 0
icmp_count = 0
dns_count = 0
last_seen_ip = None
newfile_info = []
ip_count = {}
args = None

# ── Packet Handlers ───────────────────────────────────────
def tcp_filter(packet, result):
    global tcp_count
    line = result.strftime("[%H:%M:%S] ") + "Packet " + str(tcp_count + 1) + " | TCP " + packet[IP].src + ":" + str(packet[TCP].sport) + " -> " + packet[IP].dst + ":" + str(packet[TCP].dport)
    print(line)
    tcp_count += 1
    return line

def udp_filter(packet, result):
    global udp_count
    line = result.strftime("[%H:%M:%S] ") + "Packet " + str(udp_count + 1) + " | UDP " + packet[IP].src + ":" + str(packet[UDP].sport) + " -> " + packet[IP].dst + ":" + str(packet[UDP].dport)
    print(line)
    udp_count += 1
    return line

def icmp_filter(packet, result):
    global icmp_count
    line = result.strftime("[%H:%M:%S] ") + "Packet " + str(icmp_count + 1) + " | ICMP " + packet[IP].src + " -> " + packet[IP].dst
    print(line)
    icmp_count += 1
    return line

def dns_filter(packet, result):
    global dns_count
    qname = packet[DNS].qd.qname.decode().strip(".")
    qtype = QTYPE_MAP.get(packet[DNS].qd.qtype, "UNKNOWN")
    qclass = QCLASS_MAP.get(packet[DNS].qd.qclass, "UNKNOWN")
    line = result.strftime("[%H:%M:%S] ") + "Packet " + str(dns_count + 1) + " | DNS " + packet[IP].src + " -> " + qname + " | Type: " + qtype + " | Class: " + qclass
    print(line)
    dns_count += 1
    return line

# ── Core Analysis ─────────────────────────────────────────
def packet_analysis(packet):
    filter_val = args.filter.lower() if args.filter else None
    line = None
    result = datetime.fromtimestamp(packet.time)
    anomaly_detection(packet)

    if filter_val == "tcp":
        if packet.haslayer(IP) and packet.haslayer(TCP):
            line = tcp_filter(packet, result)
    elif filter_val == "udp":
        if packet.haslayer(IP) and packet.haslayer(UDP):
            line = udp_filter(packet, result)
    elif filter_val == "icmp":
        if packet.haslayer(IP) and packet.haslayer(ICMP):
            line = icmp_filter(packet, result)
    else:
        if packet.haslayer(IP):
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                line = dns_filter(packet, result)
            elif packet.haslayer(TCP):
                line = tcp_filter(packet, result)
            elif packet.haslayer(UDP):
                line = udp_filter(packet, result)
            elif packet.haslayer(ICMP):
                line = icmp_filter(packet, result)
            else:
                line = "Other IP Packet"
                print(line)

    if line:
        newfile_info.append(line)
    print("")

# ── Anomaly Detection ─────────────────────────────────────
def anomaly_detection(packet):
    global last_seen_ip
    if not packet.haslayer(IP):
        return

    src_ip = packet[IP].src

    if src_ip == last_seen_ip:
        ip_count[src_ip] += 1
    else:
        if last_seen_ip is not None:
            ip_count[last_seen_ip] = 0
        ip_count[src_ip] = 1
        last_seen_ip = src_ip

    if ip_count[src_ip] >= ANOMALY_THRESHOLD:
        alert = f"[⚠️  ALERT] {src_ip} appeared {ANOMALY_THRESHOLD} times consecutively — possible scan!"
        print(alert)
        newfile_info.append(alert)

# ── Summary & Output ──────────────────────────────────────
def user_inter():
    newfile_info.append("TCP: " + str(tcp_count))
    newfile_info.append("UDP: " + str(udp_count))
    newfile_info.append("ICMP: " + str(icmp_count))
    newfile_info.append("DNS: " + str(dns_count))
    newfile_info.append("Total: " + str(tcp_count + udp_count + icmp_count + dns_count))

# ── Entry Point ───────────────────────────────────────────
def main():
    global args
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--count", type=int, required=True, help="Number of packets")
    parser.add_argument("-o", "--output", type=str, default="result.txt", help="Output file name")
    parser.add_argument("-f", "--filter", type=str, help="Filter your traffic")
    args = parser.parse_args()

    sniff(filter=args.filter, prn=packet_analysis, count=args.count)

    print("--- Summary ---")
    print("TCP: " + str(tcp_count))
    print("UDP: " + str(udp_count))
    print("ICMP: " + str(icmp_count))
    print("DNS: " + str(dns_count))
    print("Total: " + str(tcp_count + udp_count + icmp_count + dns_count))

    user = input('Do you want to save the result to a file? ').lower().startswith('y')
    if user:
        user_inter()
        with open(args.output, "w") as file:
            file.write("\n".join(newfile_info))

if __name__ == "__main__":
    main()