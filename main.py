import argparse
from scapy.all import ARP, Ether, srp, IP, TCP, sr1, ICMP
# from prettytable import PrettyTable
import datetime
import pytz
import requests
import json
import os

def signature():
    sig = r"""
    _   _  _____ _____   _____ _____   ___   _   _  _   _  ___________ 
    | \ | ||  ___|_   _| /  ___/  __ \ / _ \ | \ | || \ | ||  ___| ___ \
    |  \| || |__   | |   \ `--.| /  \// /_\ \|  \| ||  \| || |__ | |_/ /
    | . ` ||  __|  | |    `--. \ |    |  _  || . ` || . ` ||  __||    / 
    | |\  || |___  | |   /\__/ / \__/\| | | || |\  || |\  || |___| |\ \ 
    \_| \_/\____/  \_/   \____/ \____/\_| |_/\_| \_/\_| \_/\____/\_| \_|
                                                                    
                                                                    
    """
    print(sig)

# Host Discovery
def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    broadcast = ether/arp

    print(f"Scanning {ip}...")
    ans, _ = srp(broadcast, timeout=3, verbose=0)
    clients = []
    for _, received in ans:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    print("Available devices in the network:")
    for client in clients:
        print(f"IP: {client['ip']}\tMAC: {client['mac']}")
    log(clients)

# Port Scanning
def port_scan(target_ip, start_port, end_port):
    port_names = {
        20: "FTP Data Transfer",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP",
        # Add more ports and their names as needed
    }

    print(f"Scanning port {start_port} to {end_port} on {target_ip}")
    for port in range(start_port, end_port + 1):
        pkt = IP(dst=target_ip)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=1, verbose=0)
        if response is None:
            print(f"Port {port} is closed")
        elif response.haslayer(TCP):
            if response[TCP].flags == 18: # SYN-ACK
                port_name = port_names.get(port, "Unknown Service")
                print(f"Port {port} is open ({port_name})")
            else:
                print(f"Port {port} is closed")
        else:
            print(f"Port {port}: Unknown response")

# OS Detection
def detect_os(ip):
    try:
        # Send ICMP Echo Request
        icmp_packet = IP(dst=ip)/ICMP()
        response = sr1(icmp_packet, timeout=2, verbose=False)

        if response:
            ttl = response.ttl
            if ttl <= 64:
                os_guess = "Linux/Unix (TTL ~64)"
            elif ttl <= 128:
                os_guess = "Windows (TTL ~128)"
            elif ttl <= 255:
                os_guess = "Cisco/Networking Device (TTL ~255)"
            else:
                os_guess = "Unknown OS"
            print(f"[+] Detected OS: {os_guess} (TTL={ttl})")
        else:
            print("[-] No response to ICMP ping. Target might be down or blocking ICMP.")
        
        # TCP SYN Packet
        tcp_packet = IP(dst=ip)/TCP(dport=80, flags="S")
        tcp_response = sr1(tcp_packet, timeout=2, verbose=False)

        if tcp_response:
            window_size = tcp_response[TCP].window
            print(f"[+] TCP Window Size: {window_size}")
        else:
            print("[-] No response to TCP SYN packet.")
    except Exception as e:
        print(f"[!] Error: {e}")

# Logging
def log(data):
    try:
        log_entry = {
            'timestamp': datetime.datetime.now(pytz.timezone('Asia/Kolkata')).isoformat(),
            'data': data
        }
        if not os.path.exists("log.json"):
            with open("log.json", "w") as f:
                json.dump([log_entry], f, indent=4)
        else:
            with open("log.json", "r+") as f:
                logs = json.load(f)
                logs.append(log_entry)
                f.seek(0)
                json.dump(logs, f, indent=4)
    except Exception as e:
        print(f"Error: {e}")

# Vendor Lookup
def get_vendor_by_mac(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url)
        
        if response.status_code == 200:
            return f"Vendor: {response.text}"
        else:
            return "Not Found"
    except Exception as e:
        return f"Error: {e}"

def main():
    signature()
    parser = argparse.ArgumentParser(prog="NetworkScanner", description="Network Scanner Tool", epilog="Happy Hacking!")
    parser.add_argument("-t", "--target", dest="target", help="Target IP address")
    parser.add_argument("-s", "--scan", dest="scan", help="Scan for devices in the network (e.g., 192.168.1.0/24)")
    parser.add_argument("-p", "--ports", dest="ports", help="Port range to scan (e.g., 1-100)")
    parser.add_argument("-o", "--os", dest="os", action="store_true", help="Detect OS using scanning techniques")
    parser.add_argument("-l", "--local", dest="local", action="store_true", help="Get Local IP Address")
    parser.add_argument("-V", "--vendor", dest="vendor", help="Get vendor by MAC address")
    parser.add_argument("-v","--version", action="version", version="%(prog)s 1.0")
    args = parser.parse_args()

    if args.local:
        print("Available local networks:")
        networks = os.popen("hostname -I").read().split()
        for network in networks:
            print("*", network)
        exit(0)

    if args.vendor:
        print(get_vendor_by_mac(args.vendor))
        exit(0)
    
    if not args.scan and not args.ports and not args.os and not args.target:
        parser.error("Please specify an action: --target, --scan, --ports, --os")

    if args.scan:
        scan(args.scan)

    if args.ports:
        if not args.target:
            parser.error("Please specify a target IP address with --target")
        start_port, end_port = map(int, args.ports.split('-'))
        port_scan(args.target, start_port, end_port)
        
    if args.os:
        if not args.target:
            parser.error("Please specify a target IP address with --target")
        detect_os(args.target)

if __name__ == "__main__":
    main()



