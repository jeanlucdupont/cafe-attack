Scenario Overview
This lab explores how a hybrid/domain-joined laptop can be tricked into sending NTLM credentials to a rogue Domain Controller when SMB signing is not enforced.

Corporate Network (Initial State)
   Laptop boots on the corporate network.
   Laptop goes to sleep.
   
Cyber Café (Attack Phase)
   DHCP-exhaust.py : consumes all available leases from the café’s DHCP server.
   roguedhcp.py : responds to DHCP requests, pointing victims to our rogue DNS server.
   Rogue DNS : rogueDNS.py intercepts DNS lookups and Redirects _ldap._tcp.dc._msdcs.<domain> to our rogue DC IP.
   Rogue DC : rogueDC.py pretends to be a Domain Controller and captures NTLM authentication attempts if SMB signing is not enforced.

Offline Cracking of Captured NTLM
   If NTLMv1: Use rainbow table attack with RainbowCrack or Hashcat.
   If NTLMv2: Use John the Ripper or Hashcat with targeted wordlists/masks.

Disclaimer
This project is for educational and lab use only. (It does not at this stage anyway)
Do not run these tools on any network without explicit authorization. Unauthorized use can cause denial of service and legal consequences.
