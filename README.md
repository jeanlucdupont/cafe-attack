This the scenario we want to explore

Laptop boots on corporate network
   Authenticates to a real Domain Controller
   Caches the DC info in memory (NL$ secrets, krbtgt ticket, DC IPs)
   Laptop goes to sleep

Cyber cafe
   DHCP-exhaust.py kills the current DHCP server.
   roguedhcp.py answers DHCP requests and point to our rogue DNS server

Laptop connects to the cyber cafe
   rogueDNS.py answers DNS request and redirect _ldap._tcp.dc._msdcs to our rogue DC
   rogueDC.py captures ntlm challenges if SMB signing is not enforced
   
Offline crack of captured ntlm challenges
   If client accepted ntlmV1 ==> rainbow attack with RainbowCrack or Hashcat 
   If not, John the Ripper.
