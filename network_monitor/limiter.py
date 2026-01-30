
import threading
import time
from scapy.all import sniff, sendp, IP, Ether, ARP, UDP, TCP, DNS, DNSQR, DNSRR
from collections import defaultdict
import logging

class PacketLimiter:
    def __init__(self, interface, gateway_ip, gateway_mac):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.running = False
        self.limits = {} # {ip: {'up': kbps, 'down': kbps}}
        self.limits_lock = threading.Lock()
        
        # Token buckets: {ip: {'up': tokens, 'down': tokens, 'last_update': time}}
        self.buckets = defaultdict(lambda: {'up': 0, 'down': 0, 'last_update': time.time()})
        
        # Caches
        self.my_mac = self._get_my_mac()
        self.targets_mac = {} # {ip: mac}
        
        # Features
        self.intercept_all_ports = False # If False, only intercept specific ports
        self.monitor_ports = {80, 443, 53, 8080, 8443} # Common web/DNS ports
        self.dns_blacklist = set() # block_list for domains
        self.captive_portal_macs = set() # MACs that should be redirected
        self.dns_lock = threading.Lock()
        self.my_ip = self._get_my_ip_address()
        self.domain_rules = []

    def update_domain_rules(self, rules):
        with self.dns_lock:
            self.domain_rules = rules # List of dicts

        
    def _get_my_mac(self):
        from scapy.all import get_if_hwaddr
        try:
            return get_if_hwaddr(self.interface)
        except:
            return None

    def _get_my_ip_address(self):
        import socket
        try:
            # We need the IP on the active interface.
            # scapy get_if_addr is reliable
            from scapy.all import get_if_addr
            return get_if_addr(self.interface)
        except:
            return "127.0.0.1"

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._forward_loop, daemon=True)
        self.thread.start()
        print("[*] Packet Limiter Started (User-Space Forwarding)")

    def stop(self):
        self.running = False
        # thread will die as daemon or via loop check

    def set_limit(self, ip, upload_kbps, download_kbps):
        with self.limits_lock:
            if upload_kbps <= 0 and download_kbps <= 0:
                if ip in self.limits:
                    del self.limits[ip]
            else:
                self.limits[ip] = {'up': upload_kbps * 1024 * 8, 'down': download_kbps * 1024 * 8} # Convert KB/s to bps
                # Initialize bucket full burst
                self.buckets[ip]['up'] = self.limits[ip]['up']
                self.buckets[ip]['down'] = self.limits[ip]['down']
                self.buckets[ip]['last_update'] = time.time()
                
    def set_dns_blacklist(self, domains):
        with self.dns_lock:
            self.dns_blacklist = set(domains)
            print(f"[*] DNS Blacklist updated: {len(self.dns_blacklist)} domains")

    def set_captive_portal(self, mac, enable=True):
        with self.dns_lock:
            if enable:
                self.captive_portal_macs.add(mac)
            elif mac in self.captive_portal_macs:
                self.captive_portal_macs.remove(mac)

    def update_targets(self, devices):
        with self.limits_lock:
            for d in devices:
                self.targets_mac[d['ip']] = d['mac']

    def _forward_loop(self):
        # We sniff ALL packets on interface that are NOT for us (promiscuous mostly)
        # Filter: ip and (src or dst is in our targets)
        # Actually, simpler: sniff promiscuously, filter in python.
        sniff(
            iface=self.interface,
            prn=self._process_packet,
            store=0,
            stop_filter=lambda x: not self.running
        )

    def _process_packet(self, packet):
        try:
            if not self.running: return
            if not packet.haslayer(Ether): return
            eth = packet[Ether]
            
            # 1. Ignore packets sent BY us (loopback/outbound)
            if eth.src == self.my_mac: return
            # 2. Only process packets sent TO us (from Victim or Gateway)
            if eth.dst != self.my_mac: return
            if not packet.haslayer(IP): return

            ip_pkt = packet[IP]
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            print(f"[DEBUG] Packet seen: {src_ip} -> {dst_ip}") # TRACE ALL
            
            # Check if this packet is from a known target?
            # if src_ip in self.targets_mac:
            #     print(f"[DEBUG] Target Packet: {src_ip} -> {dst_ip}")
            
            # DNS BLACKHOLING CHECK (UDP/53)
            # Only check requests FROM targets (Upload)
            if packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNS):
                if src_ip in self.targets_mac:
                    print(f"[DNS SNIFF] Caught DNS Query from Target {src_ip}")
                    if self._handle_dns_spoofing(packet, src_ip, eth):
                        print(f"[DNS BLOCK] Spoofed response for {src_ip}")
                        return # Packet handled (spoofed response sent), stop forwarding
                    else:
                         print(f"[DNS ALLOW] Forwarding DNS query from {src_ip}")

            # CAPTIVE PORTAL ENFORCEMENT
            # If device is captive, BLOCK all traffic unless it is for US (Web UI).
            if src_ip in self.targets_mac:
                c_mac = self.targets_mac[src_ip]
                if c_mac in self.captive_portal_macs:
                    if dst_ip != self.my_ip and dst_ip != "255.255.255.255":
                        # Block internet access
                        # print(f"[Captive] Dropped packet from {src_ip} -> {dst_ip}")
                        return
            
            # SELECTIVE PORT FILTER
            # If enabled, pass-through (forward without limiting) packets on non-monitored ports
            if not self.intercept_all_ports:
                port = 0
                if packet.haslayer(TCP): port = packet[TCP].dport if src_ip in self.targets_mac else packet[TCP].sport
                elif packet.haslayer(UDP): port = packet[UDP].dport if src_ip in self.targets_mac else packet[UDP].sport
                
                # If port is NOT in our monitor list at all, we immediately forward it WITHOUT limiting?
                # Actually, user wants "Only intercept specific traffic... Stealth Benefit: Allows heavy traffic like local file transfers or gaming (UDP) to bypass the limiter entirely"
                # So yes, if it's not a monitored port, we forward but set check_limit=False
                if port > 0 and port not in self.monitor_ports:
                    # Forward but Bypass Limit
                    if src_ip in self.targets_mac:
                        self._forward_packet(packet, eth, ip_pkt, src_ip, dst_ip, check_limit=False, direction='up')
                        return
                    elif dst_ip in self.targets_mac:
                        self._forward_packet(packet, eth, ip_pkt, src_ip, dst_ip, check_limit=False, direction='down')
                        return

            # UPLOAD: Src is a Target -> Forward to Gateway
            if src_ip in self.targets_mac:
                # print(f"[Debug] Forwarding UPLOAD from {src_ip}")
                self._forward_packet(packet, eth, ip_pkt, src_ip, dst_ip, check_limit=True, direction='up')
                return

            # DOWNLOAD: Dst is Target (Coming from Gateway) -> Forward to Target
            if dst_ip in self.targets_mac:
                # print(f"[Debug] Forwarding DOWNLOAD to {dst_ip}")
                self._forward_packet(packet, eth, ip_pkt, src_ip, dst_ip, check_limit=True, direction='down')
                return
                
        except Exception as e:
            # print(f"[Limiter Error] {e}") # Debug only, avoid spam
            pass

    def _check_limit(self, ip, direction, bits):
        try:
            with self.limits_lock:
                if ip not in self.limits:
                    return True # No limit
                
                settings = self.limits[ip]
                limit_bps = settings[direction]
                
                if limit_bps <= 0:
                    return True
                    
                bucket = self.buckets[ip]
                now = time.time()
                elapsed = now - bucket['last_update']
                bucket['last_update'] = now
                
                # Refill bucket
                bucket[direction] += elapsed * limit_bps
                
                # Cap at burst size (1.0 seconds worth)
                if bucket[direction] > limit_bps:
                    bucket[direction] = limit_bps
                    
                # Consume
                if bucket[direction] >= bits:
                    bucket[direction] -= bits
                    return True
                else:
                    return False
        except:
            return True

    def _handle_dns_spoofing(self, packet, src_ip, eth):
        try:
            import fnmatch
            dns = packet[DNS]
            if dns.qr == 0: # Query
                qname = dns.qd.qname.decode('utf-8')
                check_name = qname[:-1] if qname.endswith('.') else qname
                
                # print(f"[DNS DEBUG] Query for {check_name} from {src_ip}") # Spammy, but uncomment if needed

                blocked = False
                redirect_ip = '0.0.0.0'
                
                # Determine target MAC to check rules
                target_mac_addr = self.targets_mac.get(src_ip)
                
                with self.dns_lock:
                    # 1. Captive Portal Check (Priority)
                    if target_mac_addr and target_mac_addr in self.captive_portal_macs:
                        print(f"[Captive Portal] Blocked DNS for {src_ip} ({target_mac_addr}): {check_name}")
                        blocked = True
                        redirect_ip = self.my_ip
                    else:
                        # 2. Domain Rules (Wildcard)
                        # Check specific rules first, then global ('ALL')
                        # self.domain_rules structure: list of dicts {mac, pattern, action, target}
                        for rule in self.domain_rules:
                            # Filter by MAC (Specific or Global)
                            if rule['target_mac'] == 'ALL' or rule['target_mac'] == target_mac_addr:
                                if fnmatch.fnmatch(check_name, rule['domain_pattern']):
                                    # Match found
                                    print(f"[Rules] Matched {check_name} against {rule['domain_pattern']}. Action: {rule['action']}")
                                    if rule['action'] == 'block':
                                        blocked = True
                                        redirect_ip = self.my_ip # Redirect to our block page
                                    elif rule['action'] == 'redirect':
                                        # TODO: Advanced DNS redirection requires dynamic resolution of target?
                                        # Or simple IP mapping. If target is an IP, easy. If domain, harder (need to resolve it ourselves).
                                        # For now, simplistic: if target is IP, use it. If not, ignore (or self to handle HTTP redirect).
                                        import socket
                                        try:
                                            # Try to see if target is an IP
                                            socket.inet_aton(rule['redirect_target'])
                                            redirect_ip = rule['redirect_target']
                                            blocked = True
                                        except:
                                            # It's a domain name. We can't put a CNAME in an A record easily without more parsing.
                                            # Easier approach: Redirect to US (self.my_ip), then HTTP 302 to target.
                                            redirect_ip = self.my_ip
                                            blocked = True
                                    break
                        
                        # 3. Simple Blacklist (Legacy)
                        if not blocked and check_name in self.dns_blacklist:
                            blocked = True
                        
                if blocked:
                    # Construct Block Response
                    # Swap Src/Dst
                    ip_resp = IP(src=packet[IP].dst, dst=packet[IP].src)
                    udp_resp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport)
                    dns_resp = DNS(
                        id=dns.id,
                        qr=1, # Response
                        aa=1, # Authoritative
                        rd=dns.rd, # Recursion Desired (copy)
                        ra=1, # Recursion Available
                        qd=dns.qd, # Query copy
                        an=DNSRR(rrname=qname, ttl=10, rdata=redirect_ip) # Answer
                    )
                    
                    spoof_pkt = Ether(src=self.my_mac, dst=eth.src) / ip_resp / udp_resp / dns_resp
                    sendp(spoof_pkt, iface=self.interface, verbose=0)
                    print(f"[Spoof] Sent fake DNS response for {check_name} -> {redirect_ip}")
                    return True
        except Exception as e:
            print(f"[DNS Error] {e}")
            pass
        return False

    def _forward_packet(self, packet, eth, ip_pkt, src_ip, dst_ip, check_limit=True, direction='up'):
        """Forward packet with optional limiting."""
        # Determine Destination MAC
        target_mac = None
        
        if direction == 'up':
            # To Gateway
            target_mac = self.gateway_mac
        else:
            # To Target
            target_mac = self.targets_mac.get(dst_ip)
            
        if not target_mac: return

        # Check Limit
        if check_limit:
            # Calculate bytes based on frame size * 8 bits
            if not self._check_limit(src_ip if direction=='up' else dst_ip, direction, len(packet) * 8):
                return # Drop packet (Limit Exceeded)

        # Rewrite Ether
        eth.src = self.my_mac
        eth.dst = target_mac
        
        # Fix Checksums (Critical for forwarding)
        del ip_pkt.chksum
        if packet.haslayer('UDP'): del packet['UDP'].chksum
        if packet.haslayer('TCP'): del packet['TCP'].chksum
        
        # Send
        sendp(packet, iface=self.interface, verbose=0)

