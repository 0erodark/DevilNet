import threading
import time
import struct
from collections import defaultdict
from typing import Dict, Set
from scapy.all import sniff, IP, TCP, UDP, BOOTP, DHCP

class BandwidthMonitor:
    def __init__(self, interface: str):
        self.interface = interface
        self.running = False
        self.lock = threading.Lock()
        
        # Cumulative counters
        self.bytes_sent = defaultdict(int)
        self.bytes_recv = defaultdict(int)
        
        # Rate calculation (bytes per second)
        self.upload_speed = defaultdict(int)
        self.download_speed = defaultdict(int)
        
        # Device Intelligence
        self.device_os = defaultdict(lambda: "Unknown")
        self.os_confidence = defaultdict(int) # 0-100 score
        self.visited_domains = defaultdict(list)
        self.detected_apps = defaultdict(set) # {ip: {app_name, ...}}
        
        # Heuristics state
        self.flow_trackers = defaultdict(lambda: {'pkts': 0, 'size': 0, 'start': 0})
        
        self.last_check_time = time.time()
        self.last_bytes_sent = defaultdict(int)
        self.last_bytes_recv = defaultdict(int)

        self.last_packet_ts = 0

    def start(self):
        self.running = True
        # Sniff thread
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        
        # Rate calculator thread
        self.calc_thread = threading.Thread(target=self._calc_loop, daemon=True)
        self.calc_thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'sniff_thread'):
            pass

    def _sniff_loop(self):
        # Sniff packets without simple store=0 to avoid memory leak
        sniff(iface=self.interface, prn=self._process_packet, store=0)

    def _process_packet(self, packet):
        if not self.running:
            return
        try:
            if IP in packet:
                ip_layer = packet[IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                length = len(packet)
                
                # Enhanced OS Fingerprinting
                # 1. DHCP Analysis (Highest Confidence)
                if packet.haslayer(UDP) and packet[UDP].sport == 68 and packet[UDP].dport == 67:
                    self._analyze_dhcp(src_ip, packet)
                    
                # 2. TCP SYN Fingerprinting (High Confidence)
                elif packet.haslayer(TCP):
                    tcp = packet[TCP]
                    if tcp.flags.S: # SYN
                         self._analyze_tcp_syn(src_ip, ip_layer, tcp)

                # 3. Passive TTL (Fallback)
                if self.device_os[src_ip] == "Unknown":
                    self._detect_os_ttl(src_ip, ip_layer.ttl)

                # SNI Sniffing (TLS Client Hello)
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    payload = bytes(tcp_layer.payload)
                    if tcp_layer.dport == 443 and payload:
                        try:
                            self._extract_sni(src_ip, payload)
                        except:
                            pass
                            
                # App Heuristics (UDP/TCP patterns)
                self._detect_app(src_ip, packet, length)

                with self.lock:
                    self.bytes_sent[src_ip] += length
                    self.bytes_recv[dst_ip] += length
                    self.last_packet_ts = time.time()
        except:
            pass

    def _analyze_dhcp(self, ip, packet):
        try:
            if not packet.haslayer(DHCP): return
            
            # Extract Options
            options = packet[DHCP].options
            # Look for Option 12 (Host Name) or 55 (Param Request List) or 60 (Vendor Class)
            # Option format in scapy: list of (name, value) or (name, value) tuples
            
            fingerprint = "Unknown"
            
            # Scan options
            vendor_class = None
            param_list = None
            
            for opt in options:
                if opt == 'end': break
                if isinstance(opt, tuple):
                    name, val = opt
                    if name == 'vendor_class_id':
                        vendor_class = val.decode('utf-8', errors='ignore')
                    elif name == 'param_req_list':
                        param_list = val # List of ints
            
            # Heuristics
            if vendor_class:
                v = vendor_class.lower()
                if 'android' in v: fingerprint = "Android"
                elif 'msft' in v or 'windows' in v: fingerprint = "Windows"
                elif 'apple' in v or 'mac' in v: fingerprint = "Apple Device"
                elif 'ubuntu' in v or 'linux' in v: fingerprint = "Linux"
                
            # If no clear vendor, check param order (Advanced)
            # For now, let's stick to Vendor Class which is very strong if present.
            
            if fingerprint != "Unknown":
                with self.lock:
                    self.device_os[ip] = fingerprint
                    self.os_confidence[ip] = 90 # High confidence
        except:
            pass

    def _analyze_tcp_syn(self, ip, ip_pkt, tcp_pkt):
        # Don't overwrite high confidence (DHCP) guesses with TCP
        if self.os_confidence[ip] > 80: return
        
        ttl = ip_pkt.ttl
        window = tcp_pkt.window
        
        guess = "Unknown"
        
        # 1. Windows: TTL ~128
        if ttl > 64 and ttl <= 128:
            guess = "Windows"
            
        # 2. Apple (iOS/MacOS): TTL <= 64, Window often 65535
        elif ttl <= 64 and window == 65535:
            # Can we differentiate iOS vs Mac?
            # Often hard without User-Agent.
            guess = "iOS / MacOS"
            
        # 3. Android / Linux: TTL <= 64, Window varies
        elif ttl <= 64:
            # Check for generic Linux behavior
            if window in [5840, 29200, 5720]:
                guess = "Linux"
            else:
                 # High probability of Android if not 65535 and regular size
                 # This is fuzzy.
                 guess = "Android / Linux"
                 
        if guess != "Unknown":
            with self.lock:
                self.device_os[ip] = guess
                self.os_confidence[ip] = 50 # Medium confidence

    def _detect_os_ttl(self, ip, ttl):
        # Don't overwrite if we have any better guess
        if self.os_confidence[ip] >= 20: return
        
        likely_os = "Unknown"
        if ttl <= 64:
            likely_os = "Li/Mac/And (Generic)"
        elif ttl <= 128:
            likely_os = "Windows (Generic)"
        elif ttl <= 255:
            likely_os = "Network Device"
            
        if likely_os != "Unknown":
            with self.lock:
                self.device_os[ip] = likely_os

    def _detect_app(self, ip, packet, length):
        """Heuristic analysis to identify applications like Zoom/Netflix."""
        try:
            detected = None
            
            # Zoom: High frequency UDP on specific ranges or 8801
            if packet.haslayer(UDP):
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if 8801 in [sport, dport]:
                    detected = "Zoom"
                elif 3478 in [sport, dport]: # STUN/TURN (Common in VoIP)
                    # Weak signal, check payload size?
                    pass
                    
            # Netflix/Youtube (Fast.com): High bandwidth HTTPS on specific ASNs (hard)
            # Simplistic: checking specific SNI if available (already handled in SNI) but we can tag it.
            
            # Use SNI history to tag app if not yet tagged
            if not detected:
                domains = self.visited_domains.get(ip, [])
                if domains:
                    last_domain = domains[-1].get('domain', '')
                    if 'netflix.com' in last_domain or 'nflxvideo.net' in last_domain:
                        detected = "Netflix"
                    elif 'youtube.com' in last_domain or 'googlevideo.com' in last_domain:
                        detected = "YouTube"
                    elif 'zoom.us' in last_domain:
                        detected = "Zoom"
                    elif 'spotify.com' in last_domain:
                        detected = "Spotify"
            
            if detected:
                with self.lock:
                    self.detected_apps[ip].add(detected)
        except:
            pass

    def _extract_sni(self, ip, payload):
        # Basic TLS Client Hello parsing to find SNI
        # Content Type: 22 (Handshake)
        # Version: 0301 or 0303 etc
        # Length: 2 bytes
        # Handshake Type: 01 (Client Hello)
        
        if len(payload) < 5: return
        
        # 0x16 = Handshake
        if payload[0] != 0x16: return
        
        # Skip Record Header (5 bytes)
        handshake_data = payload[5:]
        if len(handshake_data) < 1: return
        
        # 0x01 = Client Hello
        if handshake_data[0] != 0x01: return
        
        # Helper to read bytes safely
        idx = 1 # Skip Handshake Type
        
        # Skip Length (3 bytes)
        idx += 3
        # Skip Version (2 bytes)
        idx += 2
        # Skip Random (32 bytes)
        idx += 32
        
        if len(handshake_data) <= idx: return
        
        # Session ID Length (1 byte)
        sid_len = handshake_data[idx]
        idx += 1 + sid_len
        
        if len(handshake_data) <= idx: return

        # Cipher Suites Length (2 bytes)
        ciphers_len = int.from_bytes(handshake_data[idx:idx+2], 'big')
        idx += 2 + ciphers_len
        
        if len(handshake_data) <= idx: return

        # Compression Methods Length (1 byte)
        comp_len = handshake_data[idx]
        idx += 1 + comp_len
        
        if len(handshake_data) <= idx: return

        # Extensions Length (2 bytes)
        if len(handshake_data) < idx + 2: return
        ext_len = int.from_bytes(handshake_data[idx:idx+2], 'big')
        idx += 2
        
        end_idx = idx + ext_len
        while idx < end_idx:
            if len(handshake_data) < idx + 4: break
            
            ext_type = int.from_bytes(handshake_data[idx:idx+2], 'big')
            ext_data_len = int.from_bytes(handshake_data[idx+2:idx+4], 'big')
            
            # SNI Extension Type is 0x0000
            if ext_type == 0x0000:
                list_len = int.from_bytes(handshake_data[idx+4:idx+6], 'big')
                if list_len > 0:
                    name_type = handshake_data[idx+6]
                    if name_type == 0: # Host Name
                        name_len = int.from_bytes(handshake_data[idx+7:idx+9], 'big')
                        domain = handshake_data[idx+9:idx+9+name_len].decode('utf-8', errors='ignore')
                        
                        with self.lock:
                            # Use a list of dicts for history: [{'domain': 'foo.com', 'time': 12345}]
                            # Check if recent to avoid spam
                            history = self.visited_domains[ip]
                            now = time.time()
                            
                            # Simple dedup: don't add if same domain seen in last 2 seconds
                            if not history or history[-1]['domain'] != domain or (now - history[-1]['time'] > 2):
                                history.append({'domain': domain, 'time': now})
                                
                                # Keep last 100
                                if len(history) > 100:
                                    history.pop(0)
                return

            idx += 4 + ext_data_len

    def _calc_loop(self):
        while self.running:
            time.sleep(0.1) # Faster updates for 100ms refresh rate
            now = time.time()
            with self.lock:
                time_diff = now - self.last_check_time
                if time_diff <= 0:
                    continue
                
                # Calculate Upload Speed (Sent)
                for ip, total_bytes in self.bytes_sent.items():
                    delta = total_bytes - self.last_bytes_sent[ip]
                    self.upload_speed[ip] = int(delta / time_diff)
                    self.last_bytes_sent[ip] = total_bytes
                
                # Calculate Download Speed (Recv)
                for ip, total_bytes in self.bytes_recv.items():
                    delta = total_bytes - self.last_bytes_recv[ip]
                    self.download_speed[ip] = int(delta / time_diff)
                    self.last_bytes_recv[ip] = total_bytes
                
                self.last_check_time = now

    def get_speeds(self) -> Dict[str, Dict[str, int]]:
        with self.lock:
            # Aggregate all IPs we know about
            all_ips = set(self.upload_speed.keys()) | set(self.download_speed.keys()) | set(self.device_os.keys())
            results = {}
            for ip in all_ips:
                results[ip] = {
                    "up": self.upload_speed.get(ip, 0),
                    "down": self.download_speed.get(ip, 0),
                    "total_up": self.bytes_sent.get(ip, 0),
                    "total_down": self.bytes_recv.get(ip, 0),
                    "os": self.device_os.get(ip, "Unknown"),
                    "domains": list(self.visited_domains.get(ip, [])),
                    "apps": list(self.detected_apps.get(ip, []))
                }
            return results, self.last_packet_ts
