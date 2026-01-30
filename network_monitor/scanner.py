import threading
import time
import socket
from typing import List, Dict, Generator
import requests
import re
from scapy.all import ARP, Ether, srp, srp1, conf, IP, UDP, TCP, sr1, sniff, AsyncSniffer
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.netbios import NBNSQueryRequest
from mac_vendor_lookup import MacLookup

class DeviceScanner:
    def __init__(self, interface: str, subnet: str):
        self.interface = interface
        self.subnet = subnet
        self.devices: Dict[str, Dict] = {} # Key: MAC address
        self.lock = threading.Lock()
        self.running = False
        try:
            self.mac_lookup = MacLookup()
            # Initialize mac database update in a separate thread/async if needed, 
            # or just rely on cached/local. For now, we'll try to update once.
            # self.mac_lookup.update_vendors() # Warning: This requires internet and might block
            pass 
        except Exception:
            self.mac_lookup = None

    def restore_devices(self, db_devices: List[Dict]):
        """Populate initial device list from database to speed up targeting on restart."""
        with self.lock:
            for d in db_devices:
                mac = d.get('mac')
                ip = d.get('ip')
                if mac and ip:
                     # Calculate last seen based on DB?
                     # If old, maybe don't trust the IP, but good for initial target list.
                     # Spoofer will fail gracefully if IP is gone.
                     self.devices[mac] = {
                         "ip": ip,
                         "mac": mac,
                         "vendor": d.get("vendor", "Unknown"),
                         "hostname": d.get("hostname", "Unknown"),
                         "possible_names": [],
                         "manual_hostname": True if d.get("hostname") else False,
                         "last_seen": d.get("last_seen", time.time())
                     }

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._scan_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=1.0)

    def _scan_loop(self):
        # Initial vendor update if possible
        try:
            self.mac_lookup.update_vendors() 
        except:
            pass

        while self.running:
            self._scan()
            time.sleep(10)  # Scan every 10 seconds

    def _scan(self):
        # Create ARP request
        arp = ARP(pdst=self.subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp

        try:
            # Send packet and capture response
            # timeout=2, verbose=0
            result = srp(packet, timeout=2, verbose=0, iface=self.interface)[0]

            # Process results OUTSIDE the lock to avoid freezing the UI
            temp_updates = []
            
            for sent, received in result:
                mac = received.hwsrc
                ip = received.psrc
                
                # Resolve details (collect all)
                # Check cache first
                hostname = "Unknown"
                possible_names = []
                
                names = self._get_all_hostnames(ip)
                possible_names = names
                if names:
                    hostname = names[0] # Default to first found
                
                # Check previous cache to preserve manual overrides or better names
                with self.lock:
                    cached = self.devices.get(mac)
                    if cached and cached.get("hostname", "Unknown") != "Unknown":
                        # If we failed this time but had one, keep it?
                        # Or if we found a new one, update it.
                        if hostname == "Unknown": 
                            hostname = cached["hostname"]

                vendor = "Unknown"
                if self.mac_lookup:
                    try:
                        vendor = self.mac_lookup.lookup(mac)
                    except:
                        pass
                
                temp_updates.append({
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "possible_names": possible_names,
                    "vendor": vendor
                })

            # Quick update with lock
            with self.lock:
                for item in temp_updates:
                    mac = item["mac"]
                    if mac not in self.devices:
                        self.devices[mac] = {
                            "ip": item["ip"],
                            "mac": mac,
                            "vendor": item["vendor"],
                            "hostname": item["hostname"],
                            "possible_names": item.get("possible_names", []),
                            "last_seen": time.time()
                        }
                    else:
                        # Check for IP conflict (IP moved to this new MAC)
                        # Remove IP from any other device that claimed it
                        for other_mac, other_dev in list(self.devices.items()):
                            if other_mac != mac and other_dev['ip'] == item['ip']:
                                del self.devices[other_mac] # Remove stale entry

                        self.devices[mac]["ip"] = item["ip"]
                        self.devices[mac]["last_seen"] = time.time()
                        
                        # Update hostnames list
                        if "possible_names" not in self.devices[mac]:
                            self.devices[mac]["possible_names"] = []
                        
                        # Merge new names
                        for name in item["possible_names"]:
                            if name not in self.devices[mac]["possible_names"]:
                                self.devices[mac]["possible_names"].append(name)
                        
                        # Pick best hostname
                        if self.devices[mac].get("manual_hostname"):
                            pass # Don't overwrite manual name
                        elif item["hostname"] != "Unknown":
                             self.devices[mac]["hostname"] = item["hostname"]
                        elif self.devices[mac]["hostname"] == "Unknown" and self.devices[mac]["possible_names"]:
                             self.devices[mac]["hostname"] = self.devices[mac]["possible_names"][0]

        except Exception as e:
            # print(f"Error scanning: {e}")
            pass

    def set_hostname(self, ip, name):
        with self.lock:
            for mac, dev in self.devices.items():
                if dev['ip'] == ip:
                    self.devices[mac]['hostname'] = name
                    self.devices[mac]['manual_hostname'] = True
                    return True
        return False

    def resolve_ip(self, ip) -> Generator[Dict, None, None]:
        """
        Deep scan for a specific IP using multiple protocols.
        Yields status updates and final results.
        """
        found_names = []
        
        # Helper to add unique
        def add_name(n, source):
            if n and n not in found_names and n != ip:
                found_names.append(n)
                return True
            return False

        # 1. Reverse DNS (Standard)
        yield {"type": "status", "message": "Checking Reverse DNS..."}
        try:
            name = socket.gethostbyaddr(ip)[0]
            if add_name(name, "DNS"):
                yield {"type": "result", "name": name, "source": "DNS"}
        except:
            pass

        # 2. mDNS (Multicast DNS)
        yield {"type": "status", "message": "Querying mDNS (Bonjour/Avahi)..."}
        name = self._resolve_mdns(ip)
        if add_name(name, "mDNS"):
            yield {"type": "result", "name": name, "source": "mDNS"}

        # 3. LLMNR (Windows/Linux)
        yield {"type": "status", "message": "Querying LLMNR..."}
        name = self._resolve_llmnr(ip)
        if add_name(name, "LLMNR"):
            yield {"type": "result", "name": name, "source": "LLMNR"}

        # 4. NetBIOS (Windows)
        yield {"type": "status", "message": "Querying NetBIOS..."}
        name = self._resolve_netbios(ip)
        if name == "NetBIOS-Device": name = None # Refine if possible
        # NetBIOS often needs parsing, assuming None for now if not implemented fully
        # Re-implementing simplified generic check
        
        # 5. SSDP (UPnP)
        yield {"type": "status", "message": "Scanning SSDP (UPnP)..."}
        name = self._resolve_ssdp(ip)
        if add_name(name, "SSDP"):
            yield {"type": "result", "name": name, "source": "SSDP"}

        # 6. SMB (Port 445)
        yield {"type": "status", "message": "Checking SMB headers..."}
        name = self._resolve_smb(ip)
        if add_name(name, "SMB"):
             yield {"type": "result", "name": name, "source": "SMB"}

        # 7. HTTP Scrape (Port 80/443)
        yield {"type": "status", "message": "Analyzing HTTP Services..."}
        name = self._resolve_http(ip)
        if add_name(name, "HTTP"):
            yield {"type": "result", "name": name, "source": "HTTP"}

        # Final Update
        with self.lock:
            for mac, dev in self.devices.items():
                if dev['ip'] == ip:
                     if "possible_names" not in self.devices[mac]:
                         self.devices[mac]["possible_names"] = []
                     
                     for n in found_names:
                         if n not in self.devices[mac]["possible_names"]:
                             self.devices[mac]["possible_names"].append(n)
                     
                     if self.devices[mac]["hostname"] == "Unknown" and found_names:
                         self.devices[mac]["hostname"] = found_names[0]
                     break
        
        yield {"type": "done", "names": found_names}

    def _resolve_mdns(self, ip):
        try:
            # Query _services._dns-sd._udp.local first? Or just PTR for IP.
            # PTR is standard for "Reverse"
            query_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            packet = Ether(dst="01:00:5e:00:00:fb")/IP(dst="224.0.0.251")/UDP(sport=5353, dport=5353)/DNS(rd=1, qd=DNSQR(qname=query_name, qtype="PTR"))
            response = srp1(packet, verbose=0, timeout=1, iface=self.interface)
            if response and response.haslayer(DNS) and response[DNS].an:
                name = response[DNS].an.rdata
                if isinstance(name, bytes): name = name.decode('utf-8')
                return name.rstrip('.')
        except: pass
        return None

    def _resolve_llmnr(self, ip):
        try:
            # LLMNR Query to 224.0.0.252:5355 using standard DNS structure
            # Querying for the IP itself is not standard LLMNR (usually A record query for name).
            # But we can try Reverse lookups in LLMNR too? 
            # Actually LLMNR is typically "Who is HOSTNAME?" -> IP.
            # Reverse: "Who is IP?" -> PTR?
            # Let's try PTR for the IP in in-addr.arpa domain, multicast to 224.0.0.252
            query_name = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
            packet = Ether(dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252")/UDP(sport=5355, dport=5355)/DNS(rd=1, qd=DNSQR(qname=query_name, qtype="PTR"))
            response = srp1(packet, verbose=0, timeout=1, iface=self.interface)
            if response and response.haslayer(DNS) and response[DNS].an:
                name = response[DNS].an.rdata
                if isinstance(name, bytes): name = name.decode('utf-8')
                return name.rstrip('.')
        except: pass
        return None

    def _resolve_netbios(self, ip):
        try:
            # NBNS Node Status (0x21)
            packet = IP(dst=ip)/UDP(sport=0, dport=137)/NBNSQueryRequest(SUFFIX=" "*15, QUESTION_TYPE=0x21, QUESTION_CLASS=1)
            response = sr1(packet, verbose=0, timeout=1, iface=self.interface)
            if response and response.haslayer("NBNS Resource Record"):
                # Extract first name. Scapy's generic NBNS parsing puts RRs in 'an' usually or we need to parse raw
                # For now, simplistic return if header exists
                 return "NetBIOS-Device"
        except: pass
        return None

    def _resolve_ssdp(self, ip):
        try:
            # Unicast SSDP meant for the device IP directly?
            # Or just send M-SEARCH and filter?
            # Sending M-SEARCH to 239.255.255.250 is standard, but we want THIS IP.
            # We can try sending unicast M-SEARCH to port 1900 of the target IP.
            msg = \
                'M-SEARCH * HTTP/1.1\r\n' \
                'HOST: 239.255.255.250:1900\r\n' \
                'MAN: "ssdp:discover"\r\n' \
                'MX: 1\r\n' \
                'ST: ssnp:all\r\n' \
                '\r\n'
            
            # Send UDP to IP:1900
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.0)
            sock.sendto(msg.encode(), (ip, 1900))
            data, _ = sock.recvfrom(1024)
            data = data.decode()
            
            # Parse for SERVER: or headers
            # Or friendly name in XML location?
            # Quick grab: SERVER field
            for line in data.split('\r\n'):
                if line.upper().startswith('SERVER:'):
                     return line.split(':', 1)[1].strip()
        except: pass
        return None

    def _resolve_http(self, ip):
        try:
            # Try port 80
            r = requests.get(f"http://{ip}", timeout=1.5)
            if r.status_code == 200:
                # regex title
                m = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE)
                if m: return m.group(1).strip()
        except: pass
        return None

    def _resolve_smb(self, ip):
        # Very basic TCP check or banner grab
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((ip, 445))
            if result == 0:
                s.close()
                return "SMB-Host" # True parsing of SMB NTLM is complex without impl
        except: pass
        return None
        
    def _get_all_hostnames(self, ip):
        # Compatibility wrapper if needed, but resolve_ip supersedes it
        # Just return result of dry run?
        # For now, scanner main loop uses this. We should update it to use the generator or a simplified version?
        # Simplified synchronous version:
        names = []
        try:
             name = socket.gethostbyaddr(ip)[0]
             if name: names.append(name)
        except: pass
        
        n = self._resolve_mdns(ip)
        if n and n not in names: names.append(n)
        
        return names

    def get_devices(self) -> List[Dict]:
        with self.lock:
            return list(self.devices.values())
