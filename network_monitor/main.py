import sys
import os
import argparse
import socket
import psutil
from network_monitor.logger import Logger

# Allow running directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def get_default_interface_info():
    gateways = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    gw_ip = None
    try:
        from scapy.all import conf
        gw_ip = conf.route.route("0.0.0.0")[2]
    except:
        pass
    
    # Fallback for MacOS if scapy fails
    if not gw_ip and sys.platform == "darwin":
        try:
            import subprocess
            result = subprocess.check_output(["route", "-n", "get", "default"]).decode()
            for line in result.split("\n"):
                if "gateway" in line:
                    gw_ip = line.split(":")[1].strip()
                    break
        except:
            pass

    for iface, addrs in gateways.items():
        if iface in stats and stats[iface].isup:
            for addr in addrs:
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return iface, addr.address, addr.netmask, gw_ip
    return None, None, None, None

def main():
    parser = argparse.ArgumentParser(description="Network Monitor with Active Surveillance")
    parser.add_argument('--web', action='store_true', help='Launch the Web UI instead of Terminal UI')
    parser.add_argument('--port', type=int, default=5000, help='Port for Web UI (default: 5000)')
    parser.add_argument('--cleanup', action='store_true', help='Emergency cleanup: Restore ARP tables')
    parser.add_argument('--kill', action='store_true', help='Force kill any process on the specified port')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose debug logging')
    args = parser.parse_args()

    # Setup Logging
    Logger.setup(args.verbose)

    # Detect Interface common for both
    iface, ip, netmask, gw_ip = get_default_interface_info()
    if not iface:
        Logger.error("Could not detect active network interface!")
        # sys.exit(1) # Don't exit yet if we just want to kill/cleanup
        pass # potentially we can continue for cleanup even if interface is weird, but usually needed.
        
    if args.kill:
        print(f"[*] Force killing process on port {args.port}...")
        try:
            # Find PID using lsof
            cmd = f"lsof -t -i :{args.port}"
            pid = os.popen(cmd).read().strip()
            if pid:
                pid = pid.replace('\n', ' ')
                Logger.info(f"Found PID(s) {pid}. Killing...")
                os.system(f"kill -9 {pid}")
                Logger.success("Process(es) killed.")
            else:
                Logger.info("No process found on that port.")
        except Exception as e:
            Logger.error(f"Error killing process: {e}")
            
        # Also run cleanup
        args.cleanup = True

    if args.cleanup:
        Logger.info("Running Emergency Network Cleanup...")
        from network_monitor.spoofer import ARPSpoofer
        # ... existing cleanup logic ...
        spoofer = ARPSpoofer(iface, gw_ip)
        if spoofer.gateway_mac:
            spoofer.restore_all()
            Logger.success("ARP Restoration Broadcast Sent.")
        else:
            Logger.error("Could not resolve Gateway MAC, cannot restore.")
        
        # Reset IP forwarding just in case
        if sys.platform == "darwin":
            os.system("sysctl -w net.inet.ip.forwarding=0")
        elif sys.platform.startswith("linux"):
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        Logger.success("Cleanup complete.")
        sys.exit(0)
        
    if not iface:
         sys.exit(1)

    cidr = sum(bin(int(x)).count('1') for x in netmask.split('.'))
    subnet = f"{ip}/{cidr}"

    if args.web:
        from network_monitor.web_server import start_server
        start_server(iface, subnet, gw_ip, args.port)
    else:
        from network_monitor.cli import start_cli
        start_cli(iface, ip, netmask, gw_ip)

if __name__ == "__main__":
    main()
