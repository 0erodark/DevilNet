from zeroconf import Zeroconf
import socket

def get_mdns_hostname(ip):
    zeroconf = Zeroconf()
    try:
        # We try to see if any service on that IP is announcing itself
        # This is how names like 'macbook.local' are found
        info = zeroconf.get_service_info("_http._tcp.local.", "AnyDeviceName._http._tcp.local.")
        # Note: True mDNS lookup by IP is complex, but often just 
        # pinging the IP can trigger a name resolution in the OS cache.
        
        host_info = socket.gethostbyaddr(ip)
        print(f"Found via OS Cache: {host_info[0]}")
    except Exception:
        print(f"mDNS also failed to identify 192.168.100.6")
    finally:
        zeroconf.close()

get_mdns_hostname("192.168.100.6")