import signal
import sys
import time
import socket
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box

from network_monitor.scanner import DeviceScanner
from network_monitor.monitor import BandwidthMonitor
from network_monitor.spoofer import ARPSpoofer

def cidr_from_netmask(netmask):
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))

def format_speed(bytes_sec):
    if bytes_sec < 1024:
        return f"{bytes_sec} B/s"
    elif bytes_sec < 1024 * 1024:
        return f"{bytes_sec / 1024:.1f} KB/s"
    else:
        return f"{bytes_sec / (1024 * 1024):.1f} MB/s"

def format_total(bytes_total):
    if bytes_total < 1024:
        return f"{bytes_total} B"
    elif bytes_total < 1024 * 1024:
        return f"{bytes_total / 1024:.1f} KB"
    else:
        return f"{bytes_total / (1024 * 1024):.1f} MB"

def start_cli(iface, ip, netmask, gw_ip):
    console = Console()
    
    cidr = cidr_from_netmask(netmask)
    subnet = f"{ip}/{cidr}"
    
    console.print(f"[green]Starting Network Monitor[/green]")
    console.print(f"Interface: [bold]{iface}[/bold]")
    console.print(f"Your IP: [bold]{ip}[/bold]")
    console.print(f"Gateway: [bold]{gw_ip}[/bold]")
    console.print(f"Subnet: [bold]{subnet}[/bold] (Scanning...)")
    
    if not gw_ip:
        console.print("[yellow]Warning: Gateway IP not found. Active monitoring might fail.[/yellow]")

    # 2. Init Modules
    scanner = DeviceScanner(iface, subnet)
    monitor = BandwidthMonitor(iface)
    spoofer = ARPSpoofer(iface, gw_ip)

    def cleanup(sig, frame):
        console.print("\n[yellow]Stopping... (Restoring ARP tables, this may take a few seconds)[/yellow]")
        spoofer.stop()
        monitor.stop()
        scanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    scanner.start()
    monitor.start()
    spoofer.start()

    # 3. UI Loop
    try:
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                devices = scanner.get_devices()
                
                # Update spoof targets
                spoofer.set_targets(devices)
                
                speeds = monitor.get_speeds()

                table = Table(box=box.ROUNDED, title=f"Network Devices ({len(devices)} found)")
                table.add_column("IP Address", style="cyan")
                table.add_column("MAC Address", style="magenta")
                table.add_column("Hostname", style="white")
                table.add_column("Vendor", style="yellow")
                table.add_column("Download", justify="right", style="green")
                table.add_column("Upload", justify="right", style="blue")
                table.add_column("Total Usage", justify="right", style="bold white")

                known_ips = set()
                
                # Add rows for discovered devices
                for dev in devices:
                    ip = dev['ip']
                    known_ips.add(ip)
                    sp = speeds.get(ip, {"up": 0, "down": 0, "total_up": 0, "total_down": 0})
                    
                    total_bytes = sp.get('total_up', 0) + sp.get('total_down', 0)
                    
                    table.add_row(
                        ip,
                        dev['mac'],
                        dev.get('hostname', 'Unknown'),
                        dev['vendor'],
                        format_speed(sp['down']),
                        format_speed(sp['up']),
                        format_total(total_bytes)
                    )
                
                live.update(Panel(table, title="[bold blue]Network Monitor (Active Mode)[/bold blue]", subtitle="Press Ctrl+C to stop correctly"))
                time.sleep(1)

    except KeyboardInterrupt:
        pass
    except Exception as e:
        console.print_exception()
    finally:
        cleanup(None, None)
