import threading
import time
import signal
import sys
import logging
import json
from flask import Flask, jsonify, render_template, request, Response, stream_with_context
from network_monitor.scanner import DeviceScanner
from network_monitor.monitor import BandwidthMonitor
from network_monitor.spoofer import ARPSpoofer
from network_monitor.limiter import PacketLimiter
from network_monitor.database import DatabaseManager
from network_monitor.scheduler import Scheduler
from network_monitor.logger import Logger

# Disable flask banner
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)

# Global instances
scanner = None
monitor = None
spoofer = None
limiter = None
db = None
scheduler = None
running = False
limits_active = False
device_quota_cache = {}

def init_modules(iface, subnet, gw_ip):
    global scanner, monitor, spoofer, limiter, db, scheduler, running
    scanner = DeviceScanner(iface, subnet)
    monitor = BandwidthMonitor(iface)
    spoofer = ARPSpoofer(iface, gw_ip)
    
    # Wait for gateway MAC to ensure Limiter works correctly
    retries = 3
    while spoofer.gateway_mac is None and retries > 0:
        time.sleep(1)
        spoofer = ARPSpoofer(iface, gw_ip) 
        retries -= 1
        
    limiter = PacketLimiter(iface, gw_ip, spoofer.gateway_mac)
    
    # Initialize DB and Scheduler
    db = DatabaseManager()
    
    def rule_callback(mac, action, enable):
        Logger.info(f"[Scheduler] Rule triggered: {mac} {action} {enable}")
        # TODO: Apply action
        pass

    scheduler = Scheduler(db, rule_callback)
    
    running = True

    scanner.start()
    monitor.start()
    spoofer.start()
    scheduler.start()
    
    # Start background sync
    t_sync = threading.Thread(target=background_sync, daemon=True)
    t_sync.start()

def background_sync():
    """Periodically syncs discovered devices, history, apps, and usage to DB and modules."""
    Logger.info("Background Persistence Loop Started")
    last_io_counters = {} # {ip: {'up': 0, 'down': 0}}
    
    while running:
        if scanner and spoofer and limiter and db and monitor:
            try:
                # 1. Sync Scanned Devices -> DB & Spoofer/Limiter
                devices = scanner.get_devices()
                spoofer.set_targets(devices)
                limiter.update_targets(devices)
                
                # Persist Devices
                for d in devices:
                    db.update_device(d['mac'], d['ip'], d.get('hostname'), d.get('vendor'))
                
                # 2. Sync History -> DB
                history_data = monitor.get_and_clear_history() # {ip: [(domain, ts)]}
                for ip, domains in history_data.items():
                    dev = next((d for d in devices if d['ip'] == ip), None)
                    if dev:
                        for entry in domains:
                            db.log_browsing_history(dev['mac'], entry[0], entry[1])

                # 3. Sync Apps -> DB
                apps_data = monitor.get_and_clear_apps() # {ip: {app_names}}
                for ip, app_set in apps_data.items():
                    dev = next((d for d in devices if d['ip'] == ip), None)
                    if dev:
                        for app in app_set:
                            db.update_app_usage(dev['mac'], app, 0, 0) # Bytes not tracked yet

                # 4. Sync Bandwidth -> DB (Quotas)
                speeds, _ = monitor.get_speeds()
                for ip, stats in speeds.items():
                    dev = next((d for d in devices if d['ip'] == ip), None)
                    if not dev: continue
                    
                    mac = dev['mac']
                    t_up = stats.get('total_up', 0)
                    t_down = stats.get('total_down', 0)
                    
                    if ip not in last_io_counters:
                        last_io_counters[ip] = {'up': t_up, 'down': t_down}
                        continue
                        
                    delta_up = t_up - last_io_counters[ip]['up']
                    delta_down = t_down - last_io_counters[ip]['down']
                    
                    # Handle resets
                    if delta_up < 0 or delta_down < 0:
                        last_io_counters[ip] = {'up': t_up, 'down': t_down}
                        continue

                    total_delta = delta_up + delta_down
                    if total_delta > 0:
                         over_quota = db.update_quota_usage(mac, total_delta)
                         
                         if limiter:
                             if over_quota:
                                 if mac not in limiter.quota_blocked_macs:
                                     limiter.set_quota_block(mac, True)
                                     check_limiter_state()
                                     Logger.warning(f"Device {ip} ({mac}) exceeded quota! Blocking enabled.")
                             else:
                                 # Unblock if under quota (e.g. limit increased)
                                 if mac in limiter.quota_blocked_macs:
                                     limiter.set_quota_block(mac, False)
                                     check_limiter_state()
                                     Logger.info(f"Device {ip} ({mac}) quota restored.")

                    last_io_counters[ip]['up'] = t_up
                    last_io_counters[ip]['down'] = t_down

            except Exception as e:
                Logger.error(f"Persistence Sync Error: {e}")
            
            # 5. Refresh Quota Cache
            try:
                device_quota_cache = db.get_all_quotas()
            except: pass
            
        time.sleep(5.0)

def stop_modules():
    global running
    try:
        if scheduler: scheduler.stop()
        if limiter: limiter.stop()
        if spoofer: spoofer.stop()
        if monitor: monitor.stop()
        if scanner: scanner.stop()
    except: pass

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/captive_portal')
def captive_portal():
    return render_template('captive_portal.html')

@app.route('/api/captive/acknowledge', methods=['POST'])
def captive_ack():
    # Allow the user
    # We need to know who sent this.
    ip = request.remote_addr
    # Find MAC from IP
    mac = None
    if scanner:
        with scanner.lock:
             for m, d in scanner.devices.items():
                 if d['ip'] == ip:
                     mac = m
                     break
    
    if mac and limiter:
        Logger.info(f"Access Granted (Captive) for {ip} ({mac})")
        limiter.set_captive_portal(mac, False)
        # Also ensure they aren't blocked by scheduler if that was the cause?
        # For now, just disable the captive flag.
        return jsonify({"status": "granted"})
        
    return jsonify({"error": "Unknown device"}), 400

def check_limiter_state():
    global limits_active
    if not limiter or not spoofer: return

    has_limits = len(limiter.limits) > 0
    has_rules = len(limiter.domain_rules) > 0
    has_captive = len(limiter.captive_portal_macs) > 0
    has_quota = len(limiter.quota_blocked_macs) > 0
    
    should_run = has_limits or has_rules or has_captive or has_quota
    
    if should_run and not limits_active:
        Logger.info(f"Activating Traffic Limiter (Reason: Limits={has_limits}, Rules={has_rules}, Captive={has_captive})")
        spoofer._disable_ip_forwarding()
        limiter.start()
        limits_active = True
    elif not should_run and limits_active:
        Logger.info("Deactivating Traffic Limiter (Enabling OS Forwarding)")
        limiter.stop()
        spoofer._enable_ip_forwarding()
        limits_active = False

@app.route('/api/limit', methods=['POST'])
def update_limit():
    global limits_active
    data = request.json
    ip = data.get('ip')
    up = int(data.get('up', 0))
    down = int(data.get('down', 0))
    
    if not limiter:
        return jsonify({"error": "Limiter not initialized"}), 500
        
    limiter.set_limit(ip, up, down)
    check_limiter_state()
        
    return jsonify({"status": "ok", "active": limits_active})

@app.route('/api/settings/dns', methods=['POST'])
def update_dns_blacklist():
    data = request.json
    domains = data.get('domains', [])
    if limiter:
        limiter.set_dns_blacklist(domains)
        check_limiter_state()
        return jsonify({"status": "ok", "count": len(domains)})
    return jsonify({"error": "Limiter not running"}), 500

@app.route('/api/settings/captive', methods=['POST'])
def update_captive_portal():
    data = request.json
    ip = data.get('ip')
    enable = data.get('enable', False)
    
    if limiter and scanner:
        # Update run-time and persistence
        
        # We need MAC address
        found_mac = None
        with scanner.lock:
             # Find MAC for this IP
             for m, d in scanner.devices.items():
                 if d['ip'] == ip:
                     found_mac = m
                     break
        
        if found_mac:
             limiter.set_captive_portal(found_mac, enable)
             if db:
                 db.set_captive_status(found_mac, enable)
             check_limiter_state()
             
        return jsonify({"status": "ok", "ip": ip, "captive": enable})
    return jsonify({"error": "Limiter not running"}), 500

@app.route('/events')
def sse_events():
    rate_ms = request.args.get('rate', 500)
    try:
        delay = float(rate_ms) / 1000.0
    except:
        delay = 0.5
    if delay < 0.1: delay = 0.1

    def generate():
        # Store last totals to calculate average speed over the `delay` interval
        # format: {ip: {'up': total_bytes, 'down': total_bytes, 'time': timestamp}}
        last_stats = {}
        
        # Pre-fill to minimize startup spikes
        if monitor:
            s, _ = monitor.get_speeds()
            now = time.time()
            for ip, d in s.items():
                last_stats[ip] = {'up': d['total_up'], 'down': d['total_down'], 'time': now}

        while True:
            start_time = time.time()
            if not scanner or not monitor:
                time.sleep(1)
                continue
                
            devices = scanner.get_devices()
            
            if spoofer: spoofer.set_targets(devices)
            if limiter: limiter.update_targets(devices)
            
            speeds, last_packet_ts = monitor.get_speeds()
            monitor_lag = time.time() - last_packet_ts if last_packet_ts > 0 else -1
            
            output_data = []
            for dev in devices:
                ip = dev['ip']
                if not ip or ip == "0.0.0.0":
                    continue
                    
                sp = speeds.get(ip, {"up": 0, "down": 0, "total_up": 0, "total_down": 0, "os": "Unknown", "domains": []})
                
                # Calculate speed over the custom interval
                total_up = sp.get('total_up', 0)
                total_down = sp.get('total_down', 0)
                
                display_up = 0
                display_down = 0
                
                if ip in last_stats:
                    prev = last_stats[ip]
                    dt = start_time - prev['time']
                    if dt > 0:
                        d_up = total_up - prev['up']
                        d_down = total_down - prev['down']
                        display_up = int(d_up / dt)
                        display_down = int(d_down / dt)
                
                last_stats[ip] = {'up': total_up, 'down': total_down, 'time': start_time}
                
                limit_up = 0
                limit_down = 0
                if limiter and ip in limiter.limits:
                    l = limiter.limits[ip]
                    limit_up = int(l['up'] / 8 / 1024)
                    limit_down = int(l['down'] / 8 / 1024)

                quota_limit = 0
                quota_used = 0
                if dev['mac'] in device_quota_cache:
                    q = device_quota_cache[dev['mac']]
                    quota_limit = q['limit']
                    quota_used = q['used']

                output_data.append({
                    "ip": ip,
                    "mac": dev['mac'],
                    "hostname": dev.get('hostname', 'Unknown'),
                    "possible_names": dev.get('possible_names', []),
                    "vendor": dev['vendor'],
                    "os": sp.get("os", "Unknown"),
                    "domains": sp.get("domains", []),
                    "up_speed": display_up,
                    "down_speed": display_down,
                    "total_up": total_up,
                    "total_down": total_down,
                    "last_seen": dev.get('last_seen', 0),
                    "limit_up": limit_up,
                    "limit_down": limit_down,
                    "quota_limit": quota_limit,
                    "quota_used": quota_used
                })
            
            json_data = json.dumps({
                "devices": output_data,
                "monitor_lag": monitor_lag
            })
            
            yield f"data: {json_data}\n\n"
            
            # Smart sleep to maintain consistent rate
            elapsed = time.time() - start_time
            sleep_time = delay - elapsed
            if sleep_time < 0: sleep_time = 0
            time.sleep(sleep_time)
            
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/data')
def get_data():
    # Keep this for fallback or initial fetch if needed
    if not scanner or not monitor:
        return jsonify({"error": "Modules not initialized"})
    
    devices = scanner.get_devices()
    speeds, last_packet_ts = monitor.get_speeds()
    monitor_lag = time.time() - last_packet_ts if last_packet_ts > 0 else -1
    
    data = []
    for dev in devices:
        ip = dev['ip']
        if not ip or ip == "0.0.0.0": continue
        
        sp = speeds.get(ip, {"up": 0, "down": 0, "total_up": 0, "total_down": 0, "os": "Unknown", "domains": []})
        limit_up = 0
        limit_down = 0
        if limiter and ip in limiter.limits:
            l = limiter.limits[ip]
            limit_up = int(l['up'] / 8 / 1024)
            limit_down = int(l['down'] / 8 / 1024)

        quota_limit = 0
        quota_used = 0
        if dev['mac'] in device_quota_cache:
            q = device_quota_cache[dev['mac']]
            quota_limit = q['limit']
            quota_used = q['used']

        data.append({
            "ip": ip,
            "mac": dev['mac'],
            "hostname": dev.get('hostname', 'Unknown'),
            "possible_names": dev.get('possible_names', []),
            "vendor": dev['vendor'],
            "os": sp.get("os", "Unknown"),
            "domains": sp.get("domains", []),
            "up_speed": sp['up'],
            "down_speed": sp['down'],
            "total_up": sp.get('total_up', 0),
            "total_down": sp.get('total_down', 0),
            "last_seen": dev.get('last_seen', 0),
            "limit_up": limit_up,
            "limit_down": limit_down,
            "quota_limit": quota_limit,
            "quota_used": quota_used
        })
        
    return jsonify({"devices": data, "monitor_lag": monitor_lag})

    
    return jsonify({"devices": data, "monitor_lag": monitor_lag})

@app.route('/history/<ip>')
def history_page(ip):
    # Get device info for name
    device_name = "Unknown Device"
    if scanner:
        # scanner.get_devices() returns list of dicts
        for d in scanner.get_devices():
            if d['ip'] == ip:
                device_name = d.get('hostname', 'Unknown')
                break
    
    # Get history
    history = []
    if monitor:
        speeds, _ = monitor.get_speeds()
        if ip in speeds:
            history = speeds[ip].get('domains', [])
    
    # Ensure history is list of objects (handle potential legacy strings)
    formatted_history = []
    for h in history:
        if isinstance(h, str):
            formatted_history.append({'domain': h, 'time': 0})
        else:
            formatted_history.append(h)
    
    # Reverse to show newest first
    formatted_history.reverse()

    return render_template('history.html', ip=ip, hostname=device_name, history=formatted_history)


@app.route('/rules')
def rules_page():
    return render_template('rules.html')

@app.route('/blocked')
def blocked_page():
    return render_template('blocked.html')

@app.route('/quota_exceeded')
def quota_exceeded():
    return render_template('quota_exceeded.html')

@app.route('/api/rules/domain', methods=['GET', 'POST'])
def domain_rules_api():
    if request.method == 'GET':
        if db: return jsonify(db.get_domain_rules())
        return jsonify([])
    
    # POST
    data = request.json
    if db:
        # Save to DB
        db.add_domain_rule(data['mac'], data['pattern'], data['action'], data['target'])
        # Update Limiter (Reload all rules)
        rules = db.get_domain_rules()
        if limiter: limiter.update_domain_rules(rules)
        check_limiter_state()
        return jsonify({"status": "ok"})
    return jsonify({"error": "DB not ready"}), 500

@app.route('/api/rules/domain/<int:rule_id>', methods=['DELETE'])
def delete_domain_rule(rule_id):
    if db:
        db.remove_domain_rule(rule_id)
        rules = db.get_domain_rules()
        if limiter: limiter.update_domain_rules(rules)
        check_limiter_state()
        return jsonify({"status": "ok"})
    return jsonify({"error": "DB not ready"}), 500

@app.route('/api/quota', methods=['POST'])
def update_quota():
    data = request.json
    mac = data.get('mac')
    limit_mb = int(data.get('limit_mb', 0))
    limit_bytes = limit_mb * 1024 * 1024
    if db and mac:
        db.set_quota(mac, limit_bytes)
        return jsonify({"status": "ok", "limit_mb": limit_mb})
    return jsonify({"error": "DB not ready or missing MAC"}), 400

@app.route('/api/quota/<ip>')
def get_quota(ip):
    # Resolve MAC
    if scanner:
         with scanner.lock:
             dev = next((d for d in scanner.devices.values() if d['ip'] == ip), None)
             if dev and db:
                 status = db.get_quota_status(dev['mac'])
                 if status:
                     return jsonify(dict(status))
                 else:
                     return jsonify({"quota_limit": 0, "bytes_used": 0})
    return jsonify({"error": "Device not found"}), 404

@app.route('/api/schedule', methods=['GET', 'POST'])
def schedule_api():
    if request.method == 'GET':
        if db: return jsonify(db.get_active_rules())
        return jsonify([])
    
    # POST
    data = request.json
    if db:
        # name, target_mac, action, start, end, days
        db.add_rule(data['name'], data['mac'], data['action'], data['start'], data['end'], data['days'])
        if scheduler: scheduler.load_rules()
        return jsonify({"status": "ok"})
    return jsonify({"error": "DB not ready"}), 500

@app.route('/api/schedule/<int:rule_id>', methods=['DELETE'])
def delete_schedule_rule(rule_id):
    if db:
        db.delete_rule(rule_id)
        if scheduler: scheduler.load_rules()
        return jsonify({"status": "ok"})
    return jsonify({"error": "DB not ready"}), 500

def start_redirect_server(target_port):
    """Starts a simple HTTP server on port 80 to redirect to the web UI or Blocked Page."""
    from http.server import HTTPServer, BaseHTTPRequestHandler
    import fnmatch
    
    class RedirectHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            host_header = self.headers.get('Host', '')
            host_domain = host_header.split(':')[0] if host_header else ''
            client_ip = self.client_address[0]
            
            # Check if this request is due to a Block or Captive Portal?
            # DNS spoofing sends them here.
            # If they are here, it's either:
            # 1. Captive Portal (Lock)
            # 2. Blocked Domain
            # 3. Random HTTP traffic (if we are default GW, usually not seen unless we intercept port 80 strictly. 
            #    Our limiter only redirects specific DNS to us. So if they are here, they were likely spoofed.)
            
            is_blocked = False
            
            # Check Limiter state for this IP/Domain
            if limiter:
                # 1. Captive Portal / Quota check
                target_mac_addr = limiter.targets_mac.get(client_ip)
                
                if target_mac_addr:
                    if target_mac_addr in limiter.captive_portal_macs:
                         self.redirect_to(f"http://{limiter.my_ip}:{target_port}/captive_portal")
                         return
                    if target_mac_addr in limiter.quota_blocked_macs:
                         self.redirect_to(f"http://{limiter.my_ip}:{target_port}/quota_exceeded")
                         return

                # 2. Domain Rule Check
                # We need to match what the limiter matched.
                target_mac_addr = limiter.targets_mac.get(client_ip)
                
                for rule in limiter.domain_rules:
                    if rule['target_mac'] == 'ALL' or rule['target_mac'] == target_mac_addr:
                        if fnmatch.fnmatch(host_domain, rule['domain_pattern']):
                            if rule['action'] == 'block':
                                is_blocked = True
                                break
                            elif rule['action'] == 'redirect':
                                # HTTP Redirect
                                self.redirect_to(rule['redirect_target'])
                                return

            if is_blocked:
                 # Show Blocked Page via Redirect to main server /blocked (to serve the HTML)
                 # We can't serve nice HTML easily from BaseHTTPRequestHandler without reading file.
                 # Easier to redirect to Flask app.
                 # We need our local IP. 
                 # host_domain might be 'youtube.com', so we can't redirect to that. 
                 # We must redirect to OUR IP.
                 my_ip = limiter.my_ip
                 self.redirect_to(f"http://{my_ip}:{target_port}/blocked")
                 return

            # Default: Captive Portal fallback?
            self.redirect_to(f"http://{limiter.my_ip if limiter else '0.0.0.0'}:{target_port}/captive_portal")

        def redirect_to(self, url):
            self.send_response(302)
            self.send_header('Location', url)
            self.end_headers()

    try:
        # Allow binding to port 80 (requires root)
        server = HTTPServer(('0.0.0.0', 80), RedirectHandler)
        Logger.info("Port 80 Redirect Server Started")
        server.serve_forever()
    except Exception as e:
        Logger.error(f"Could not start Redirect Server on port 80: {e}")

def start_server(iface, subnet, gw_ip, port=5000):
    init_modules(iface, subnet, gw_ip)
    
    # Load rules
    if db and limiter:
        # 1. Domain Rules
        rules = db.get_domain_rules()
        if limiter: limiter.update_domain_rules(rules)
        Logger.info(f"Loaded {len(rules)} domain rules")
        
        # 2. Captive Portal State (Persistence)
        devices = db.get_all_devices()
        count = 0
        for d in devices:
            if d.get('is_captive') == 1 and d.get('mac'):
                limiter.set_captive_portal(d['mac'], True)
                count += 1
            
            # Restore Quota Blocks
            q = db.get_quota_status(d['mac'])
            if q and q['bytes_used'] > q['quota_limit'] and q['quota_limit'] > 0:
                limiter.set_quota_block(d['mac'], True)
                Logger.warning(f"Restored Quota Block for {d['mac']}")

        Logger.info(f"Restored Captive Portal for {count} devices")
        
        # Ensure limiter starts if rules/captive loaded
        check_limiter_state()
        
        # Populate Quota Cache
        global device_quota_cache
        try:
            device_quota_cache = db.get_all_quotas()
            Logger.info(f"Loaded Quota Cache for {len(device_quota_cache)} devices")
        except: pass
        
        # 3. Restore known devices for immediate targeting
        if scanner:
            scanner.restore_devices(devices)
            restored = scanner.get_devices()
            Logger.info(f"Restored {len(devices)} known devices to Scanner")
            if spoofer: spoofer.set_targets(restored)
            if limiter: limiter.update_targets(restored)

    from werkzeug.serving import make_server
    # IMPORTANT: threaded=True is required for SSE to work without blocking other requests
    server = make_server('0.0.0.0', port, app, threaded=True)
    
    def signal_handler(sig, frame):
        print("\nStopping modules and server...")
        stop_modules()
        server.shutdown()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    Logger.success(f"Web UI running at http://0.0.0.0:{port}")
    
    # Start Redirect Server in background
    t_redirect = threading.Thread(target=start_redirect_server, args=(port,), daemon=True)
    t_redirect.start()
    
    server.serve_forever()
