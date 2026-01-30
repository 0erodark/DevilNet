import sqlite3
import threading
import time
import os
import json
from network_monitor.logger import Logger

class DatabaseManager:
    def __init__(self, db_path="network_data.db"):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        try:
            with self.lock:
                conn = sqlite3.connect(self.db_path)
                c = conn.cursor()
                
                # Devices table (persistent tracking)
                c.execute('''CREATE TABLE IF NOT EXISTS devices (
                            mac TEXT PRIMARY KEY,
                            ip TEXT,
                            hostname TEXT,
                            first_seen REAL,
                            last_seen REAL,
                            vendor TEXT,
                            alias TEXT,
                            profile TEXT DEFAULT 'default',
                            is_captive INTEGER DEFAULT 0
                        )''')

                # Quotas table
                c.execute('''CREATE TABLE IF NOT EXISTS quotas (
                            mac TEXT PRIMARY KEY,
                            bytes_used INTEGER DEFAULT 0,
                            quota_limit INTEGER DEFAULT 0, /* 0 = unlimited */
                            reset_period TEXT DEFAULT 'daily', /* daily, weekly, monthly */
                            last_reset REAL
                        )''')

                # Traffic Rules (Time-based events)
                c.execute('''CREATE TABLE IF NOT EXISTS rules (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT,
                            target_mac TEXT, /* 'ALL' or specific MAC */
                            action TEXT, /* 'block', 'throttle', 'redirect' */
                            start_time TEXT, /* HH:MM */
                            end_time TEXT, /* HH:MM */
                            days TEXT, /* 0,1,2,3,4,5,6 (Monday-Sunday) */
                            enabled INTEGER DEFAULT 1
                        )''')

                # DHCP Starvation Events / Security logs
                c.execute('''CREATE TABLE IF NOT EXISTS security_logs (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp REAL,
                            event_type TEXT,
                            details TEXT,
                            severity TEXT
                        )''')
                
                # Application/DPI Logs (Aggregated per device)
                c.execute('''CREATE TABLE IF NOT EXISTS app_usage (
                             mac TEXT,
                             app_name TEXT,
                             bytes_down INTEGER DEFAULT 0,
                             bytes_up INTEGER DEFAULT 0,
                             last_updated REAL,
                             PRIMARY KEY (mac, app_name)
                        )''')

                # Domain Redirection/Blocking Rules
                c.execute('''CREATE TABLE IF NOT EXISTS domain_rules (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            target_mac TEXT, /* 'ALL' or specific MAC */
                            domain_pattern TEXT, /* Wildcard support */
                            action TEXT, /* 'block' or 'redirect' */
                            redirect_target TEXT, /* URL or IP */
                            created_at REAL
                        )''')
                        
                # Browsing History (Persistent)
                c.execute('''CREATE TABLE IF NOT EXISTS browsing_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            mac TEXT,
                            domain TEXT,
                            timestamp REAL
                        )''')
                
                # Indexes
                c.execute("CREATE INDEX IF NOT EXISTS idx_history_mac ON browsing_history (mac)")

                # --- MIGRATIONS ---
                # Robust column addition using try/except
                try:
                    c.execute("ALTER TABLE devices ADD COLUMN is_captive INTEGER DEFAULT 0")
                    Logger.info("Migrated: Added 'is_captive' to devices")
                except sqlite3.OperationalError: pass # Exists
                
                try:
                    c.execute("ALTER TABLE devices ADD COLUMN profile TEXT DEFAULT 'default'")
                    Logger.info("Migrated: Added 'profile' to devices")
                except sqlite3.OperationalError: pass
                
                try:
                    c.execute("ALTER TABLE devices ADD COLUMN alias TEXT")
                    Logger.info("Migrated: Added 'alias' to devices")
                except sqlite3.OperationalError: pass

                conn.commit()
                conn.close()
                Logger.info(f"Database initialized at {self.db_path}")

        except Exception as e:
            Logger.error(f"Database Initialization Failed: {e}")

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    # --- Device Management ---
    def update_device(self, mac, ip, hostname=None, vendor=None):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            now = time.time()
            # check if exists
            c.execute("SELECT * FROM devices WHERE mac=?", (mac,))
            if c.fetchone():
                c.execute("UPDATE devices SET last_seen=?, ip=? WHERE mac=?", (now, ip, mac))
                if hostname:
                    c.execute("UPDATE devices SET hostname=? WHERE mac=?", (hostname, mac))
                if vendor:
                     c.execute("UPDATE devices SET vendor=? WHERE mac=?", (vendor, mac))
            else:
                c.execute("INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, vendor) VALUES (?, ?, ?, ?, ?, ?)",
                          (mac, ip, hostname, now, now, vendor))
            conn.commit()
            conn.close()
    
    def get_device(self, mac):
        with self.lock:
             conn = self.get_connection()
             conn.row_factory = sqlite3.Row
             c = conn.cursor()
             c.execute("SELECT * FROM devices WHERE mac=?", (mac,))
             row = c.fetchone()
             conn.close()
             return dict(row) if row else None
             
    def get_all_devices(self):
        with self.lock:
            conn = self.get_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM devices")
            rows = c.fetchall()
            conn.close()
            return [dict(r) for r in rows]

    # --- Quota Management ---
    def update_quota_usage(self, mac, bytes_delta):
        """Updates bytes used. Returns True if over quota (and quota is set)."""
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            
            # Ensure record exists
            c.execute("INSERT OR IGNORE INTO quotas (mac, last_reset) VALUES (?, ?)", (mac, time.time()))
            
            c.execute("UPDATE quotas SET bytes_used = bytes_used + ? WHERE mac=?", (bytes_delta, mac))
            
            # Check limit
            c.execute("SELECT bytes_used, quota_limit FROM quotas WHERE mac=?", (mac,))
            row = c.fetchone()
            conn.commit()
            conn.close()
            
            if row and row[1] > 0 and row[0] > row[1]:
                return True
            return False

    def get_quota_status(self, mac):
        with self.lock:
            conn = self.get_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM quotas WHERE mac=?", (mac,))
            row = c.fetchone()
            conn.close()
            return dict(row) if row else None
            
    def set_quota(self, mac, limit_bytes):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT OR IGNORE INTO quotas (mac, last_reset) VALUES (?, ?)", (mac, time.time()))
            c.execute("UPDATE quotas SET quota_limit=? WHERE mac=?", (limit_bytes, mac))
            conn.commit()
            conn.close()

    # --- Rules (Time-based) ---
    def add_rule(self, name, target_mac, action, start, end, days):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT INTO rules (name, target_mac, action, start_time, end_time, days) VALUES (?, ?, ?, ?, ?, ?)",
                      (name, target_mac, action, start, end, days))
            conn.commit()
            conn.close()

    def delete_rule(self, rule_id):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("DELETE FROM rules WHERE id=?", (rule_id,))
            conn.commit()
            conn.close()

    def get_active_rules(self):
        with self.lock:
            conn = self.get_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM rules WHERE enabled=1")
            rows = c.fetchall()
            conn.close()
            return [dict(r) for r in rows]
            
    # --- Security Logs ---
    def log_security_event(self, event_type, details, severity="low"):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT INTO security_logs (timestamp, event_type, details, severity) VALUES (?, ?, ?, ?)",
                      (time.time(), event_type, details, severity))
            conn.commit()
            conn.close()

    # --- App Usage ---
    def update_app_usage(self, mac, app_name, bytes_down, bytes_up):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT INTO app_usage (mac, app_name, bytes_down, bytes_up, last_updated) VALUES (?, ?, ?, ?, ?) "
                      "ON CONFLICT(mac, app_name) DO UPDATE SET "
                      "bytes_down = bytes_down + ?, bytes_up = bytes_up + ?, last_updated=?",
                      (mac, app_name, bytes_down, bytes_up, time.time(), bytes_down, bytes_up, time.time()))
            conn.commit()
            conn.close()

    # --- Captive Portal & Domain Rules ---
    def set_captive_status(self, mac, is_captive):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            val = 1 if is_captive else 0
            # Ensure device exists first? usually it does if we found MAC.
            # But better safe:
            c.execute("UPDATE devices SET is_captive=? WHERE mac=?", (val, mac))
            conn.commit()
            conn.close()

    def get_domain_rules(self):
        with self.lock:
            conn = self.get_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT * FROM domain_rules ORDER BY created_at DESC")
            rows = c.fetchall()
            conn.close()
            # Convert to list of dicts
            return [dict(r) for r in rows]

    def add_domain_rule(self, target_mac, pattern, action, target):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT INTO domain_rules (target_mac, domain_pattern, action, redirect_target, created_at) VALUES (?, ?, ?, ?, ?)",
                      (target_mac, pattern, action, target, time.time()))
            conn.commit()
            conn.close()

    def remove_domain_rule(self, rule_id):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("DELETE FROM domain_rules WHERE id=?", (rule_id,))
            conn.commit()
            conn.close()

    
    # --- Browsing History ---
    def log_browsing_history(self, mac, domain, timestamp):
        with self.lock:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("INSERT INTO browsing_history (mac, domain, timestamp) VALUES (?, ?, ?)",
                      (mac, domain, timestamp))
            conn.commit()
            conn.close()

    def get_browsing_history(self, mac, limit=100):
        with self.lock:
            conn = self.get_connection()
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT domain, timestamp FROM browsing_history WHERE mac=? ORDER BY timestamp DESC LIMIT ?", (mac, limit))
            rows = c.fetchall()
            conn.close()
            return [dict(r) for r in rows]
