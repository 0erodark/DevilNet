import threading
import time
import datetime
import logging

class Scheduler:
    def __init__(self, db_manager, action_callback):
        """
        :param db_manager: Instance of DatabaseManager
        :param action_callback: Function to call when a rule is triggered (args: mac, action, enable=True/False)
        """
        self.db = db_manager
        self.action_callback = action_callback
        self.running = False
        self.thread = None
        
        # Cache active states to avoid spamming callbacks
        # Key: (rule_id, mac), Value: active (bool)
        self.active_rule_states = {} 

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _loop(self):
        while self.running:
            try:
                self._check_time_rules()
                self._check_quotas()
            except Exception as e:
                logging.error(f"Scheduler Error: {e}")
            
            time.sleep(30) # Check every 30 seconds

    def _check_time_rules(self):
        now = datetime.datetime.now()
        current_time_str = now.strftime("%H:%M")
        current_day = str(now.weekday()) # 0=Monday, 6=Sunday
        
        rules = self.db.get_active_rules()
        
        for rule in rules:
            rid = rule['id']
            mac = rule['target_mac']
            action = rule['action']
            start = rule['start_time']
            end = rule['end_time']
            days = rule['days'].split(',')
            
            if current_day not in days:
                continue
                
            # Check if current time is within range
            is_active = False
            if start <= end:
                if start <= current_time_str <= end:
                    is_active = True
            else: # Crosses midnight (e.g. 23:00 to 06:00)
                if current_time_str >= start or current_time_str <= end:
                    is_active = True
            
            state_key = (rid, mac)
            last_state = self.active_rule_states.get(state_key, False)
            
            if is_active and not last_state:
                # Rule just started
                print(f"[Scheduler] Activating rule '{rule['name']}' for {mac}")
                self.action_callback(mac, action, True)
                self.active_rule_states[state_key] = True
            elif not is_active and last_state:
                # Rule just ended
                print(f"[Scheduler] Deactivating rule '{rule['name']}' for {mac}")
                self.action_callback(mac, action, False)
                self.active_rule_states[state_key] = False

    def _check_quotas(self):
        # Retrieve all quotas
        # If over quota, apply 'block' action if not already blocked by quota reason
        # This part requires more integration with the limiter to distinguish "Time Block" from "Quota Block"
        # For now, we just log/notify
        pass 
