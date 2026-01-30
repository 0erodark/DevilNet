import sys
import threading
import datetime

# Simple ANSI colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Logger:
    _verbose = False
    _lock = threading.Lock()

    @staticmethod
    def setup(verbose=False):
        Logger._verbose = verbose
        if verbose:
            print(f"{Colors.CYAN}[*] Verbose Logging Enabled{Colors.ENDC}")

    @staticmethod
    def success(msg):
        with Logger._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Colors.GREEN}[+] {msg}{Colors.ENDC}")

    @staticmethod
    def info(msg):
        with Logger._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Colors.BLUE}[*] {msg}{Colors.ENDC}")

    @staticmethod
    def warning(msg):
        with Logger._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Colors.WARNING}[!] {msg}{Colors.ENDC}")

    @staticmethod
    def error(msg):
        with Logger._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            print(f"{Colors.FAIL}[-] {msg}{Colors.ENDC}")

    @staticmethod
    def debug(msg):
        if not Logger._verbose:
            return
        with Logger._lock:
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            # Debug logs are often high volume, maybe dim them?
            print(f"{Colors.CYAN}[DEBUG] {msg}{Colors.ENDC}")
