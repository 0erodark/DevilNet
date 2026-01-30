# 😈 DevilNet
> *Absolute dominion over your local network.*

**DevilNet** (formerly Python Evil Limits) is a ruthless, userspace network monitoring and control suite designed to give you complete visibility and authority over devices on your LAN. 

Through advanced ARP spoofing, traffic shaping, and deep packet inspection techniques, DevilNet allows you to monitor usage, throttle bandwidth, block internet access, enforce captive portals, and even inspect visited domains—all from a stunning, sci-fi inspired web interface.

**⚠️ WARNING: EDUCATIONAL PURPOSE ONLY**
> This tool is intended for network administrators to monitor and manage their *own* networks. Features like ARP spoofing and MITM are aggressive. Do not use this on public networks or networks you do not own/have permission to audit. The author is not responsible for any misuse.

---

## 🔥 Features

### 👁️ Monitoring & Surveillance
- **Real-Time Bandwidth**: Watch live Upload/Download speeds for every device.
- **Deep Packet Inspection (DPI)**: Detects applications (Zoom, Netflix, YouTube) based on traffic heuristics.
- **SNI Sniffing**: Logs visited domains (HTTPS) for every target in real-time.
- **OS Fingerprinting**: Identifies device types (iOS, Windows, Linux) via TTL matching.
- **Stealth Mode**: "Smart Evasion" pauses spoofing when the Gateway investigates, keeping you undetected.

### ⚡ Traffic Control
- **Precision Limiting**: Apply upload/download caps (e.g., "50KB/s") to specific targets.
- **Bulk Actions**: Select multiple devices and apply rules instantly.
- **Domain Blocking**: Block specific websites (e.g., `*.tiktok.com`) or redirect them.
- **Captive Portal**: Force specific devices into a "locked" state where they only see a login page.

### 🕸️ Modern Web Interface
- **Cyberpunk Aesthetics**: Three distinct themes (Nexus, Cyber, Sunset).
- **SocketIO / SSE**: Real-time data streaming (<1s latency).
- **Interactive Graphs**: Per-device bandwidth history and top consumer visualization.

---

## 🛠️ Installation

### Prerequisites
- **Python 3.8+**
- **Root / Administrator Privileges** (Required for raw sockets & ARP injection)
- **OS**: MacOS or Linux (Windows support is experimental)

### Install Dependencies
Dependencies are managed via `requirements.txt`.

```bash
pip install -r requirements.txt
```

*Note: You may need to install `libpcap` specifics for your OS if Scapy complains (e.g., `brew install libpcap` on Mac).*

## 🚀 Usage

DevilNet is controlled primarily through its Web UI.

### 1. Start the Web Dashboard
This launches the backend service and the web server.

```bash
sudo python3 -m network_monitor.main --web --port 4000
```
Then open **`http://localhost:4000`** in your browser.

### 2. Monitoring Only (CLI Mode)
If you prefer the terminal:
```bash
sudo python3 -m network_monitor.main
```

### 3. Emergency Cleanup
If the program crashes or you need to immediately restore normal network routing (stop all spoofing):
```bash
sudo python3 -m network_monitor.main --cleanup
```

## 📂 Project Structure

- `network_monitor/`
  - `main.py`: Entry point and argument parsing.
  - `web_server.py`: Flask-based backend, handles API & SSE.
  - `monitor.py`: Core logic for bandwidth tracking, DPI, and SNI sniffing.
  - `limiter.py`: The enforcer—handles Token Bucket shaping and Packet Forwarding.
  - `spoofer.py`: ARP Poisoning logic with Smart Evasion.
  - `scanner.py`: Device discovery (ARP, mDNS, NetBIOS).
  - `database.py`: SQLite storage for persistent rules and history.
  - `templates/`: HTML/Tailwind frontend files.

## 📜 License
Unlicensed / Private. Use with caution.
