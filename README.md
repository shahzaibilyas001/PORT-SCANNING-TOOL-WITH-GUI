# NetScan Pro — Advanced Port Scanner

A production-grade, GUI-driven network port scanner built in Python.  
Features a dark glassmorphic interface, TCP/SYN scanning, banner grabbing, and JSON export.

---

## Features

| Feature | Details |
|---|---|
| **GUI** | CustomTkinter · dark glassmorphic theme · fully responsive |
| **Target input** | Single IP · hostname (DNS resolved) · CIDR range (e.g. `10.0.0.0/24`) |
| **Port selection** | Range (`1-1024`) · list (`80,443,8080`) · `common` preset (25 well-known ports) |
| **Scan types** | TCP Connect (no privileges needed) · SYN Stealth (root/admin required) |
| **Performance** | `ThreadPoolExecutor` with configurable thread count (10–500) |
| **Banner grabbing** | HTTP HEAD probe · raw recv for SSH/FTP/SMTP and others |
| **Color coding** | Open = green · Closed = red · Filtered = amber |
| **Display filter** | Show All / Open+Filtered / Open Only (switchable mid-scan) |
| **Export** | JSON with full result set + scan metadata + summary |
| **Error handling** | DNS failures · invalid inputs · missing privileges — all surfaced as dialogs |

---

## Requirements

- Python **3.10+**
- For SYN Stealth scan on **Windows**: install [Npcap](https://npcap.com) (free)
- For SYN Stealth scan on **Linux**: run with `sudo`

---

## Installation

```bash
# 1. Clone or download the project folder
cd "PORT SCANNING"

# 2. (Recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the Application

### TCP Connect scan (no special privileges needed)
```bash
python main.py
```

### SYN Stealth scan — Linux / macOS
```bash
sudo python main.py
```

### SYN Stealth scan — Windows
Right-click your terminal / VS Code → **Run as Administrator**, then:
```bash
python main.py
```

---

## Usage

1. **Target** — enter an IP address (`192.168.1.1`), hostname (`scanme.nmap.org`), or CIDR range (`192.168.1.0/24`).
2. **Ports** — enter a range (`1-1024`), list (`22,80,443`), or type `common` for the top 25 well-known ports.
3. **Scan Type** — select *TCP Connect* (safe, no privileges) or *SYN Stealth* (requires admin/root + Npcap on Windows).
4. **Timeout / Threads** — adjust sliders. Lower timeout = faster scan; more threads = higher concurrency.
5. Press **▶ START SCAN**. Results stream in real-time.
6. Use the **SHOW** filter to toggle between All / Open+Filtered / Open Only.
7. Press **⬇ EXPORT JSON** to save results once the scan finishes.

---

## Project Structure

```
PORT SCANNING/
├── main.py          # Entry point — DPI awareness + launch
├── gui.py           # UI layout, styling, event handlers
├── scanner.py       # TCP/SYN scan engine, banner grabbing
├── utils.py         # IP/CIDR parsing, port parsing, privilege check
└── requirements.txt
```

---

## Export Format (JSON)

```json
{
  "scan_info": {
    "target": "scanme.nmap.org",
    "scan_type": "TCP Connect",
    "port_range": "1-1024",
    "timestamp": "2026-07-02T14:30:00",
    "duration_seconds": 18.4
  },
  "results": [
    { "host": "45.33.32.156", "port": 22,  "status": "open", "service": "SSH",  "banner": "SSH-2.0-OpenSSH_6.6.1p1", "scan_time": 0.082 },
    { "host": "45.33.32.156", "port": 80,  "status": "open", "service": "HTTP", "banner": "HTTP/1.0 200 OK Server: Apache", "scan_time": 0.134 }
  ],
  "summary": {
    "total_hosts": 1,
    "total_ports_scanned": 1024,
    "open": 2,
    "closed": 1018,
    "filtered": 4
  }
}
```

---

## Legal & Ethical Notice

Only scan hosts you own or have **explicit written permission** to test.  
Unauthorized port scanning may be illegal in your jurisdiction.  
This tool is intended for educational and authorised security testing purposes only.
"FOR KALI"
(source venv/bin/activate
python main.py)