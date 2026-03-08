# ⬡ NEURAL NETWORK MAP v1.0

```
╔══════════════════════════════════════════════════════════╗
║  NEURAL NETWORK MAP  ·  Cyberpunk Edition  ·  v1.0       ║
║  Network Scanner & Real-Time Visual Graph                ║
╚══════════════════════════════════════════════════════════╝
```

## Overview

Neural Network Map scans your local network and renders every device as a glowing node in a cyberpunk-style interactive graph. Data pulses animate across connections, devices are auto-fingerprinted by type, and the whole thing updates in real time.

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run with auto-detection (needs sudo for ARP)
sudo python main.py

# 3. Or specify your subnet and theme
sudo python main.py --subnet 192.168.1.0/24 --theme neon

# 4. Headless mode (no GUI)
sudo python main.py --no-gui
```

---

## Project Architecture

```
neural_network_map/
│
├── main.py                    # Entry point, orchestration
│
├── config/
│   └── settings.py            # All tunable parameters, themes
│
├── core/
│   ├── scanner.py             # Network scanning engine
│   │                            (ping sweep, ARP, DNS, port scan)
│   └── graph_engine.py        # NetworkX graph + layout engine
│
├── ui/
│   └── renderer.py            # Pygame cyberpunk renderer
│                                (glow, pulses, zoom, pan, HUD)
│
├── modules/
│   ├── traffic_monitor.py     # Real-time TX/RX stats (psutil)
│   └── ids.py                 # Intrusion detection stubs
│
├── requirements.txt
└── logs/
    └── nnm.log
```

---

## Controls

| Key / Action       | Effect                          |
|--------------------|---------------------------------|
| Scroll wheel       | Zoom in / out                   |
| Left drag          | Pan the map                     |
| Left click node    | Select & open info panel        |
| Right click        | Deselect                        |
| `L`                | Toggle labels                   |
| `R`                | Reset camera                    |
| `Escape`           | Deselect node                   |
| `Q`                | Quit                            |

---

## CLI Options

```
--subnet 192.168.1.0/24   Target subnet (auto-detected if omitted)
--interface eth0           Network interface
--scan-interval 30         Rescan every N seconds
--theme cyberpunk          Theme: cyberpunk | matrix | neon
--no-gui                   Headless mode
```

---

## Device Detection

The scanner identifies devices by combining:

1. **Reverse DNS** hostname lookup
2. **MAC OUI** vendor prefix database
3. **Open port** fingerprinting (SSH, HTTP, RDP, printing ports)
4. **Hostname pattern** matching

Detected types: `router`, `server`, `phone`, `laptop`, `desktop`,
`printer`, `iot`, `smart_tv`, `raspberry`, `nas`, `camera`, `unknown`

---

## Safe Scanning Recommendations

- ✅ Only scan networks you own or have permission to scan
- ✅ Use passive ARP reading when possible (`arp -n`)
- ✅ Default scan is non-intrusive (ICMP + light TCP connect)
- ✅ No SYN stealth scans by default (requires root + scapy)
- ✅ Logs all activity to `logs/nnm.log`
- ❌ Do NOT run aggressive port scans on corporate/shared networks
- ❌ Do NOT scan subnets you don't control

---

## Themes

| Theme      | Palette                                |
|------------|----------------------------------------|
| cyberpunk  | Cyan/magenta/dark-blue (default)       |
| matrix     | Green-on-black                         |
| neon       | Purple/magenta/violet                  |

---

## Future Modules Roadmap

### Phase 2 — Traffic Analysis
```python
# modules/deep_traffic.py
# - scapy sniffer for per-device bandwidth
# - protocol breakdown (TCP/UDP/DNS/HTTP)
# - top talker ranking
```

### Phase 3 — IDS Expansion
```python
# modules/ids.py (extend)
# - ARP spoofing detection (complete)
# - Port scan detection
# - New device alerts with sound
# - Email/webhook notifications
```

### Phase 4 — 3D Visualization
```python
# ui/renderer_3d.py
# - ModernGL / PyOpenGL
# - 3D force-directed graph
# - RTX particle effects
# - VR/AR ready
```

### Phase 5 — Web Dashboard
```python
# web/dashboard.py
# - Flask + SocketIO
# - Live browser dashboard
# - REST API for device data
# - Historical timeline
```

---

## Hardware Optimization (Ryzen 7 5700 + RTX 50 Series)

- Pygame uses hardware-accelerated `DOUBLEBUF` rendering
- Thread pool scanner uses up to 64 parallel workers
- FPS locked to 60 for smooth animation
- Background scan thread never blocks the render loop
- For 3D mode: enable `pygame.OPENGL` flag in renderer
- RTX 50: future CUDA-accelerated graph layout (cuGraph)

---

## Dependencies

| Package    | Purpose                          |
|------------|----------------------------------|
| pygame     | Hardware-accelerated GUI         |
| networkx   | Graph topology + algorithms      |
| psutil     | Interface traffic stats          |
| scapy      | ARP scanning (optional, root)    |
| numpy      | Animation math                   |
| matplotlib | Export + offline analysis        |

---

## Legal Notice

This tool is for **authorized network analysis only**.
Scanning networks without permission may violate laws including
the Computer Fraud and Abuse Act (CFAA) or local equivalents.
Always obtain written permission before scanning networks you don't own.
