# ⬡ Neural Network Map v2.0 — Cyberpunk Edition

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![Pygame](https://img.shields.io/badge/Pygame-2.x-green?style=for-the-badge)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=for-the-badge&logo=flask)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?style=for-the-badge&logo=scikit-learn)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2B-lightblue?style=for-the-badge&logo=windows)

**Real-time cyberpunk network monitor with AI anomaly detection, honeypot, and 3D visualization.**

[🇺🇸 English](#english) · [🇦🇷 Español](#español)

![NNM Main](docs/2026-03-08%20(9).png)

</div>

---

## 🖼️ Gallery / Galería

| Cyberpunk GUI — Honeypot + Radar + Timeline | Matrix Theme — Router selected |
|:---:|:---:|
| ![Main GUI](docs/2026-03-08%20(9).png) | ![Matrix Theme](docs/2026-03-08%20(13).png) |

| Web Dashboard — Device List + 3D Globe | 3D Globe — Live connections from Argentina |
|:---:|:---:|
| ![Dashboard](docs/2026-03-08%20(10).png) | ![Globe](docs/2026-03-08%20(11).png) |

| System Tab — Active modules + ML + Plugins + IDS Alerts |
|:---:|
| ![System](docs/2026-03-08%20(12).png) |

---

---

<a name="english"></a>
# 🇺🇸 English

## What is Neural Network Map?

Neural Network Map is a real-time local network monitor with a cyberpunk-style GUI. It discovers all devices on your network, visualizes them as an interactive graph, detects attacks using machine learning, and runs a honeypot to catch intruders — all from a single Python script.

Think of it as **Wireshark + Maltego + a hacker movie**, running live on your home or lab network.

## ✨ Features

**🖥️ Live Cyberpunk GUI (60fps)**
- Interactive node graph with zoom, pan, drag
- 4 themes: Cyberpunk, Matrix, Neon, Amber — press `T` to cycle
- Animated particles traveling between nodes based on real DPI traffic
- Attack radar (sonar-style) showing where alerts come from
- Alert timeline bar with hover tooltips
- Per-device DPI bubbles (TikTok, Google, Twitch, etc.)
- Minimap, spawn animations, glow effects

**🔍 Network Discovery**
- ARP + ping sweep
- OS fingerprinting via TTL + Nmap (7 levels)
- Vendor lookup by OUI (MAC prefix)
- NetBIOS + SSDP hostname resolution

**🚨 IDS — Intrusion Detection**
- New device detection
- ARP spoofing detection
- Port scan detection
- High traffic anomaly
- Streaming whitelist (Netflix, Twitch, YouTube — no false positives)
- Audio alert on CRITICAL events

**🤖 Machine Learning (Phase 9)**
- Isolation Forest per-device anomaly scoring (0–100%)
- Z-score statistical analysis
- DBSCAN clustering
- Auto-excludes NNM host from self-alerts

**🔗 Correlation Engine (Phase 14)**
- 8 attack patterns detected:
  `RECON_TO_EXPLOIT` · `LATERAL_MOVEMENT` · `DATA_EXFILTRATION`
  `C2_BEACON_CONFIRM` · `MULTI_STAGE_ATTACK` · and more

**🍯 Honeypot**
- 7 trap ports: FTP(21), Telnet(23), HTTP(80), HTTPS(443), RDP(3389), HTTP-Alt(8080), Backdoor(4444)
- Fake banners to attract scanners
- CRITICAL alert + visual pulsing orange node on connection

**🌍 Threat Intelligence (Phase 12)**
- AbuseIPDB integration
- VirusTotal integration
- Emerging Threats feed (555 IPs)
- Feodo Tracker feed
- 24h cache, 5-minute check interval

**📊 Web Dashboard** — `http://localhost:5000`
- Tab: 3D Globe (Three.js) with animated connection lines from Argentina
- Tab: ML Anomalies
- Tab: Live Traffic
- Tab: Threats
- Tab: System (active phases, modules, libraries)

**🔌 REST API — 14 endpoints**
```
/api/v1/status    /api/v1/devices   /api/v1/alerts
/api/v1/threats   /api/v1/incidents /api/v1/geo
/api/v1/ml        ...
```

**💾 SQLite persistence** — 4 tables, full history between restarts

**🔧 Plugin System v2**
- EventBus architecture
- 7 plugins: GeoIP · BandwidthAlert · PortAlert · AutoReport · DNSMonitor · MalwareTraffic

---

## 🚀 Quick Start

### Requirements
- Windows 10+ (run as Administrator)
- Python 3.11+
- Nmap installed: `C:\Program Files (x86)\Nmap\nmap.exe`

### Install
```bash
git clone https://github.com/maxivilte/neural-network-map.git
cd neural-network-map
pip install -r requirements.txt
```

### Configure API keys (optional)
Copy `.env.example` to `.env` and add your keys:
```
ABUSEIPDB_KEY=your_key_here
VIRUSTOTAL_KEY=your_key_here
TELEGRAM_BOT_TOKEN=your_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

### Run
```bash
# Run as Administrator
python main.py --subnet 192.168.1.0/24
```

---

## ⌨️ Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `T` | Cycle theme |
| `I` | Toggle IDS panel |
| `H` | Toggle history panel |
| `M` | Toggle minimap |
| `L` | Toggle labels |
| `R` | Reset camera |
| `Q` | Quit |
| `Scroll` | Zoom |
| `Drag` | Pan |
| `Click node` | Select + info panel |

---

## 🗂️ Project Structure

```
neural-network-map/
├── main.py                  # Entry point
├── web_dashboard.py         # Flask + SocketIO + 3D Globe
├── config/
│   └── settings.py          # All configuration
├── core/
│   ├── scanner.py           # ARP + fingerprinting
│   └── graph_engine.py      # NetworkX graph
├── modules/
│   ├── ids.py               # Intrusion detection
│   ├── anomaly_engine.py    # ML: IF + Z-score + DBSCAN
│   ├── threat_intel.py      # AbuseIPDB + VirusTotal + feeds
│   ├── correlation_engine.py# 8 attack patterns
│   └── honeypot.py          # 7 trap ports
├── ui/
│   └── renderer.py          # Pygame 60fps GUI
├── plugins/
│   └── plugin_manager.py    # EventBus + 7 plugins
├── api/
│   └── rest_api.py          # 14 REST endpoints
└── requirements.txt
```

---

## 🧩 Comparison

| Feature | NNM v2.0 | Wireshark | Nmap | Maltego |
|---------|----------|-----------|------|---------|
| Live cyberpunk GUI | ✅ | ❌ | ❌ | ⚠️ |
| ML anomaly detection | ✅ | ❌ | ❌ | ❌ |
| Attack correlation | ✅ | ❌ | ❌ | ⚠️ |
| Honeypot built-in | ✅ | ❌ | ❌ | ❌ |
| 3D globe visualization | ✅ | ❌ | ❌ | ❌ |
| Web dashboard + API | ✅ | ❌ | ❌ | ⚠️ |
| Real-time graph | ✅ | ⚠️ | ❌ | ⚠️ |
| Free & open source | ✅ | ✅ | ✅ | ❌ |

---

## 📋 Requirements

```
pygame
scapy
networkx
flask
flask-socketio
scikit-learn
numpy
scipy
requests
python-nmap
```

---

## ⚠️ Legal Notice

This tool is intended for use on networks you own or have explicit permission to monitor. Do not use on networks without authorization.

---

## 👤 Author

**Maximiliano Jonatan Vilte**
- GitHub: [@maxivilte](https://github.com/maxivilte)
- Project: [github.com/maxivilte/neural-network-map](https://github.com/maxivilte/neural-network-map)

---

## 📄 License

MIT License — Copyright (c) 2026 Maximiliano Jonatan Vilte — see [LICENSE](LICENSE)

---
---

<a name="español"></a>
# 🇦🇷 Español

## ¿Qué es Neural Network Map?

Neural Network Map es un monitor de red local en tiempo real con interfaz visual estilo cyberpunk. Descubre todos los dispositivos en tu red, los visualiza como un grafo interactivo, detecta ataques usando machine learning y ejecuta un honeypot para atrapar intrusos — todo desde un solo script Python.

Pensalo como **Wireshark + Maltego + una película de hackers**, corriendo en vivo en tu red doméstica o de laboratorio.

## ✨ Características

**🖥️ GUI Cyberpunk en vivo (60fps)**
- Grafo de nodos interactivo con zoom, paneo, arrastre
- 4 temas: Cyberpunk, Matrix, Neon, Amber — tecla `T` para ciclar
- Partículas animadas viajando entre nodos según tráfico DPI real
- Radar de ataques estilo sonar mostrando de dónde vienen las alertas
- Barra de timeline de alertas con tooltip al pasar el mouse
- Burbujas DPI por dispositivo (TikTok, Google, Twitch, etc.)
- Minimapa, animaciones de entrada, efectos de glow

**🔍 Descubrimiento de Red**
- ARP + ping sweep
- Fingerprinting de OS por TTL + Nmap (7 niveles)
- Lookup de fabricante por OUI (prefijo MAC)
- Resolución de hostname por NetBIOS + SSDP

**🚨 IDS — Detección de Intrusiones**
- Detección de nuevo dispositivo
- Detección de ARP spoofing
- Detección de port scan
- Anomalía de tráfico alto
- Whitelist de streaming (Netflix, Twitch, YouTube — sin falsos positivos)
- Alerta de sonido en eventos CRITICAL

**🤖 Machine Learning (Fase 9)**
- Isolation Forest por dispositivo, score 0–100%
- Análisis estadístico Z-score
- Clustering DBSCAN
- Excluye automáticamente el host NNM de sus propias alertas

**🔗 Motor de Correlación (Fase 14)**
- 8 patrones de ataque detectados:
  `RECON_TO_EXPLOIT` · `LATERAL_MOVEMENT` · `DATA_EXFILTRATION`
  `C2_BEACON_CONFIRM` · `MULTI_STAGE_ATTACK` · y más

**🍯 Honeypot**
- 7 puertos trampa: FTP(21), Telnet(23), HTTP(80), HTTPS(443), RDP(3389), HTTP-Alt(8080), Backdoor(4444)
- Banners falsos para atraer scanners
- Alerta CRITICAL + nodo naranja pulsante al recibir conexión

**🌍 Threat Intelligence (Fase 12)**
- Integración AbuseIPDB
- Integración VirusTotal
- Feed Emerging Threats (555 IPs)
- Feed Feodo Tracker
- Cache 24h, chequeo cada 5 minutos

**📊 Dashboard Web** — `http://localhost:5000`
- Tab: Globo 3D (Three.js) con líneas animadas desde Argentina
- Tab: Anomalías ML
- Tab: Tráfico en vivo
- Tab: Amenazas
- Tab: Sistema (fases activas, módulos, librerías)

**🔌 API REST — 14 endpoints**
```
/api/v1/status    /api/v1/devices   /api/v1/alerts
/api/v1/threats   /api/v1/incidents /api/v1/geo
/api/v1/ml        ...
```

**💾 Persistencia SQLite** — 4 tablas, historial completo entre reinicios

**🔧 Sistema de Plugins v2**
- Arquitectura EventBus
- 7 plugins: GeoIP · BandwidthAlert · PortAlert · AutoReport · DNSMonitor · MalwareTraffic

---

## 🚀 Inicio Rápido

### Requisitos
- Windows 10+ (ejecutar como Administrador)
- Python 3.11+
- Nmap instalado: `C:\Program Files (x86)\Nmap\nmap.exe`

### Instalación
```bash
git clone https://github.com/maxivilte/neural-network-map.git
cd neural-network-map
pip install -r requirements.txt
```

### Configurar claves API (opcional)
Copiar `.env.example` a `.env` y agregar tus claves:
```
ABUSEIPDB_KEY=tu_clave_aqui
VIRUSTOTAL_KEY=tu_clave_aqui
TELEGRAM_BOT_TOKEN=tu_token_aqui
TELEGRAM_CHAT_ID=tu_chat_id_aqui
```

### Ejecutar
```bash
# Ejecutar como Administrador
python main.py --subnet 192.168.1.0/24
```

---

## ⌨️ Atajos de Teclado

| Tecla | Acción |
|-------|--------|
| `T` | Cambiar tema |
| `I` | Panel IDS |
| `H` | Panel historial |
| `M` | Minimapa |
| `L` | Etiquetas |
| `R` | Reset cámara |
| `Q` | Salir |
| `Scroll` | Zoom |
| `Arrastrar` | Mover vista |
| `Click nodo` | Seleccionar + info |

---

## 🗂️ Estructura del Proyecto

```
neural-network-map/
├── main.py                  # Punto de entrada
├── web_dashboard.py         # Flask + SocketIO + Globo 3D
├── config/
│   └── settings.py          # Configuración central
├── core/
│   ├── scanner.py           # ARP + fingerprinting
│   └── graph_engine.py      # Grafo NetworkX
├── modules/
│   ├── ids.py               # Detección de intrusiones
│   ├── anomaly_engine.py    # ML: IF + Z-score + DBSCAN
│   ├── threat_intel.py      # AbuseIPDB + VirusTotal + feeds
│   ├── correlation_engine.py# 8 patrones de ataque
│   └── honeypot.py          # 7 puertos trampa
├── ui/
│   └── renderer.py          # GUI Pygame 60fps
├── plugins/
│   └── plugin_manager.py    # EventBus + 7 plugins
├── api/
│   └── rest_api.py          # 14 endpoints REST
└── requirements.txt
```

---

## ⚠️ Aviso Legal

Esta herramienta está diseñada para uso en redes propias o con permiso explícito. No usar en redes sin autorización.

---

## 👤 Autor

**Maximiliano Jonatan Vilte**
- GitHub: [@maxivilte](https://github.com/maxivilte)
- Proyecto: [github.com/maxivilte/neural-network-map](https://github.com/maxivilte/neural-network-map)

---

## 📄 Licencia

MIT License — Copyright (c) 2026 Maximiliano Jonatan Vilte — ver [LICENSE](LICENSE)
