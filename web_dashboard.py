"""
web_dashboard.py
FASE 8 — Dashboard Web Neural Network Map v2.0
- Mapa mundial GeoIP con Leaflet.js (IPs externas en tiempo real)
- Panel ML: scores de anomalía por dispositivo
- Todo lo anterior (dispositivos, DPI, IDS, tráfico)
"""

import threading
import time
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from flask import Flask, render_template_string, jsonify
    from flask_socketio import SocketIO, emit
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    logger.warning("Flask/SocketIO no disponible — pip install flask flask-socketio")


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NEURAL NETWORK MAP</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
<script src="https://unpkg.com/globe.gl@2.27.2/dist/globe.gl.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
  :root {
    --bg:#05050f; --bg2:#0a0a1a; --cyan:#00c8ff; --pink:#ff3c78;
    --purple:#7850c8; --green:#00ffa0; --text:#b4ffff;
    --text-dim:#406070; --border:#0a3050; --glow:rgba(0,200,255,0.15);
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'Share Tech Mono',monospace;min-height:100vh;overflow-x:hidden;}
  body::before{content:'';position:fixed;inset:0;
    background-image:linear-gradient(rgba(0,100,180,0.05) 1px,transparent 1px),
    linear-gradient(90deg,rgba(0,100,180,0.05) 1px,transparent 1px);
    background-size:40px 40px;pointer-events:none;z-index:0;}
  header{position:relative;z-index:10;display:flex;align-items:center;justify-content:space-between;
    padding:12px 24px;border-bottom:1px solid var(--border);background:rgba(5,5,20,0.95);backdrop-filter:blur(10px);}
  .logo{font-family:'Orbitron',monospace;font-size:1.1rem;font-weight:900;color:var(--pink);
    letter-spacing:3px;text-shadow:0 0 20px rgba(255,60,120,0.6);}
  .logo span{color:var(--cyan);}
  .status-bar{display:flex;gap:20px;font-size:0.75rem;color:var(--text-dim);}
  .status-bar .val{color:var(--cyan);} .status-bar .alert-val{color:var(--pink);}
  .dot-live{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);
    box-shadow:0 0 8px var(--green);animation:blink 1.2s infinite;margin-right:6px;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:0.3}}
  .container{position:relative;z-index:1;display:grid;grid-template-columns:1fr 340px;
    grid-template-rows:auto;gap:12px;padding:12px;max-width:1600px;margin:0 auto;}
  @media(max-width:900px){.container{grid-template-columns:1fr;}.sidebar{display:grid;grid-template-columns:1fr 1fr;gap:12px;}}
  @media(max-width:600px){.sidebar{grid-template-columns:1fr;}}
  .card{background:rgba(10,10,26,0.9);border:1px solid var(--border);border-radius:4px;
    padding:0;overflow:hidden;box-shadow:0 0 20px rgba(0,0,0,0.5),inset 0 0 30px rgba(0,50,80,0.1);}
  .card-header{display:flex;align-items:center;justify-content:space-between;padding:10px 16px;
    border-bottom:1px solid var(--border);font-size:0.7rem;letter-spacing:2px;color:var(--cyan);}
  .card-header .icon{margin-right:8px;opacity:0.8;}
  .card-body{padding:12px 16px;}
  .devices-table{width:100%;border-collapse:collapse;font-size:0.72rem;}
  .devices-table th{color:var(--text-dim);text-align:left;padding:6px 8px;border-bottom:1px solid var(--border);
    letter-spacing:1px;font-size:0.65rem;}
  .devices-table td{padding:8px 8px;border-bottom:1px solid rgba(10,30,50,0.8);vertical-align:middle;}
  .devices-table tr:hover td{background:rgba(0,100,180,0.08);}
  .type-badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:0.6rem;letter-spacing:1px;border:1px solid;}
  .type-router{color:var(--pink);border-color:var(--pink);background:rgba(255,60,120,0.1);}
  .type-phone{color:var(--cyan);border-color:var(--cyan);background:rgba(0,200,255,0.1);}
  .type-windows_pc,.type-windows{color:#0078d4;border-color:#0078d4;background:rgba(0,120,212,0.1);}
  .type-printer{color:#00c870;border-color:#00c870;background:rgba(0,200,112,0.1);}
  .type-unknown{color:var(--purple);border-color:var(--purple);background:rgba(120,80,200,0.1);}
  .type-server{color:#ffcc00;border-color:#ffcc00;background:rgba(255,204,0,0.1);}
  .status-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px;}
  .status-active{background:var(--green);box-shadow:0 0 6px var(--green);}
  .status-offline{background:#444;}
  .ip-link{color:var(--cyan);text-decoration:none;cursor:pointer;}
  .ip-link:hover{text-shadow:0 0 8px var(--cyan);}
  .activity-list{list-style:none;}
  .activity-item{display:flex;align-items:center;gap:10px;padding:7px 0;
    border-bottom:1px solid rgba(10,30,50,0.8);font-size:0.72rem;animation:fadeIn 0.4s ease;}
  @keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
  .activity-icon{font-size:1rem;width:22px;text-align:center;}
  .activity-service{flex:1;} .activity-ip{color:var(--text-dim);font-size:0.65rem;}
  .activity-time{color:var(--text-dim);font-size:0.65rem;min-width:30px;text-align:right;}
  .alert-item{display:flex;align-items:flex-start;gap:10px;padding:8px 0;
    border-bottom:1px solid rgba(10,30,50,0.8);font-size:0.7rem;animation:fadeIn 0.3s ease;}
  .alert-crit{color:#ff4444;} .alert-warn{color:#ffc800;} .alert-info{color:#60c8ff;}
  .alert-icon{font-size:0.9rem;width:20px;} .alert-msg{flex:1;line-height:1.4;}
  .alert-ts{color:var(--text-dim);font-size:0.6rem;white-space:nowrap;}
  .talker-row{display:flex;align-items:center;gap:10px;padding:6px 0;font-size:0.72rem;}
  .talker-ip{color:var(--cyan);min-width:110px;}
  .talker-bar-wrap{flex:1;height:4px;background:var(--border);border-radius:2px;}
  .talker-bar{height:100%;background:var(--cyan);border-radius:2px;transition:width 0.5s;}
  .talker-val{color:var(--text-dim);font-size:0.65rem;min-width:55px;text-align:right;}
  .stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:12px;}
  @media(max-width:600px){.stats-row{grid-template-columns:repeat(2,1fr);}}
  .stat-box{background:rgba(10,10,26,0.9);border:1px solid var(--border);border-radius:4px;
    padding:12px 16px;text-align:center;}
  .stat-val{font-family:'Orbitron',monospace;font-size:1.6rem;font-weight:700;color:var(--cyan);
    text-shadow:0 0 12px rgba(0,200,255,0.5);}
  .stat-val.pink{color:var(--pink);text-shadow:0 0 12px rgba(255,60,120,0.5);}
  .stat-val.green{color:var(--green);text-shadow:0 0 12px rgba(0,255,160,0.5);}
  .stat-val.purple{color:var(--purple);text-shadow:0 0 12px rgba(120,80,200,0.5);}
  .stat-label{font-size:0.6rem;color:var(--text-dim);letter-spacing:2px;margin-top:4px;}
  footer{position:relative;z-index:10;text-align:center;padding:10px;font-size:0.6rem;
    color:var(--text-dim);border-top:1px solid var(--border);}
  ::-webkit-scrollbar{width:4px;}
  ::-webkit-scrollbar-track{background:var(--bg);}
  ::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}
  .no-data{color:var(--text-dim);font-size:0.7rem;padding:12px 0;text-align:center;}

  /* ── Incidentes correlación ── */
  .incident-item{padding:7px 0;border-bottom:1px solid rgba(10,30,50,0.8);font-size:0.7rem;}
  .incident-header{display:flex;align-items:center;gap:6px;margin-bottom:2px;}
  .incident-pattern{font-size:0.6rem;padding:1px 6px;border-radius:2px;border:1px solid;}
  .sev-CRITICAL{color:#ff1e1e;border-color:#ff1e1e;background:rgba(255,30,30,0.1);}
  .sev-WARN{color:#ffd700;border-color:#ffd700;background:rgba(255,215,0,0.1);}
  .incident-conf{color:var(--text-dim);font-size:0.6rem;margin-left:auto;}
  .incident-desc{color:var(--text-dim);font-size:0.62rem;line-height:1.3;}
  #globe-container{height:320px;border-radius:2px;background:#050510;position:relative;overflow:hidden;}
  #globe-container canvas{border-radius:2px;}
  .globe-loading{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
    color:var(--text-dim);font-size:0.7rem;letter-spacing:2px;}
  .threat-badge{display:inline-block;padding:1px 6px;border-radius:2px;font-size:0.6rem;
    background:rgba(255,30,30,0.15);border:1px solid #ff1e1e;color:#ff1e1e;margin-left:4px;}

  /* ── ML Anomaly panel ── */
  .anomaly-row{display:flex;align-items:center;gap:8px;padding:6px 0;
    border-bottom:1px solid rgba(10,30,50,0.8);font-size:0.7rem;}
  .anomaly-ip{color:var(--cyan);min-width:100px;}
  .anomaly-bar-wrap{flex:1;height:6px;background:var(--border);border-radius:3px;}
  .anomaly-bar{height:100%;border-radius:3px;transition:width 0.8s,background 0.8s;}
  .anomaly-level{font-size:0.65rem;min-width:70px;text-align:center;padding:1px 6px;
    border-radius:2px;border:1px solid;}
  .level-normal{color:#00c870;border-color:#00c870;background:rgba(0,200,112,0.1);}
  .level-suspicious{color:#ffc800;border-color:#ffc800;background:rgba(255,200,0,0.1);}
  .level-anomaly{color:#ff6400;border-color:#ff6400;background:rgba(255,100,0,0.1);}
  .level-critical{color:#ff2020;border-color:#ff2020;background:rgba(255,32,32,0.15);animation:blink 1s infinite;}
  .ml-badge{font-size:0.55rem;padding:1px 5px;border-radius:2px;
    background:rgba(120,80,200,0.2);border:1px solid var(--purple);color:var(--purple);}
  .ml-training{color:var(--text-dim);font-size:0.65rem;font-style:italic;}

  /* ── Sistema/About panel ── */
  .sys-section{margin-bottom:16px;}
  .sys-title{font-size:0.65rem;letter-spacing:2px;color:var(--cyan);margin-bottom:8px;
    border-bottom:1px solid var(--border);padding-bottom:4px;}
  .sys-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;}
  .sys-card{background:rgba(0,50,80,0.08);border:1px solid var(--border);border-radius:3px;
    padding:8px 12px;}
  .sys-card-title{font-size:0.68rem;color:var(--pink);margin-bottom:4px;font-weight:bold;}
  .sys-item{font-size:0.65rem;color:var(--text-dim);padding:2px 0;display:flex;gap:6px;align-items:center;}
  .sys-item .dot{color:var(--green);font-size:0.55rem;}
  .sys-item .dot-warn{color:var(--pink);font-size:0.55rem;}
  .lib-row{display:flex;align-items:center;justify-content:space-between;padding:4px 0;
    border-bottom:1px solid rgba(10,30,50,0.6);font-size:0.68rem;}
  .lib-name{color:var(--cyan);}
  .lib-ver{color:var(--text-dim);font-size:0.6rem;}
  .lib-ok{color:var(--green);}
  .lib-missing{color:var(--pink);}
  .phase-row{display:flex;align-items:center;gap:8px;padding:4px 0;
    border-bottom:1px solid rgba(10,30,50,0.6);font-size:0.68rem;}
  .phase-num{color:var(--pink);min-width:28px;font-family:'Orbitron',monospace;font-size:0.6rem;}
  .phase-name{flex:1;color:var(--text);}
  .phase-ok{color:var(--green);}
  .phase-pending{color:#ffc800;}

  .tab-nav{display:flex;gap:0;border-bottom:1px solid var(--border);}
  .tab-btn{padding:8px 16px;font-size:0.65rem;letter-spacing:1px;color:var(--text-dim);
    background:none;border:none;cursor:pointer;font-family:'Share Tech Mono',monospace;
    border-bottom:2px solid transparent;transition:all 0.2s;}
  .tab-btn:hover{color:var(--cyan);}
  .tab-btn.active{color:var(--cyan);border-bottom-color:var(--cyan);}
  .tab-content{display:none;} .tab-content.active{display:block;}
</style>
</head>
<body>

<header>
  <div class="logo">⬡ NEURAL <span>NETWORK</span> MAP</div>
  <div class="status-bar">
    <span><span class="dot-live"></span>LIVE</span>
    <span>NODES: <span class="val" id="hdr-nodes">-</span></span>
    <span>ALERTS: <span class="alert-val" id="hdr-alerts">-</span></span>
    <span>SUBNET: <span class="val" id="hdr-subnet">-</span></span>
    <span id="hdr-time">--:--:--</span>
  </div>
</header>

<div class="container">

  <!-- Stats row -->
  <div style="grid-column:1/-1;">
    <div class="stats-row">
      <div class="stat-box"><div class="stat-val" id="stat-devices">-</div><div class="stat-label">DISPOSITIVOS</div></div>
      <div class="stat-box"><div class="stat-val pink" id="stat-alerts">-</div><div class="stat-label">ALERTAS HOY</div></div>
      <div class="stat-box"><div class="stat-val green" id="stat-active">-</div><div class="stat-label">ACTIVOS DPI</div></div>
      <div class="stat-box"><div class="stat-val purple" id="stat-services">-</div><div class="stat-label">SERVICIOS</div></div>
    </div>
  </div>

  <!-- Main column -->
  <div>

    <!-- Devices table -->
    <div class="card" style="height:360px;overflow:hidden;display:flex;flex-direction:column;">
      <div class="card-header">
        <span><span class="icon">◈</span> DISPOSITIVOS EN LA RED</span>
        <span id="devices-count" style="color:var(--text-dim);font-size:0.65rem;"></span>
      </div>
      <div style="overflow-y:auto;flex:1;">
        <table class="devices-table">
          <thead><tr>
            <th>ESTADO</th><th>IP</th><th>HOSTNAME</th><th>VENDOR</th>
            <th>TIPO</th><th>OS</th><th>PUERTOS</th><th>VISTO</th>
          </tr></thead>
          <tbody id="devices-tbody"><tr><td colspan="8" class="no-data">Cargando...</td></tr></tbody>
        </table>
      </div>
    </div>

    <!-- GeoIP + ML tabs -->
    <div class="card" style="margin-top:12px;">
      <div class="tab-nav">
        <button class="tab-btn active" onclick="switchTab('geoip')">🌍 GLOBO 3D</button>
        <button class="tab-btn" onclick="switchTab('ml')">🤖 ANOMALÍAS ML</button>
        <button class="tab-btn" onclick="switchTab('traffic')">▲ TRÁFICO</button>
        <button class="tab-btn" onclick="switchTab('threats')">☠ AMENAZAS</button>
        <button class="tab-btn" onclick="switchTab('sistema')">⚙ SISTEMA</button>
      </div>

      <!-- Globo 3D tab (Fase 10) -->
      <div id="tab-geoip" class="tab-content active" style="padding:0;">
        <div id="globe-container">
          <div class="globe-loading" id="globe-loading">INICIALIZANDO GLOBO 3D...</div>
        </div>
        <div class="card-body" style="padding:8px 12px;">
          <div style="font-size:0.65rem;color:var(--text-dim);margin-bottom:6px;letter-spacing:1px;">TOP PAÍSES</div>
          <div id="geo-countries" style="display:flex;flex-wrap:wrap;gap:6px;"></div>
        </div>
      </div>

      <!-- ML Anomalies tab -->
      <div id="tab-ml" class="tab-content">
        <div class="card-body">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <span style="font-size:0.65rem;color:var(--text-dim);letter-spacing:1px;">SCORE DE ANOMALÍA POR DISPOSITIVO</span>
            <span class="ml-badge">IF + Z-SCORE + DBSCAN</span>
          </div>
          <div id="ml-scores-list"><div class="no-data">Recolectando datos... (necesita ~20 min)</div></div>
          <div style="margin-top:8px;font-size:0.6rem;color:var(--text-dim);">
            El modelo aprende el comportamiento normal de cada dispositivo y detecta patrones inusuales.
          </div>
        </div>
      </div>

      <!-- Traffic tab -->
      <div id="tab-traffic" class="tab-content">
        <div class="card-body" id="talkers-list"></div>
      </div>

      <!-- Sistema tab -->
      <div id="tab-sistema" class="tab-content">
        <div class="card-body" style="max-height:480px;overflow-y:auto;">

          <!-- Fases -->
          <div class="sys-section">
            <div class="sys-title">⬡ FASES COMPLETADAS</div>
            <div>
              <div class="phase-row"><span class="phase-num">F1</span><span class="phase-name">IDS — Alertas, ARP spoofing, port scan, sonido</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F2</span><span class="phase-name">Fingerprinting — OS, vendor, 7 niveles</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F3</span><span class="phase-name">SQLite — Historial persistente 4 tablas</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F4</span><span class="phase-name">Dashboard web Flask + SocketIO + mobile</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F5</span><span class="phase-name">GUI Pygame 60fps — 4 temas, minimap, animaciones</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F6</span><span class="phase-name">API REST — 14 endpoints</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F7</span><span class="phase-name">Plugin system v2 — EventBus + 7 plugins</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F8</span><span class="phase-name">GeoIP mundial + ML Isolation Forest scores</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F9</span><span class="phase-name">ML avanzado — perfiles por dispositivo + Z-score + DBSCAN</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F10</span><span class="phase-name">Globo 3D Three.js — conexiones mundiales animadas</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F11</span><span class="phase-name">Plugins v2 — DNSMonitor + MalwareTraffic</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F12</span><span class="phase-name">Threat Intelligence — AbuseIPDB + VirusTotal + feeds</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">F13</span><span class="phase-name">Visual cyberpunk avanzado — partículas, radar, timeline</span><span class="phase-pending">⏳ pendiente</span></div>
              <div class="phase-row"><span class="phase-num">F14</span><span class="phase-name">Motor correlación — 8 patrones de ataque</span><span class="phase-ok">✓</span></div>
              <div class="phase-row"><span class="phase-num">FX</span><span class="phase-name">Honeypot — 7 puertos trampa + nodo visual</span><span class="phase-ok">✓</span></div>
            </div>
          </div>

          <!-- Módulos activos -->
          <div class="sys-section">
            <div class="sys-title">◈ MÓDULOS ACTIVOS</div>
            <div class="sys-grid">
              <div class="sys-card">
                <div class="sys-card-title">🔍 DETECCIÓN</div>
                <div class="sys-item"><span class="dot">●</span> NetworkScanner (ARP + ping)</div>
                <div class="sys-item"><span class="dot">●</span> PacketSniffer (Scapy)</div>
                <div class="sys-item"><span class="dot">●</span> DPI Engine — 60+ servicios</div>
                <div class="sys-item"><span class="dot">●</span> OS Fingerprinting (Nmap)</div>
                <div class="sys-item"><span class="dot">●</span> NetBIOS + SSDP + UPnP</div>
              </div>
              <div class="sys-card">
                <div class="sys-card-title">🛡️ SEGURIDAD</div>
                <div class="sys-item"><span class="dot">●</span> IDS — ARP spoofing</div>
                <div class="sys-item"><span class="dot">●</span> IDS — Port scan detect</div>
                <div class="sys-item"><span class="dot">●</span> IDS — Nuevo dispositivo</div>
                <div class="sys-item"><span class="dot">●</span> IDS — Tráfico alto</div>
                <div class="sys-item"><span class="dot">●</span> Honeypot — 7 puertos trampa</div>
              </div>
              <div class="sys-card">
                <div class="sys-card-title">🤖 MACHINE LEARNING</div>
                <div class="sys-item"><span class="dot">●</span> Isolation Forest por IP</div>
                <div class="sys-item"><span class="dot">●</span> Z-score estadístico</div>
                <div class="sys-item"><span class="dot">●</span> DBSCAN clustering</div>
                <div class="sys-item"><span class="dot">●</span> Whitelist streaming</div>
                <div class="sys-item"><span class="dot">●</span> Exclusión host NNM</div>
              </div>
              <div class="sys-card">
                <div class="sys-card-title">🌍 INTELIGENCIA</div>
                <div class="sys-item"><span class="dot">●</span> GeoIP — ip-api.com</div>
                <div class="sys-item"><span class="dot">●</span> AbuseIPDB (score ≥25)</div>
                <div class="sys-item"><span class="dot">●</span> VirusTotal</div>
                <div class="sys-item"><span class="dot">●</span> Emerging Threats feed</div>
                <div class="sys-item"><span class="dot">●</span> Feodo Tracker feed</div>
              </div>
              <div class="sys-card">
                <div class="sys-card-title">⚔ CORRELACIÓN</div>
                <div class="sys-item"><span class="dot">●</span> RECON_TO_EXPLOIT</div>
                <div class="sys-item"><span class="dot">●</span> LATERAL_MOVEMENT</div>
                <div class="sys-item"><span class="dot">●</span> DATA_EXFILTRATION</div>
                <div class="sys-item"><span class="dot">●</span> C2_BEACON_CONFIRM</div>
                <div class="sys-item"><span class="dot">●</span> MULTI_STAGE_ATTACK</div>
              </div>
              <div class="sys-card">
                <div class="sys-card-title">🔌 PLUGINS ACTIVOS</div>
                <div class="sys-item"><span class="dot">●</span> GeoIP</div>
                <div class="sys-item"><span class="dot">●</span> BandwidthAlert</div>
                <div class="sys-item"><span class="dot">●</span> PortAlert</div>
                <div class="sys-item"><span class="dot">●</span> AutoReport</div>
                <div class="sys-item"><span class="dot">●</span> DNSMonitor</div>
                <div class="sys-item"><span class="dot">●</span> MalwareTraffic</div>
              </div>
            </div>
          </div>

          <!-- Librerías -->
          <div class="sys-section">
            <div class="sys-title">📦 LIBRERÍAS PYTHON</div>
            <div id="libs-list">
              <div class="lib-row"><span class="lib-name">pygame</span><span class="lib-ver">GUI 60fps cyberpunk</span><span class="lib-ok" id="lib-pygame">●</span></div>
              <div class="lib-row"><span class="lib-name">scapy</span><span class="lib-ver">Packet capture + DPI</span><span class="lib-ok" id="lib-scapy">●</span></div>
              <div class="lib-row"><span class="lib-name">networkx</span><span class="lib-ver">Grafo de dispositivos</span><span class="lib-ok" id="lib-networkx">●</span></div>
              <div class="lib-row"><span class="lib-name">flask + flask-socketio</span><span class="lib-ver">Dashboard web + push</span><span class="lib-ok" id="lib-flask">●</span></div>
              <div class="lib-row"><span class="lib-name">scikit-learn</span><span class="lib-ver">Isolation Forest + DBSCAN</span><span class="lib-ok" id="lib-sklearn">●</span></div>
              <div class="lib-row"><span class="lib-name">numpy</span><span class="lib-ver">Vectores ML + Z-score</span><span class="lib-ok" id="lib-numpy">●</span></div>
              <div class="lib-row"><span class="lib-name">scipy</span><span class="lib-ver">Estadística avanzada</span><span class="lib-ok" id="lib-scipy">●</span></div>
              <div class="lib-row"><span class="lib-name">requests</span><span class="lib-ver">AbuseIPDB + VirusTotal + GeoIP</span><span class="lib-ok" id="lib-requests">●</span></div>
              <div class="lib-row"><span class="lib-name">python-nmap</span><span class="lib-ver">OS fingerprinting</span><span class="lib-ok" id="lib-nmap">●</span></div>
              <div class="lib-row"><span class="lib-name">sqlite3</span><span class="lib-ver">Base de datos local (built-in)</span><span class="lib-ok">●</span></div>
              <div class="lib-row"><span class="lib-name">socket / threading</span><span class="lib-ver">Honeypot + concurrencia (built-in)</span><span class="lib-ok">●</span></div>
            </div>
            <div style="margin-top:8px;">
              <div style="font-size:0.6rem;color:var(--text-dim);letter-spacing:1px;margin-bottom:4px;">FRONTEND (CDN)</div>
              <div class="lib-row"><span class="lib-name">Three.js / globe.gl</span><span class="lib-ver">Globo 3D interactivo</span><span class="lib-ok">●</span></div>
              <div class="lib-row"><span class="lib-name">Socket.IO JS</span><span class="lib-ver">WebSocket tiempo real</span><span class="lib-ok">●</span></div>
              <div class="lib-row"><span class="lib-name">Google Fonts (Orbitron)</span><span class="lib-ver">Tipografía cyberpunk</span><span class="lib-ok">●</span></div>
            </div>
          </div>

          <!-- Info sistema -->
          <div class="sys-section">
            <div class="sys-title">💻 INFO DEL SISTEMA</div>
            <div id="sys-info">
              <div class="lib-row"><span class="lib-name">Versión</span><span style="color:var(--cyan)">Neural Network Map v2.0</span></div>
              <div class="lib-row"><span class="lib-name">Subnet</span><span style="color:var(--cyan)" id="sys-subnet">-</span></div>
              <div class="lib-row"><span class="lib-name">Host NNM</span><span style="color:var(--cyan)" id="sys-host">192.168.1.41</span></div>
              <div class="lib-row"><span class="lib-name">Dashboard</span><span style="color:var(--green)">http://localhost:5000</span></div>
              <div class="lib-row"><span class="lib-name">API REST</span><span style="color:var(--green)">http://localhost:5000/api/v1/status</span></div>
              <div class="lib-row"><span class="lib-name">Licencia</span><span style="color:var(--text-dim)">MIT — Open Source</span></div>
            </div>
          </div>

        </div>
      </div>

      <!-- Threats tab (Fase 12) -->
      <div id="tab-threats" class="tab-content">
        <div class="card-body">
          <div style="font-size:0.65rem;color:var(--text-dim);letter-spacing:1px;margin-bottom:10px;">
            IPS MALICIOSAS DETECTADAS — AbuseIPDB · VirusTotal · Emerging Threats · Feodo
          </div>
          <div id="threats-list"><div class="no-data">Verificando IPs externas...</div></div>
        </div>
      </div>
    </div>

  </div>

  <!-- Sidebar -->
  <div class="sidebar">

    <!-- DPI Activity -->
    <div class="card">
      <div class="card-header"><span class="icon">◉</span> ACTIVIDAD DPI EN VIVO</div>
      <div class="card-body" style="max-height:260px;overflow-y:auto;padding:8px 12px;">
        <ul class="activity-list" id="activity-list"><li class="no-data">Sin datos</li></ul>
      </div>
    </div>

    <!-- IDS Alerts -->
    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <span><span class="icon">⚠</span> IDS ALERTS</span>
        <span id="alerts-count" style="color:var(--pink);font-size:0.65rem;"></span>
      </div>
      <div id="alerts-list" class="card-body" style="max-height:260px;overflow-y:auto;padding:8px 12px;">
        <div class="no-data">Sin alertas</div>
      </div>
    </div>

    <!-- Top Services -->
    <div class="card" style="margin-top:12px;">
      <div class="card-header"><span class="icon">▶</span> TOP SERVICIOS</div>
      <div class="card-body" id="services-list" style="padding:8px 12px;"></div>
    </div>

    <!-- Incidentes Correlación (Fase 14) -->
    <div class="card" style="margin-top:12px;">
      <div class="card-header">
        <span><span class="icon">⚔</span> INCIDENTES CORRELADOS</span>
        <span id="incidents-count" style="color:var(--pink);font-size:0.65rem;"></span>
      </div>
      <div id="incidents-list" class="card-body" style="max-height:240px;overflow-y:auto;padding:8px 12px;">
        <div class="no-data">Analizando patrones...</div>
      </div>
    </div>

  </div>
</div>

<footer>NEURAL NETWORK MAP · Cyberpunk Edition · v2.0 · GeoIP + ML Anomaly Detection</footer>

<script>
// ── Socket ────────────────────────────────────────────────────────────────────
const socket = io();
let globe = null;
let _lastGeoData = [];
let _lastThreats = [];

// ── Globo 3D (Fase 10) ───────────────────────────────────────────────────────
const HOME_LAT = -24.19, HOME_LNG = -65.30;

function initGlobe() {
  const container = document.getElementById('globe-container');
  if (!container || typeof Globe === 'undefined') {
    document.getElementById('globe-loading').textContent = 'globe.gl no disponible';
    return;
  }
  document.getElementById('globe-loading').style.display = 'none';
  globe = Globe()(container)
    .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
    .backgroundImageUrl('https://unpkg.com/three-globe/example/img/night-sky.png')
    .width(container.clientWidth).height(320)
    .pointsData([]).pointLat('lat').pointLng('lng')
    .pointColor('color').pointAltitude(0.02).pointRadius('radius')
    .pointLabel(d => `<div style="background:#0a0a1a;border:1px solid #0a3050;padding:6px 10px;
      font-family:monospace;font-size:0.7rem;color:#b4ffff;border-radius:2px;">
      <b>${d.flag||'🌐'} ${d.country||'?'}</b><br>
      IP: <span style="color:#00c8ff">${d.ip}</span><br>
      ${d.service?'Svc: '+d.service+'<br>':''}
      ${d.threat?'<span style="color:#ff1e1e">☠ '+d.threat+'</span>':''}</div>`)
    .arcsData([]).arcStartLat(HOME_LAT).arcStartLng(HOME_LNG)
    .arcEndLat('lat').arcEndLng('lng').arcColor('arcColor')
    .arcAltitude(0.2).arcStroke(0.4)
    .arcDashLength(0.4).arcDashGap(0.2).arcDashAnimateTime(2000)
    .arcsTransitionDuration(500);
  globe.controls().autoRotate = true;
  globe.controls().autoRotateSpeed = 0.4;
  globe.pointsData([{lat:HOME_LAT,lng:HOME_LNG,color:'#ff3c78',radius:0.6,
    ip:'192.168.1.x',country:'Argentina',flag:'🇦🇷'}]);
}

function updateGlobe(geoData, threats) {
  if (!globe || !geoData || !geoData.length) return;
  const threatIPs = new Set((threats||[]).map(t=>t.ip));
  const countryCount = {};
  const points = [{lat:HOME_LAT,lng:HOME_LNG,color:'#ff3c78',radius:0.6,
    ip:'192.168.1.x',country:'Argentina',flag:'🇦🇷'}];
  const arcs = [];
  geoData.forEach(item => {
    if (!item.lat || !item.lon) return;
    const isThreat = threatIPs.has(item.ip);
    const color = isThreat ? '#ff1e1e' : item.service !== 'Unknown' ? '#00c8ff' : '#7850c8';
    const radius = isThreat ? 0.5 : 0.2 + Math.log2((item.count||1)+1)*0.05;
    const code = item.code || item.country || '??';
    countryCount[code] = (countryCount[code]||0) + (item.count||1);
    points.push({lat:item.lat,lng:item.lon,color,radius,
      ip:item.ip,country:item.country||'?',flag:item.flag||'🌐',
      service:item.service||'',threat:isThreat?'IP maliciosa':null});
    arcs.push({lat:item.lat,lng:item.lon,
      arcColor:isThreat
        ?['rgba(255,30,30,0.05)','rgba(255,30,30,0.7)']
        :['rgba(0,200,255,0.03)','rgba(0,200,255,0.35)']});
  });
  globe.pointsData(points);
  globe.arcsData(arcs);
  const sorted = Object.entries(countryCount).sort((a,b)=>b[1]-a[1]).slice(0,8);
  document.getElementById('geo-countries').innerHTML = sorted.map(([code,count]) => {
    const item = geoData.find(g=>(g.code||g.country)===code)||{};
    return `<span style="font-size:0.65rem;color:var(--text-dim);">
      ${item.flag||'🌐'} <span style="color:var(--cyan)">${code}</span>
      <span style="color:var(--text-dim)">${count}x</span></span>`;
  }).join('');
}

// ── Threats panel (Fase 12) ───────────────────────────────────────────────────
function updateThreats(threats) {
  const div = document.getElementById('threats-list');
  if (!threats || !threats.length) {
    div.innerHTML = '<div class="no-data" style="color:var(--green)">✓ Sin amenazas detectadas</div>';
    return;
  }
  div.innerHTML = threats.map(t => {
    const color = t.level==='critical'?'#ff1e1e':t.level==='high'?'#ff6b00':t.level==='medium'?'#ffd700':'#00c864';
    const sources = (t.sources||[]).join(', ')||'blocklist';
    const cats = (t.categories||[]).slice(0,2).join(', ')||'';
    return `<div style="display:flex;align-items:center;gap:8px;padding:6px 0;
      border-bottom:1px solid rgba(10,30,50,0.8);font-size:0.7rem;">
      <span style="color:${color};font-size:1rem;">☠</span>
      <div style="flex:1">
        <div><span style="color:${color}">${t.ip}</span>
          <span class="threat-badge">${(t.level||'').toUpperCase()}</span>
          <span style="color:var(--text-dim);font-size:0.6rem;margin-left:4px;">${sources}</span>
        </div>
        ${cats?`<div style="color:var(--text-dim);font-size:0.6rem">${cats}</div>`:''}
      </div>
      <span style="color:${color};font-weight:bold">${t.threat_score||0}</span>
    </div>`;
  }).join('');
}

// ── ML Scores ─────────────────────────────────────────────────────────────────
function updateMLScores(scores) {
  const container = document.getElementById('ml-scores-list');
  if (!scores || !scores.length) {
    container.innerHTML = '<div class="no-data ml-training">Recolectando datos... (~20 min para entrenar)</div>';
    return;
  }
  container.innerHTML = scores.map(s => {
    const pct    = Math.round(s.score * 100);
    const barClr = s.level==='critical'?'#ff2020':s.level==='anomaly'?'#ff6400':s.level==='suspicious'?'#ffc800':'#00c870';
    const badge  = s.trained
      ? `<span class="ml-badge" style="margin-left:4px">${(s.detection_method||'ML').toUpperCase()}</span>`
      : '<span style="font-size:0.55rem;color:var(--text-dim)">(reglas)</span>';
    const reasons = s.reasons&&s.reasons.length
      ? `<div style="font-size:0.6rem;color:var(--text-dim);margin-top:2px">${s.reasons[0]}</div>` : '';
    return `<div class="anomaly-row">
      <span class="anomaly-ip">${s.ip}</span>
      <div style="flex:1">
        <div style="display:flex;align-items:center;gap:6px">
          <div class="anomaly-bar-wrap"><div class="anomaly-bar" style="width:${pct}%;background:${barClr}"></div></div>
          <span style="font-size:0.65rem;color:${barClr};min-width:30px">${pct}%</span>
          <span class="anomaly-level level-${s.level}">${s.icon||''} ${(s.level||'').toUpperCase()}</span>
          ${badge}
        </div>${reasons}
      </div></div>`;
  }).join('');
}

// ── Tab switching ─────────────────────────────────────────────────────────────
function switchTab(name) {
  const tabs = ['geoip','ml','traffic','threats','sistema'];
  document.querySelectorAll('.tab-btn').forEach((b,i) => b.classList.toggle('active', tabs[i]===name));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  if (name==='geoip' && globe)
    setTimeout(()=>globe.width(document.getElementById('globe-container').clientWidth),50);
  if (name==='threats') fetchThreats();
}

function fetchThreats() {
  fetch('/api/v1/threats').then(r=>r.json()).then(data=>{
    _lastThreats = data||[];
    updateThreats(_lastThreats);
    updateGlobe(_lastGeoData, _lastThreats);
  }).catch(()=>{});
}

// ── Incidentes correlación (Fase 14) ─────────────────────────────────────────
function updateIncidents(incidents) {
  const div = document.getElementById('incidents-list');
  const cnt = document.getElementById('incidents-count');
  if (!incidents || !incidents.length) {
    div.innerHTML = '<div class="no-data" style="color:var(--green)">✓ Sin incidentes activos</div>';
    cnt.textContent = '';
    return;
  }
  cnt.textContent = incidents.length + ' activos';
  div.innerHTML = incidents.map(inc => {
    const sevCls = `sev-${inc.severity}`;
    const ts = inc.timestamp ? new Date(inc.timestamp*1000).toLocaleTimeString() : '';
    const conf = Math.round((inc.confidence||0)*100);
    return `<div class="incident-item">
      <div class="incident-header">
        <span style="font-size:1rem">${inc.icon||'⚡'}</span>
        <span class="incident-pattern ${sevCls}">${inc.pattern}</span>
        <span style="color:var(--cyan);font-size:0.6rem">${inc.id||''}</span>
        <span class="incident-conf">${conf}% · ${ts}</span>
      </div>
      <div class="incident-desc">${inc.description||''}</div>
      ${inc.ip ? `<div style="font-size:0.6rem;color:var(--cyan);margin-top:2px">${inc.ip}</div>` : ''}
    </div>`;
  }).join('');
}

function fetchIncidents() {
  fetch('/api/v1/incidents').then(r=>r.json()).then(data=>{
    updateIncidents(data||[]);
  }).catch(()=>{});
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (!b) return '-';
  if (b < 1024) return b+'B';
  if (b < 1048576) return (b/1024).toFixed(1)+'KB';
  if (b < 1073741824) return (b/1048576).toFixed(1)+'MB';
  return (b/1073741824).toFixed(2)+'GB';
}

function timeAgo(ts) {
  if (!ts) return '-';
  const s = Math.floor(Date.now()/1000 - ts);
  if (s < 60) return s+'s';
  if (s < 3600) return Math.floor(s/60)+'m';
  if (s < 86400) return Math.floor(s/3600)+'h';
  return Math.floor(s/86400)+'d';
}

function typeBadge(t) {
  const label = (t||'unknown').replace('_',' ').toUpperCase();
  const cls   = t === 'router' ? 'type-router' :
                t === 'phone'  ? 'type-phone'  :
                t === 'printer'? 'type-printer' :
                t && t.includes('windows') ? 'type-windows_pc' :
                t === 'server' ? 'type-server'  : 'type-unknown';
  return `<span class="type-badge ${cls}">${label}</span>`;
}

// ── Render functions ──────────────────────────────────────────────────────────
function updateDevices(devices) {
  const tbody = document.getElementById('devices-tbody');
  if (!devices || !devices.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="no-data">Sin dispositivos</td></tr>';
    return;
  }
  document.getElementById('devices-count').textContent = devices.length + ' dispositivos';
  document.getElementById('hdr-nodes').textContent = devices.length;
  document.getElementById('stat-devices').textContent = devices.length;

  tbody.innerHTML = devices.map(d => {
    const statusCls = d.status === 'active' ? 'status-active' : 'status-offline';
    const ports = Array.isArray(d.open_ports) ? d.open_ports.slice(0,3).join(', ') : (d.open_ports||'-');
    const os    = (d.os_info||'').substring(0,20);
    const ago   = timeAgo(d.last_seen);
    return `<tr>
      <td><span class="status-dot ${statusCls}"></span></td>
      <td><a class="ip-link">${d.ip}</a></td>
      <td>${d.hostname||'Unknown'}</td>
      <td>${d.vendor||'Unknown'}</td>
      <td>${typeBadge(d.device_type)}</td>
      <td style="color:var(--text-dim);font-size:0.65rem">${os}</td>
      <td style="color:var(--cyan)">${ports||'-'}</td>
      <td style="color:var(--text-dim)">${ago}</td>
    </tr>`;
  }).join('');
}

function updateActivity(activity) {
  const list = document.getElementById('activity-list');
  const active = new Set(activity.map(a => a.ip));
  document.getElementById('stat-active').textContent = active.size;
  document.getElementById('stat-services').textContent = activity.length;
  if (!activity.length) { list.innerHTML = '<li class="no-data">Sin actividad</li>'; return; }
  list.innerHTML = activity.slice(0,20).map(a => {
    const color = a.color ? `rgb(${a.color.join(',')})` : '#00c8ff';
    return `<li class="activity-item">
      <span class="activity-icon" style="color:${color}">${a.icon||'●'}</span>
      <span class="activity-service">${a.service}</span>
      <span class="activity-ip">${a.ip}</span>
      <span class="activity-time">${a.age}</span>
    </li>`;
  }).join('');
}

function updateAlerts(alerts) {
  const div = document.getElementById('alerts-list');
  const today = alerts.filter(a => {
    const ts = a.timestamp || a.ts || 0;
    return Date.now()/1000 - ts < 86400;
  }).length;
  document.getElementById('stat-alerts').textContent = today;
  document.getElementById('hdr-alerts').textContent  = today;
  document.getElementById('alerts-count').textContent = alerts.length + ' alertas';
  if (!alerts.length) { div.innerHTML = '<div class="no-data">Sin alertas</div>'; return; }
  div.innerHTML = alerts.slice(0,15).map(a => {
    const sev = (a.severity||'INFO').toUpperCase();
    const cls = sev==='CRITICAL'?'alert-crit':sev==='WARN'?'alert-warn':'alert-info';
    const ts  = a.timestamp ? new Date(a.timestamp*1000).toLocaleTimeString() : '';
    return `<div class="alert-item ${cls}">
      <span class="alert-icon">${a.icon||'●'}</span>
      <div class="alert-msg">
        <div>${a.message}</div>
        <div style="color:var(--text-dim);font-size:0.6rem">${a.ip||''}</div>
      </div>
      <span class="alert-ts">${ts}</span>
    </div>`;
  }).join('');
}

function updateTalkers(talkers) {
  const div = document.getElementById('talkers-list');
  if (!talkers || !talkers.length) { div.innerHTML = '<div class="no-data">Sin datos de tráfico</div>'; return; }
  const max = Math.max(...talkers.map(t => t[1]||0), 1);
  div.innerHTML = talkers.map(t => {
    const pct = Math.round((t[1]||0)/max*100);
    return `<div class="talker-row">
      <span class="talker-ip">${t[0]}</span>
      <div class="talker-bar-wrap"><div class="talker-bar" style="width:${pct}%"></div></div>
      <span class="talker-val">${fmtBytes(t[1])}</span>
    </div>`;
  }).join('');
}

function updateTopServices(svcs) {
  const div = document.getElementById('services-list');
  if (!svcs || !svcs.length) { div.innerHTML = '<div class="no-data">Sin datos</div>'; return; }
  const max = Math.max(...svcs.map(s => s[1]||0), 1);
  div.innerHTML = svcs.map(s => {
    const pct = Math.round((s[1]||0)/max*100);
    return `<div class="talker-row">
      <span class="talker-ip">${s[0]}</span>
      <div class="talker-bar-wrap"><div class="talker-bar" style="width:${pct}%;background:var(--pink)"></div></div>
      <span class="talker-val">${s[1]}x</span>
    </div>`;
  }).join('');
}

// ── Clock ─────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('hdr-time').textContent = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Socket events ─────────────────────────────────────────────────────────────
let _globeUpdateTimer = null;

function scheduleGlobeUpdate() {
  // Debounce: espera 800ms antes de actualizar el globo para no laggear
  if (_globeUpdateTimer) clearTimeout(_globeUpdateTimer);
  _globeUpdateTimer = setTimeout(() => {
    updateGlobe(_lastGeoData, _lastThreats);
    _globeUpdateTimer = null;
  }, 800);
}

socket.on('full_update', data => {
  document.getElementById('hdr-subnet').textContent = data.subnet || '-';
  const sysSubnet = document.getElementById('sys-subnet');
  if (sysSubnet) sysSubnet.textContent = data.subnet || '-';
  updateDevices(data.devices || []);
  updateActivity(data.activity || []);
  updateAlerts(data.alerts || []);
  updateTalkers(data.talkers || []);
  updateTopServices(data.top_services || []);
  // Globo: solo actualizar si realmente hay datos nuevos
  if (data.geo_data && data.geo_data.length !== _lastGeoData.length) {
    _lastGeoData = data.geo_data;
    scheduleGlobeUpdate();
  }
  if (data.ml_scores) updateMLScores(data.ml_scores);
  if (data.threats)   { _lastThreats = data.threats; updateThreats(_lastThreats); }
});

socket.on('new_alert', () => {
  const div = document.getElementById('alerts-list');
  div.style.boxShadow = '0 0 20px rgba(255,60,120,0.4)';
  setTimeout(() => div.style.boxShadow = '', 1000);
  socket.emit('request_data');
});

socket.on('geo_update', data => {
  if (data && data.geo_data) {
    _lastGeoData = data.geo_data;
    scheduleGlobeUpdate();
  }
});

socket.on('ml_update', data => {
  if (data && data.scores) updateMLScores(data.scores);
});

// Aumentar intervalo de 5s a 8s para reducir presión en el browser
socket.on('device_update', () => socket.emit('request_data'));
setInterval(() => socket.emit('request_data'), 8000);

// ── Init ──────────────────────────────────────────────────────────────────────
function fetchGeoData() {
  fetch('/api/geo').then(r=>r.json()).then(data=>{
    if (data && data.length > 0 && data.length !== _lastGeoData.length) {
      _lastGeoData = data;
      scheduleGlobeUpdate();
    }
  }).catch(()=>{});
}

window.onload = () => {
  initGlobe();
  socket.emit('request_data');
  fetchGeoData();
  fetchIncidents();
  setInterval(fetchGeoData,    30000);
  setInterval(fetchThreats,    120000);
  setInterval(fetchIncidents,  30000);
};
</script>
</body>
</html>
"""


class WebDashboard:
    def __init__(self, port: int = 5000):
        self.port     = port
        self._thread  = None
        self._app     = None
        self._sio     = None
        self.db       = None
        self.dpi      = None
        self.ids      = None
        self.scanner  = None
        self.graph    = None
        self.settings = None
        # Fase 8
        self.geoip_plugin  = None   # GeoIPPlugin del plugin_manager
        self.anomaly_engine = None  # AnomalyEngine
        self.threat_intel   = None  # ThreatIntelEngine (Fase 12)
        self.correlator     = None  # CorrelationEngine (Fase 14)

    def _build_app(self):
        app = Flask(__name__)
        app.config['SECRET_KEY'] = 'nnm-cyberpunk-2077'
        sio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

        @app.route('/')
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route('/api/devices')
        def api_devices():
            return jsonify(self.db.get_all_devices() if self.db else [])

        @app.route('/api/alerts')
        def api_alerts():
            return jsonify(self.db.get_recent_alerts(50) if self.db else [])

        @app.route('/api/activity')
        def api_activity():
            return jsonify(self._get_activity_data())

        @app.route('/api/status')
        def api_status():
            return jsonify(self.db.get_summary() if self.db else {})

        @app.route('/api/geo')
        def api_geo():
            return jsonify(self._get_geo_data())

        @app.route('/api/ml')
        def api_ml():
            return jsonify(self._get_ml_scores())

        @app.route('/api/v1/threats')
        def api_threats():
            if self.threat_intel:
                try:
                    return jsonify(self.threat_intel.get_threats())
                except Exception:
                    pass
            return jsonify([])

        @app.route('/api/v1/incidents')
        def api_incidents():
            if self.correlator:
                try:
                    return jsonify(self.correlator.get_active_incidents())
                except Exception:
                    pass
            return jsonify([])

        @app.route('/api/v1/correlation/stats')
        def api_corr_stats():
            if self.correlator:
                try:
                    return jsonify(self.correlator.get_stats())
                except Exception:
                    pass
            return jsonify({})

        @sio.on('connect')
        def on_connect():
            self._emit_full_update(sio)

        @sio.on('request_data')
        def on_request_data():
            self._emit_full_update(sio)

        self._app = app
        self._sio = sio

    def _get_activity_data(self):
        if not self.dpi:
            return []
        result     = []
        active_ips = self.dpi.get_active_devices()
        if self.db:
            for dev in self.db.get_all_devices():
                ip = dev.get('ip', '')
                if ip and ip not in active_ips:
                    active_ips.append(ip)
        for ip in active_ips:
            for act in self.dpi.get_device_activity(ip, limit=5):
                result.append({
                    'ip':      ip,
                    'service': act.service,
                    'icon':    act.icon,
                    'color':   list(act.color),
                    'age':     act.age_str,
                    'count':   act.count,
                })
        result.sort(key=lambda x: x.get('age', '99h'))
        return result[:30]

    def _get_geo_data(self) -> list:
        """Obtiene datos GeoIP del plugin para el mapa mundial."""
        if not self.geoip_plugin:
            return []
        try:
            return self.geoip_plugin.get_map_data()
        except Exception as e:
            logger.error(f"Error obteniendo geo data: {e}")
            return []

    def _get_ml_scores(self) -> list:
        """Obtiene scores de anomalía del motor ML."""
        if not self.anomaly_engine:
            return []
        try:
            return self.anomaly_engine.get_scores_summary()
        except Exception as e:
            logger.error(f"Error obteniendo ML scores: {e}")
            return []

    def _emit_full_update(self, sio):
        try:
            devices  = self.db.get_all_devices() if self.db else []
            alerts   = self.db.get_recent_alerts(20) if self.db else []
            activity = self._get_activity_data()
            talkers  = self.dpi.get_top_talkers(5) if self.dpi else []
            top_svcs = self.dpi.get_top_services(5) if self.dpi else []
            subnet   = self.settings.subnet if self.settings else '192.168.1.0/24'
            geo_data = self._get_geo_data()
            ml_scores = self._get_ml_scores()

            sio.emit('full_update', {
                'devices':     devices,
                'alerts':      alerts,
                'activity':    activity,
                'talkers':     [[ip, b, 0] for ip, b in talkers],
                'top_services':[[s[0], s[1]] for s in top_svcs],
                'subnet':      subnet,
                'geo_data':    geo_data,
                'ml_scores':   ml_scores,
            })
        except Exception as e:
            logger.error(f"Error emitiendo update: {e}")

    def emit_new_alert(self, alert):
        if self._sio:
            try:
                self._sio.emit('new_alert', {
                    'severity': alert.severity,
                    'message':  alert.message,
                    'ip':       alert.ip,
                })
            except Exception:
                pass

    def emit_geo_update(self):
        """Push de datos GeoIP al cliente cuando hay nuevas IPs."""
        if self._sio:
            try:
                self._sio.emit('geo_update', {'geo_data': self._get_geo_data()})
            except Exception:
                pass

    def emit_ml_update(self):
        """Push de scores ML cuando cambian."""
        if self._sio:
            try:
                self._sio.emit('ml_update', {'scores': self._get_ml_scores()})
            except Exception:
                pass

    def start(self):
        if not FLASK_AVAILABLE:
            print("\033[31m[!] Flask no disponible — pip install flask flask-socketio\033[0m")
            return False
        self._build_app()
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        import socket as _socket
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "localhost"
        print(f"\033[32m[+] Dashboard web activo:\033[0m")
        print(f"\033[36m    → Desde esta PC:  http://localhost:{self.port}\033[0m")
        print(f"\033[36m    → Desde el celu:  http://{local_ip}:{self.port}\033[0m")
        return True

    def _run_server(self):
        try:
            self._sio.run(self._app, host='0.0.0.0', port=self.port,
                          debug=False, use_reloader=False, log_output=False)
        except Exception as e:
            logger.error(f"Error en servidor web: {e}")
