"""
config/settings.py
Central configuration for Neural Network Map v2.0
"""

import socket
import subprocess
import re
import os


class Settings:
    def __init__(self, args=None):
        # Network
        self.subnet        = (args.subnet if args and args.subnet else None) or self._detect_subnet()
        self.interface     = (args.interface if args and args.interface else None) or self._detect_interface()
        self.scan_interval = args.scan_interval if args and hasattr(args, 'scan_interval') else 30

        # UI
        self.theme         = args.theme if args and hasattr(args, 'theme') else 'cyberpunk'
        self.window_width  = 1600
        self.window_height = 900
        self.fps           = 60

        # Scan
        self.scan_timeout = 1.0
        self.max_threads  = 64
        self.ping_sweep   = True
        self.arp_scan     = True

        # Visualization
        self.node_radius   = 18
        self.pulse_speed   = 2.5
        self.glow_intensity = 0.8
        self.show_labels   = True
        self.show_mac      = False
        self.show_vendor   = True

        # Plugins
        self.telegram_token    = (args.telegram_token if args and hasattr(args, 'telegram_token') else None) or os.environ.get('TELEGRAM_BOT_TOKEN', '')
        self.telegram_chat     = (args.telegram_chat  if args and hasattr(args, 'telegram_chat')  else None) or os.environ.get('TELEGRAM_CHAT_ID', '')
        self.bandwidth_limit   = args.bandwidth_limit if args and hasattr(args, 'bandwidth_limit') else 10

        # ── Dispositivos confiables (no alertar ARP/anomalías) ───────────────
        self.trusted_devices = {
            '192.168.1.1':  'Router TP-Link',
            '192.168.1.34': 'ONT Huawei HG8145X6 (Telecom)',
            '192.168.1.4':  'DESKTOP-EIOHQ1O (PC principal)',
            '192.168.1.41': 'DESKTOP-EIOHQ1O (PC principal)',
        }
        # MACs confiables — no alertar ARP aunque cambien
        self.trusted_macs = {
            'FC:F1:36',   # ONT Huawei prefijo OUI
            '40:16:3B',   # OUI secundario ONT
        }

        # ── Honeypot ──────────────────────────────────────────────────────────
        self.honeypot_enabled = True
        self.honeypot_ports   = [21, 23, 80, 443, 3389, 8080, 4444]

        # ── Threat Intelligence (FASE 12) ─────────────────────────────────────
        self.abuseipdb_key              = os.environ.get('ABUSEIPDB_KEY',  '')
        self.virustotal_key             = os.environ.get('VIRUSTOTAL_KEY', '')
        self.threat_intel_enabled       = True
        self.threat_intel_cache_ttl     = 86400  # 24 horas
        self.threat_intel_check_interval = 300   # chequear cada 5 minutos
        self.threat_intel_abuse_threshold = 25   # score >= 25 → alerta CRITICAL

        # ── ML Avanzado (FASE 9) ──────────────────────────────────────────────
        # Isolation Forest
        self.ml_min_samples        = 20       # mínimo de muestras para entrenar modelo IF
        self.ml_contamination      = 0.1      # % outliers esperado en entrenamiento
        self.ml_anomaly_threshold  = 0.6      # score >= 0.6 → anomalía
        self.ml_critical_threshold = 0.85     # score >= 0.85 → crítico
        self.ml_eval_interval      = 60       # segundos entre evaluaciones
        self.ml_train_interval     = 600      # segundos entre re-entrenamientos

        # Port scan detection
        self.ml_portscan_window    = 60       # ventana en segundos
        self.ml_portscan_threshold = 15       # puertos únicos para disparar alerta

        # Exfiltración detection
        self.ml_exfil_window       = 300      # ventana en segundos (5 min)
        self.ml_exfil_threshold_mb = 50.0     # MB salientes para disparar alerta

        # Z-score
        self.ml_zscore_min_samples = 10       # muestras mínimas para Z-score

        # Themes — 4 temas
        self.themes = {
            'cyberpunk': {
                'bg':           (5, 5, 15),
                'node_default': (0, 200, 255),
                'node_gateway': (255, 60, 120),
                'node_unknown': (120, 80, 200),
                'node_active':  (0, 255, 160),
                'edge':         (0, 100, 180),
                'pulse':        (0, 255, 255),
                'text':         (180, 255, 255),
                'grid':         (10, 20, 40),
                'glow':         (0, 180, 255),
            },
            'matrix': {
                'bg':           (0, 5, 0),
                'node_default': (0, 200, 50),
                'node_gateway': (200, 255, 0),
                'node_unknown': (0, 120, 30),
                'node_active':  (180, 255, 100),
                'edge':         (0, 80, 20),
                'pulse':        (0, 255, 80),
                'text':         (100, 255, 120),
                'grid':         (0, 15, 0),
                'glow':         (0, 200, 50),
            },
            'neon': {
                'bg':           (8, 0, 15),
                'node_default': (200, 0, 255),
                'node_gateway': (255, 100, 0),
                'node_unknown': (100, 0, 200),
                'node_active':  (255, 50, 200),
                'edge':         (100, 0, 150),
                'pulse':        (255, 0, 255),
                'text':         (230, 180, 255),
                'grid':         (20, 0, 30),
                'glow':         (180, 0, 255),
            },
            'amber': {
                'bg':           (10, 6, 0),
                'node_default': (255, 160, 0),
                'node_gateway': (255, 80, 0),
                'node_unknown': (180, 100, 0),
                'node_active':  (255, 220, 80),
                'edge':         (120, 60, 0),
                'pulse':        (255, 200, 50),
                'text':         (255, 200, 120),
                'grid':         (30, 15, 0),
                'glow':         (200, 120, 0),
            },
        }

        self.colors = self.themes.get(self.theme, self.themes['cyberpunk'])

    def _detect_subnet(self):
        """Auto-detect local subnet — compatible Windows y Linux."""
        try:
            # Windows: ipconfig
            result = subprocess.run(['ipconfig'], capture_output=True, text=True,
                                    encoding='cp1252', errors='replace', timeout=5)
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for i, line in enumerate(lines):
                    if 'ipv4' in line.lower() or 'ip address' in line.lower():
                        match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if match:
                            ip    = match.group(1)
                            parts = ip.split('.')
                            if parts[0] in ('192', '10') or (parts[0] == '172' and 16 <= int(parts[1]) <= 31):
                                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            pass

        try:
            # Linux: ip route
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                if 'src' in line and ('192.168' in line or '10.' in line):
                    parts = line.split()
                    for part in parts:
                        if '/' in part and not part.startswith('default'):
                            return part
        except Exception:
            pass

        # Fallback universal
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def _detect_interface(self):
        """Auto-detect interfaz activa — Windows usa nombres diferentes a Linux."""
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'],
                                    capture_output=True, text=True, timeout=5)
            match = re.search(r'dev (\S+)', result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "eth0"
