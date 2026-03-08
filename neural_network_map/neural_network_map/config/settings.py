"""
config/settings.py
Central configuration for Neural Network Map
"""

import socket
import subprocess
import re


class Settings:
    def __init__(self, args=None):
        # Network
        self.subnet = (args.subnet if args and args.subnet else None) or self._detect_subnet()
        self.interface = (args.interface if args and args.interface else None) or self._detect_interface()
        self.scan_interval = args.scan_interval if args and hasattr(args, 'scan_interval') else 30

        # UI
        self.theme = args.theme if args and hasattr(args, 'theme') else 'cyberpunk'
        self.window_width = 1600
        self.window_height = 900
        self.fps = 60

        # Scan
        self.scan_timeout = 1.0       # seconds per host
        self.max_threads = 64         # parallel scan threads
        self.ping_sweep = True
        self.arp_scan = True

        # Visualization
        self.node_radius = 18
        self.pulse_speed = 2.5        # data pulse animation speed
        self.glow_intensity = 0.8
        self.show_labels = True
        self.show_mac = False
        self.show_vendor = True

        # Themes
        self.themes = {
            'cyberpunk': {
                'bg': (5, 5, 15),
                'node_default': (0, 200, 255),
                'node_gateway': (255, 60, 120),
                'node_unknown': (120, 80, 200),
                'node_active': (0, 255, 160),
                'edge': (0, 100, 180),
                'pulse': (0, 255, 255),
                'text': (180, 255, 255),
                'grid': (10, 20, 40),
                'glow': (0, 180, 255),
            },
            'matrix': {
                'bg': (0, 5, 0),
                'node_default': (0, 200, 50),
                'node_gateway': (200, 255, 0),
                'node_unknown': (0, 120, 30),
                'node_active': (180, 255, 100),
                'edge': (0, 80, 20),
                'pulse': (0, 255, 80),
                'text': (100, 255, 120),
                'grid': (0, 15, 0),
                'glow': (0, 200, 50),
            },
            'neon': {
                'bg': (8, 0, 15),
                'node_default': (200, 0, 255),
                'node_gateway': (255, 100, 0),
                'node_unknown': (100, 0, 200),
                'node_active': (255, 50, 200),
                'edge': (100, 0, 150),
                'pulse': (255, 0, 255),
                'text': (230, 180, 255),
                'grid': (20, 0, 30),
                'glow': (180, 0, 255),
            }
        }

        self.colors = self.themes.get(self.theme, self.themes['cyberpunk'])

    def _detect_subnet(self):
        """Auto-detect local subnet"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if 'src' in line and ('192.168' in line or '10.' in line or '172.' in line):
                    parts = line.split()
                    for part in parts:
                        if '/' in part and not part.startswith('default'):
                            return part
            # Fallback
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except Exception:
            return "192.168.1.0/24"

    def _detect_interface(self):
        """Auto-detect active network interface"""
        try:
            result = subprocess.run(['ip', 'route', 'get', '8.8.8.8'], capture_output=True, text=True)
            match = re.search(r'dev (\w+)', result.stdout)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "eth0"
