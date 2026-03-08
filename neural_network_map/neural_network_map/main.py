#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════╗
║         NEURAL NETWORK MAP v1.0                  ║
║         Network Scanner & Visualizer             ║
║         Cyberpunk Edition                        ║
╚══════════════════════════════════════════════════╝
"""

import sys
import threading
import time
import argparse
from core.scanner import NetworkScanner
from core.graph_engine import GraphEngine
from ui.renderer import CyberpunkRenderer
from config.settings import Settings
from modules.traffic_monitor import TrafficMonitor
import logging

logging.basicConfig(
    filename='logs/nnm.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


def print_banner():
    print("""
\033[36m╔══════════════════════════════════════════════════════════╗
║  ███╗   ██╗███╗   ██╗███╗   ███╗                         ║
║  ████╗  ██║████╗  ██║████╗ ████║                         ║
║  ██╔██╗ ██║██╔██╗ ██║██╔████╔██║                         ║
║  ██║╚██╗██║██║╚██╗██║██║╚██╔╝██║                         ║
║  ██║ ╚████║██║ ╚████║██║ ╚═╝ ██║                         ║
║  ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝     ╚═╝                         ║
║  NEURAL NETWORK MAP  ·  Cyberpunk Edition  ·  v1.0       ║
╚══════════════════════════════════════════════════════════╝\033[0m
""")


def parse_args():
    parser = argparse.ArgumentParser(description='Neural Network Map - Network Visualizer')
    parser.add_argument('--subnet', default=None, help='Target subnet (e.g., 192.168.1.0/24)')
    parser.add_argument('--interface', default=None, help='Network interface (e.g., eth0, wlan0)')
    parser.add_argument('--scan-interval', type=int, default=30, help='Rescan interval in seconds')
    parser.add_argument('--no-gui', action='store_true', help='Run in headless mode')
    parser.add_argument('--theme', default='cyberpunk', choices=['cyberpunk', 'matrix', 'neon'])
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()
    settings = Settings(args)

    logger.info("Neural Network Map starting...")
    print(f"\033[32m[*] Initializing Neural Network Map...\033[0m")
    print(f"\033[32m[*] Target subnet: {settings.subnet}\033[0m")
    print(f"\033[32m[*] Theme: {settings.theme}\033[0m\n")

    # Core components
    scanner = NetworkScanner(settings)
    graph_engine = GraphEngine()
    traffic_monitor = TrafficMonitor(settings)

    # Initial scan
    print(f"\033[33m[~] Running initial network scan...\033[0m")
    devices = scanner.scan()
    graph_engine.build_from_devices(devices)
    print(f"\033[32m[+] Discovered {len(devices)} devices\033[0m")

    # Background scanner thread
    def background_scan():
        while True:
            time.sleep(settings.scan_interval)
            logger.info("Running background rescan...")
            new_devices = scanner.scan()
            graph_engine.update_devices(new_devices)

    scan_thread = threading.Thread(target=background_scan, daemon=True)
    scan_thread.start()

    # Launch GUI
    if not args.no_gui:
        renderer = CyberpunkRenderer(graph_engine, traffic_monitor, settings)
        renderer.run()
    else:
        print("\033[36m[*] Running in headless mode. Press Ctrl+C to stop.\033[0m")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\033[31m[!] Shutting down Neural Network Map.\033[0m")


if __name__ == "__main__":
    main()
