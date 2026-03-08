"""
modules/traffic_monitor.py
Passive network traffic monitoring module.
Uses psutil for cross-platform interface stats.
Future: integrate scapy for deep packet inspection.
"""

import psutil
import threading
import time
import logging
from collections import defaultdict, deque
from typing import Dict, Deque, Tuple

logger = logging.getLogger(__name__)


class TrafficMonitor:
    def __init__(self, settings):
        self.settings = settings
        self.interface = settings.interface
        self._running = False
        self._thread = None

        # Stats storage
        self._bytes_sent: Deque[Tuple[float, int]] = deque(maxlen=60)
        self._bytes_recv: Deque[Tuple[float, int]] = deque(maxlen=60)
        self._prev_sent = 0
        self._prev_recv = 0
        self._lock = threading.Lock()

        # Per-device traffic (future: deep packet inspection)
        self.device_traffic: Dict[str, Dict] = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets': 0,
            'last_seen': 0,
        })

        self.start()

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"Traffic monitor started on interface: {self.interface}")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        """Sample network interface stats every second."""
        while self._running:
            try:
                stats = psutil.net_io_counters(pernic=True)
                iface_stats = stats.get(self.interface)

                if iface_stats is None:
                    # Fallback to aggregate
                    iface_stats = psutil.net_io_counters()

                now = time.time()
                sent = iface_stats.bytes_sent
                recv = iface_stats.bytes_recv

                with self._lock:
                    if self._prev_sent > 0:
                        delta_sent = sent - self._prev_sent
                        delta_recv = recv - self._prev_recv
                        self._bytes_sent.append((now, delta_sent))
                        self._bytes_recv.append((now, delta_recv))
                    self._prev_sent = sent
                    self._prev_recv = recv

            except Exception as e:
                logger.warning(f"Traffic monitor error: {e}")

            time.sleep(1.0)

    def get_current_rates(self) -> Tuple[float, float]:
        """Return current TX/RX rates in KB/s."""
        with self._lock:
            if len(self._bytes_sent) > 0:
                tx = self._bytes_sent[-1][1] / 1024.0
                rx = self._bytes_recv[-1][1] / 1024.0
                return round(tx, 2), round(rx, 2)
        return 0.0, 0.0

    def get_rate_history(self) -> Tuple[list, list]:
        """Return last 60s of TX/RX rates in KB/s."""
        with self._lock:
            tx = [v / 1024.0 for _, v in self._bytes_sent]
            rx = [v / 1024.0 for _, v in self._bytes_recv]
        return tx, rx

    def get_active_connections(self) -> list:
        """Return list of active TCP connections."""
        try:
            conns = psutil.net_connections(kind='tcp')
            active = []
            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    active.append({
                        'local': f"{c.laddr.ip}:{c.laddr.port}",
                        'remote': f"{c.raddr.ip}:{c.raddr.port}",
                        'pid': c.pid,
                        'status': c.status,
                    })
            return active[:50]  # Limit
        except Exception:
            return []
