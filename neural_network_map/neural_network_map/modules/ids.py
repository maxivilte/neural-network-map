"""
modules/ids.py
Intrusion Detection System (IDS) module — stub for future expansion.
Detects:
 - New unknown devices joining the network
 - Port scan patterns
 - ARP spoofing indicators
 - Abnormal traffic volume
"""

import time
import logging
from typing import Set, Dict, List, Callable

logger = logging.getLogger(__name__)


class Alert:
    SEVERITY_INFO = "INFO"
    SEVERITY_WARN = "WARN"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, severity: str, category: str, message: str, ip: str = ""):
        self.severity = severity
        self.category = category
        self.message = message
        self.ip = ip
        self.timestamp = time.time()

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.severity}] [{self.category}] {self.message}"


class IntrusionDetector:
    def __init__(self, settings):
        self.settings = settings
        self.known_devices: Set[str] = set()
        self.device_first_seen: Dict[str, float] = {}
        self.alerts: List[Alert] = []
        self.callbacks: List[Callable] = []
        self._port_scan_threshold = 10  # ports in < 5 seconds
        self._traffic_threshold_mb = 50  # MB/s abnormal threshold

    def register_callback(self, cb: Callable):
        """Register a function to be called on new alerts."""
        self.callbacks.append(cb)

    def _emit(self, alert: Alert):
        self.alerts.append(alert)
        logger.warning(str(alert))
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def register_known_devices(self, ips: List[str]):
        """Mark current devices as trusted baseline."""
        for ip in ips:
            self.known_devices.add(ip)
            if ip not in self.device_first_seen:
                self.device_first_seen[ip] = time.time()
        logger.info(f"IDS: {len(self.known_devices)} devices registered as baseline")

    def check_new_devices(self, current_ips: List[str]):
        """Alert on devices not in baseline."""
        for ip in current_ips:
            if ip not in self.known_devices:
                alert = Alert(
                    Alert.SEVERITY_WARN,
                    "NEW_DEVICE",
                    f"Unknown device joined: {ip}",
                    ip=ip
                )
                self._emit(alert)
                self.known_devices.add(ip)  # Add to avoid repeated alert

    def check_arp_spoofing(self, ip: str, mac: str, known_mac: str):
        """Detect ARP spoofing (MAC change for same IP)."""
        if mac != known_mac:
            alert = Alert(
                Alert.SEVERITY_CRITICAL,
                "ARP_SPOOF",
                f"MAC change for {ip}: {known_mac} → {mac} (possible ARP spoofing!)",
                ip=ip
            )
            self._emit(alert)

    def check_traffic_anomaly(self, ip: str, bytes_per_sec: float):
        """Alert on abnormal traffic from a device."""
        mb_per_sec = bytes_per_sec / (1024 * 1024)
        if mb_per_sec > self._traffic_threshold_mb:
            alert = Alert(
                Alert.SEVERITY_WARN,
                "HIGH_TRAFFIC",
                f"{ip} generating {mb_per_sec:.1f} MB/s — abnormal traffic",
                ip=ip
            )
            self._emit(alert)

    def get_recent_alerts(self, limit: int = 20) -> List[Alert]:
        return list(reversed(self.alerts[-limit:]))

    def get_alert_count(self) -> Dict[str, int]:
        counts = {Alert.SEVERITY_INFO: 0, Alert.SEVERITY_WARN: 0, Alert.SEVERITY_CRITICAL: 0}
        for a in self.alerts:
            counts[a.severity] = counts.get(a.severity, 0) + 1
        return counts
