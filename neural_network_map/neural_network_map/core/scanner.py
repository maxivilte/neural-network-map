"""
core/scanner.py
Network scanner module - ARP sweep + port detection + device fingerprinting
Uses: scapy, socket, subprocess (for safe local scanning only)
"""

import socket
import subprocess
import threading
import ipaddress
import time
import re
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)

# Known MAC vendor prefixes (partial - extend as needed)
MAC_VENDORS = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:11": "Google",
    "f4:f5:d8": "Google",
    "ac:37:43": "HTC",
    "00:17:88": "Philips Hue",
    "ec:b5:fa": "Apple",
    "a4:c3:f0": "Apple",
    "00:1b:63": "Apple",
    "3c:22:fb": "Apple",
    "70:3e:ac": "Apple",
    "00:e0:4c": "Realtek",
    "00:1d:60": "Cisco",
    "00:1e:bd": "Cisco",
    "74:d4:35": "Amazon",
    "fc:65:de": "Amazon",
    "44:65:0d": "Amazon",
    "00:04:20": "Slim Devices",
    "00:1f:33": "Nintendo",
    "00:09:bf": "Apple",
    "28:cf:da": "Apple",
}

DEVICE_SIGNATURES = {
    "router":    ["gateway", "router", "rt-", "dlink", "netgear", "tp-link", "asus", "linksys", "fritz"],
    "printer":   ["printer", "epson", "canon", "hp", "brother", "xerox", "ricoh"],
    "phone":     ["android", "iphone", "pixel", "samsung", "xiaomi", "huawei", "oneplus"],
    "smart_tv":  ["tv", "roku", "firetv", "chromecast", "appletv", "shield"],
    "iot":       ["esp", "arduino", "wemos", "tasmota", "shelly", "ring", "nest", "hue"],
    "nas":       ["synology", "qnap", "nas", "diskstation", "readynas"],
    "server":    ["server", "ubuntu", "debian", "centos", "proxmox", "truenas"],
    "laptop":    ["laptop", "macbook", "thinkpad", "notebook"],
    "desktop":   ["desktop", "pc", "workstation", "ryzen", "intel"],
    "raspberry": ["raspberry", "raspberrypi", "rpi"],
    "camera":    ["cam", "ipcam", "nvr", "dvr", "hikvision", "dahua"],
}


@dataclass
class Device:
    ip: str
    mac: str = "??:??:??:??:??:??"
    hostname: str = "Unknown"
    vendor: str = "Unknown"
    device_type: str = "unknown"
    is_gateway: bool = False
    is_alive: bool = True
    open_ports: List[int] = field(default_factory=list)
    last_seen: float = field(default_factory=time.time)
    response_time: float = 0.0

    def to_dict(self):
        return {
            'ip': self.ip,
            'mac': self.mac,
            'hostname': self.hostname,
            'vendor': self.vendor,
            'device_type': self.device_type,
            'is_gateway': self.is_gateway,
            'is_alive': self.is_alive,
            'open_ports': self.open_ports,
            'last_seen': self.last_seen,
        }


class NetworkScanner:
    def __init__(self, settings):
        self.settings = settings
        self.subnet = settings.subnet
        self.timeout = settings.scan_timeout
        self.max_threads = settings.max_threads
        self._gateway_ip = self._get_gateway()
        logger.info(f"Scanner initialized: subnet={self.subnet}, gateway={self._gateway_ip}")

    def _get_gateway(self) -> str:
        """Detect default gateway IP"""
        try:
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.startswith('default'):
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]
        except Exception:
            pass
        return "192.168.1.1"

    def _ping_host(self, ip: str) -> Optional[float]:
        """Ping a single host, return response time or None"""
        try:
            start = time.time()
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', str(ip)],
                capture_output=True, text=True, timeout=2
            )
            elapsed = (time.time() - start) * 1000
            if result.returncode == 0:
                return round(elapsed, 2)
        except (subprocess.TimeoutExpired, Exception):
            pass
        return None

    def _get_mac_from_arp(self, ip: str) -> str:
        """Read MAC from ARP cache"""
        try:
            result = subprocess.run(['arp', '-n', str(ip)], capture_output=True, text=True)
            match = re.search(r'([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}', result.stdout, re.IGNORECASE)
            if match:
                return match.group(0).upper()
        except Exception:
            pass
        return "??:??:??:??:??:??"

    def _resolve_hostname(self, ip: str) -> str:
        """Reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
            return hostname.split('.')[0]  # short name
        except Exception:
            return "Unknown"

    def _get_vendor(self, mac: str) -> str:
        """Lookup vendor from MAC OUI"""
        if mac == "??:??:??:??:??:??":
            return "Unknown"
        prefix = mac[:8].upper()
        return MAC_VENDORS.get(prefix, "Unknown")

    def _fingerprint_device(self, hostname: str, vendor: str, ip: str, open_ports: List[int]) -> str:
        """Determine device type from hostname, vendor and open ports"""
        combined = f"{hostname} {vendor}".lower()

        for dtype, keywords in DEVICE_SIGNATURES.items():
            if any(kw in combined for kw in keywords):
                return dtype

        # Port-based fingerprinting
        port_signatures = {
            80: "http_device", 443: "http_device",
            22: "server", 21: "server", 3389: "windows_pc",
            548: "apple_device", 5353: "mdns_device",
            8080: "http_device", 1883: "iot",
            9100: "printer", 631: "printer",
        }
        for port in open_ports:
            if port in port_signatures:
                return port_signatures[port]

        return "unknown"

    def _quick_port_scan(self, ip: str, ports=[22, 80, 443, 8080, 3389, 9100, 631]) -> List[int]:
        """Fast TCP connect scan on common ports"""
        open_ports = []
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex((str(ip), port))
                if result == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass
        return open_ports

    def _scan_single_host(self, ip: str) -> Optional[Device]:
        """Full scan pipeline for a single host"""
        response_time = self._ping_host(ip)
        if response_time is None:
            return None

        mac = self._get_mac_from_arp(ip)
        hostname = self._resolve_hostname(ip)
        vendor = self._get_vendor(mac)
        open_ports = self._quick_port_scan(ip)
        device_type = self._fingerprint_device(hostname, vendor, ip, open_ports)
        is_gateway = (ip == self._gateway_ip)

        device = Device(
            ip=str(ip),
            mac=mac,
            hostname=hostname,
            vendor=vendor,
            device_type=device_type,
            is_gateway=is_gateway,
            is_alive=True,
            open_ports=open_ports,
            response_time=response_time,
        )
        logger.info(f"Found device: {ip} | {hostname} | {mac} | {device_type}")
        return device

    def scan(self) -> List[Device]:
        """
        Scan the entire subnet using parallel threads.
        Returns list of alive Device objects.
        """
        network = ipaddress.IPv4Network(self.subnet, strict=False)
        hosts = list(network.hosts())

        print(f"\033[36m[~] Scanning {len(hosts)} hosts in {self.subnet}...\033[0m")
        devices = []
        lock = threading.Lock()

        def scan_wrapper(ip):
            device = self._scan_single_host(str(ip))
            if device:
                with lock:
                    devices.append(device)
                    print(f"\033[32m  [+] {device.ip:16s}  {device.hostname:20s}  {device.mac}  [{device.device_type}]\033[0m")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(scan_wrapper, ip) for ip in hosts]
            for f in as_completed(futures):
                pass  # results handled in callback

        # Always include gateway if not found
        gateway_found = any(d.ip == self._gateway_ip for d in devices)
        if not gateway_found:
            gateway = Device(
                ip=self._gateway_ip,
                hostname="Gateway",
                device_type="router",
                is_gateway=True,
            )
            devices.insert(0, gateway)

        logger.info(f"Scan complete: {len(devices)} devices found")
        return devices
