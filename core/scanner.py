"""
core/scanner.py - Windows Edition  FASE 2 + FIX
- OUI database IEEE extendida
- Nmap OS fingerprinting (-O) para detectar modelos exactos
- Nmap port scan (-sV) para servicios por puerto
- TTL fingerprinting como fallback
- Deep device identification CORREGIDA: PC/laptop/desktop toman prioridad sobre phone
"""

import socket
import subprocess
import threading
import re
import time
import logging
import json
import os
import urllib.request
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# ─── OUI Database extendida ───────────────────────────────────────────────────
OUI_BUILTIN: Dict[str, str] = {
    # TP-Link
    "1C:3C:D4": "TP-Link", "50:C7:BF": "TP-Link", "98:DA:C4": "TP-Link",
    "C4:E9:84": "TP-Link", "A0:F3:C1": "TP-Link", "B0:4E:26": "TP-Link",
    # Samsung — incluye placas de red para PCs (Realtek/Samsung)
    "FC:AA:14": "Samsung", "8C:F5:A3": "Samsung", "F4:42:8F": "Samsung",
    "CC:07:AB": "Samsung", "00:26:37": "Samsung", "18:67:B0": "Samsung",
    "A4:23:05": "Samsung", "84:38:38": "Samsung", "70:F9:27": "Samsung",
    "BC:20:A4": "Samsung", "E4:40:E2": "Samsung", "50:32:75": "Samsung",
    "FC:F1:36": "Samsung",
    # Apple
    "3C:22:FB": "Apple", "70:3E:AC": "Apple", "A4:C3:F0": "Apple",
    "F0:18:98": "Apple", "AC:BC:32": "Apple", "28:CF:E9": "Apple",
    "F4:F1:5A": "Apple", "00:CD:FE": "Apple", "8C:85:90": "Apple",
    "DC:2B:2A": "Apple", "A8:96:8A": "Apple",
    # Xiaomi
    "64:1C:B0": "Xiaomi", "0C:1D:AF": "Xiaomi", "F8:A4:5F": "Xiaomi",
    "28:6C:07": "Xiaomi", "AC:F7:F3": "Xiaomi", "34:CE:00": "Xiaomi",
    # Epson
    "A4:D7:3C": "Epson", "00:26:AB": "Epson", "AC:18:26": "Epson",
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    # Amazon
    "74:D4:35": "Amazon", "FC:65:DE": "Amazon", "40:B4:CD": "Amazon",
    "A4:08:EA": "Amazon", "68:37:E9": "Amazon",
    # Google
    "54:60:09": "Google", "F4:F5:D8": "Google", "3C:5A:B4": "Google",
    # Cisco
    "00:1D:60": "Cisco", "00:1E:49": "Cisco", "58:AC:78": "Cisco",
    # Huawei
    "00:46:4B": "Huawei", "04:C0:6F": "Huawei", "28:31:52": "Huawei",
    "9C:28:EF": "Huawei", "E0:19:54": "Huawei",
    # Realtek / Intel (PCs)
    "00:E0:4C": "Realtek", "52:54:00": "QEMU/KVM",
    "00:50:56": "VMware",  "00:0C:29": "VMware",
    "8C:8D:28": "Intel",
    # Nintendo
    "00:1F:33": "Nintendo", "00:19:FD": "Nintendo", "98:B6:E9": "Nintendo",
    # Philips Hue
    "00:17:88": "Philips Hue", "EC:B5:FA": "Signify",
    # Netgear
    "A0:40:A0": "Netgear", "20:E5:2A": "Netgear", "9C:3D:CF": "Netgear",
    # ASUS
    "10:BF:48": "ASUS", "2C:FD:A1": "ASUS", "AC:9E:17": "ASUS",
    # Motorola / Lenovo
    "AC:37:43": "Motorola", "8C:BE:BE": "Motorola",
    # OnePlus
    "AC:09:2F": "OnePlus", "94:65:2D": "OnePlus",
    # LG
    "A8:23:FE": "LG", "CC:2D:8C": "LG", "00:E0:91": "LG",
    # Sony
    "FC:0F:E6": "Sony", "30:17:C8": "Sony", "10:4F:A8": "Sony",
}

# ─── Firmas de dispositivos por keyword ───────────────────────────────────────
# ORDEN IMPORTA: se evalúan de arriba hacia abajo, primera coincidencia gana
DEVICE_SIGNATURES = {
    # PC/desktop primero — antes que phone — para evitar falsos positivos
    "windows_pc": ["windows", "microsoft windows", "win10", "win11", "desktop-", "workstation"],
    "laptop":     ["laptop", "macbook", "thinkpad", "notebook", "surface", "inspiron", "latitude"],
    "server":     ["server", "ubuntu", "debian", "proxmox", "esxi", "truenas", "centos", "fedora"],
    "raspberry":  ["raspberry", "raspberrypi", "rpi"],
    "nas":        ["synology", "qnap", "nas", "diskstation", "readynas"],
    "printer":    ["printer", "epson", "canon", "hp", "brother", "xerox", "epsonedc"],
    "camera":     ["cam", "ipcam", "nvr", "hikvision", "dahua", "reolink"],
    "smart_tv":   ["tv", "roku", "firetv", "chromecast", "appletv", "bravia", "webos", "tizen"],
    "iot":        ["esp", "arduino", "tasmota", "shelly", "ring", "nest", "hue", "alexa", "echo", "wemo"],
    "game":       ["playstation", "xbox", "nintendo", "ps4", "ps5"],
    "router":     ["gateway", "router", "dlink", "netgear", "tp-link", "asus", "linksys", "fritz", "tplink", "mikrotik", "ubiquiti"],
    # phone al final — solo si no matcheó nada arriba
    "phone":      ["android", "iphone", "pixel", "galaxy", "ipad", "redmi", "poco", "realme"],
}

# ─── Puertos que CONFIRMAN tipo de dispositivo (alta confianza) ───────────────
# Estos tienen prioridad sobre vendor-based guessing
PORT_DEVICE_MAP_HIGH = {
    5357:  "windows_pc",   # WSD — exclusivo de Windows
    3389:  "windows_pc",   # RDP — exclusivo de Windows
    135:   "windows_pc",   # RPC — exclusivo de Windows
    139:   "windows_pc",   # NetBIOS — exclusivo de Windows
    445:   "windows_pc",   # SMB — exclusivo de Windows
    9100:  "printer",      # RAW print
    631:   "printer",      # IPP
    62078: "iphone",       # iPhone sync
    548:   "apple_device", # AFP
    5353:  "apple_device", # mDNS (Apple)
    22:    "server",       # SSH
}

# Puertos de baja confianza (fallback)
PORT_DEVICE_MAP_LOW = {
    1900:  "iot",          # UPnP
    8443:  "router",
    8080:  "router",
}

# Servicios por puerto
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    137: "NetBIOS", 139: "SMB", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP/Print",
    1900: "UPnP", 3306: "MySQL", 3389: "RDP", 5000: "UPnP",
    5353: "mDNS", 5357: "WSD", 5900: "VNC", 6881: "BitTorrent",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9100: "Print-RAW", 62078: "iPhone-Sync",
}

# Vendors que son placas de red en PCs (no son el dispositivo en sí)
# Samsung, Realtek, Intel pueden ser la NIC de una PC Windows
PC_NIC_VENDORS = {"realtek", "intel", "samsung", "broadcom", "killer", "qualcomm"}


@dataclass
class Device:
    ip:             str
    mac:            str   = "??:??:??:??:??:??"
    hostname:       str   = "Unknown"
    vendor:         str   = "Unknown"
    device_type:    str   = "unknown"
    os_info:        str   = ""
    is_gateway:     bool  = False
    is_alive:       bool  = True
    open_ports:     List[int]        = field(default_factory=list)
    port_services:  Dict[int, str]   = field(default_factory=dict)
    last_seen:      float = field(default_factory=time.time)
    response_time:  float = 0.0
    ttl:            int   = 0

    def to_dict(self):
        return {
            'ip':            self.ip,
            'mac':           self.mac,
            'hostname':      self.hostname,
            'vendor':        self.vendor,
            'device_type':   self.device_type,
            'os_info':       self.os_info,
            'is_gateway':    self.is_gateway,
            'is_alive':      self.is_alive,
            'open_ports':    self.open_ports,
            'port_services': self.port_services,
            'last_seen':     self.last_seen,
            'ttl':           self.ttl,
        }


class NetworkScanner:
    def __init__(self, settings):
        self.settings    = settings
        self.subnet      = settings.subnet
        self.max_threads = settings.max_threads
        self._gateway_ip = self._get_gateway()
        self._nmap_path  = self._find_nmap()
        logger.info(f"Scanner: subnet={self.subnet}, nmap={'SI' if self._nmap_path else 'NO'}")
        if self._nmap_path:
            print(f"\033[32m[+] Nmap encontrado: {self._nmap_path}\033[0m")
        else:
            print(f"\033[33m[!] Nmap no encontrado — usando fingerprinting por puertos+TTL\033[0m")

    def _find_nmap(self) -> Optional[str]:
        candidates = [
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "nmap",
        ]
        for path in candidates:
            try:
                r = subprocess.run([path, "--version"], capture_output=True, timeout=3)
                if r.returncode == 0:
                    return path
            except Exception:
                pass
        return None

    def _get_gateway(self) -> str:
        try:
            result = subprocess.run(['ipconfig'], capture_output=True, text=True,
                                    encoding='cp1252', errors='replace')
            for line in result.stdout.splitlines():
                if 'puerta de enlace' in line.lower() or 'default gateway' in line.lower():
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass
        return "192.168.1.1"

    def _read_arp_table(self):
        devices = []
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True,
                                    encoding='cp1252', errors='replace')
            for line in result.stdout.splitlines():
                match = re.search(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})',
                    line, re.IGNORECASE
                )
                if match:
                    ip  = match.group(1)
                    mac = match.group(2).replace('-', ':').upper()
                    if (not ip.endswith('.255') and not ip.startswith('224.')
                            and not ip.startswith('239.') and ip != '255.255.255.255'):
                        devices.append((ip, mac))
        except Exception as e:
            logger.error(f"Error leyendo ARP: {e}")
        return devices

    def _resolve_hostname(self, ip: str) -> str:
        """Intenta resolver el nombre del dispositivo usando múltiples métodos."""
        # 1. NetBIOS — Windows PCs y algunos Smart TVs Samsung/LG (más confiable)
        name = self._resolve_netbios(ip)
        if name and name != "Unknown":
            return name
        # 2. DNS reverso estándar
        try:
            resolved = socket.gethostbyaddr(ip)[0]
            # Filtrar resultados inútiles tipo "192.168.1.x.in-addr.arpa"
            if 'in-addr' not in resolved and 'arpa' not in resolved:
                return resolved.split('.')[0]
        except Exception:
            pass
        # 3. SSDP/UPnP — Smart TVs, Chromecasts, routers
        name = self._resolve_ssdp(ip)
        if name and name != "Unknown":
            return name
        return "Unknown"

    def _resolve_netbios(self, ip: str) -> str:
        """Consulta NetBIOS Name Service (puerto 137 UDP)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.8)
            # NetBIOS Name Query Request (NBSTAT)
            query = (
                b'\xa1\xb2'
                b'\x00\x00'
                b'\x00\x01'
                b'\x00\x00\x00\x00\x00\x00'
                b'\x20'
                b'CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
                b'\x00'
                b'\x00\x21'
                b'\x00\x01'
            )
            s.sendto(query, (ip, 137))
            data, _ = s.recvfrom(1024)
            s.close()
            if len(data) > 57:
                num_names = data[56]
                offset = 57
                for _ in range(min(num_names, 10)):
                    if offset + 18 > len(data):
                        break
                    raw_name = data[offset:offset+15]
                    name_type = data[offset+15]
                    # Tipo 0x00 = nombre único de PC
                    if name_type == 0x00:
                        clean = raw_name.decode('ascii', errors='ignore').strip().replace('\x00', '').strip()
                        if clean and clean != '*' and len(clean) > 1:
                            return clean
                    offset += 18
        except Exception:
            pass
        return "Unknown"

    def _resolve_ssdp(self, ip: str) -> str:
        """Consulta UPnP para obtener el nombre amigable del dispositivo."""
        try:
            for port in [1900, 49152, 49153, 8080, 80]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((ip, port)) != 0:
                        s.close()
                        continue
                    s.close()
                    for path in ['/description.xml', '/rootDesc.xml',
                                 '/upnp/IGD.xml', '/device.xml']:
                        try:
                            url = f"http://{ip}:{port}{path}"
                            req = urllib.request.Request(
                                url, headers={'User-Agent': 'NNM/2.0'})
                            with urllib.request.urlopen(req, timeout=1) as resp:
                                content = resp.read(2048).decode('utf-8', errors='ignore')
                                m = re.search(
                                    r'<friendlyName>([^<]{2,40})</friendlyName>',
                                    content, re.IGNORECASE)
                                if m:
                                    return m.group(1).strip()
                                m = re.search(
                                    r'<modelName>([^<]{2,40})</modelName>',
                                    content, re.IGNORECASE)
                                if m:
                                    return m.group(1).strip()
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception:
            pass
        return "Unknown"

    def _get_vendor(self, mac: str) -> str:
        if '??' in mac:
            return "Unknown"
        prefix3 = mac[:8].upper()
        if prefix3 in OUI_BUILTIN:
            return OUI_BUILTIN[prefix3]
        prefix2 = mac[:5].upper()
        for k, v in OUI_BUILTIN.items():
            if k.startswith(prefix2):
                return v
        return "Unknown"

    def _get_ttl(self, ip: str) -> int:
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True, text=True,
                encoding='cp1252', errors='replace', timeout=3
            )
            match = re.search(r'TTL[=:](\d+)', result.stdout, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return 0

    def _fingerprint_by_ttl(self, ttl: int) -> str:
        if ttl == 0:
            return ""
        if ttl <= 64:
            return "Linux/Android"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "iOS/macOS/Router"
        return ""

    def _fingerprint_device(self, hostname: str, vendor: str, ip: str,
                             open_ports: List[int], os_info: str, ttl: int) -> str:
        """
        Identificación de tipo de dispositivo — LÓGICA MEJORADA.

        Orden de prioridad (de mayor a menor confianza):
        1. OS info de Nmap (texto exacto del OS detectado)
        2. Puertos de ALTA confianza (5357=Windows, 3389=RDP, etc.)
        3. Hostname (DESKTOP-, LAPTOP-, SERVER-, etc.)
        4. Combinación OS info + keyword matching
        5. TTL (solo si nada más dio resultado)
        6. Vendor como último recurso (con restricciones para PC_NIC_VENDORS)
        """

        os_lower       = os_info.lower()
        hostname_lower = hostname.lower()
        vendor_lower   = vendor.lower()

        # ── 1. OS INFO DE NMAP — máxima confianza ────────────────────────────
        if os_info:
            if any(x in os_lower for x in ["windows", "microsoft"]):
                return "windows_pc"
            if any(x in os_lower for x in ["ubuntu", "debian", "centos", "fedora", "proxmox", "esxi", "truenas"]):
                return "server"
            if any(x in os_lower for x in ["mac os", "macos", "os x"]):
                return "laptop"   # MacBook
            if "ios" in os_lower and "router" not in os_lower:
                return "iphone"
            if "android" in os_lower:
                return "phone"
            if any(x in os_lower for x in ["raspberry", "raspbian"]):
                return "raspberry"
            if any(x in os_lower for x in ["router", "openwrt", "dd-wrt", "mikrotik", "routeros"]):
                return "router"
            if any(x in os_lower for x in ["linux"]):
                # Linux genérico — NO asumir phone, puede ser router, server o PC
                # Decidir por puertos y hostname
                pass  # continúa a los siguientes pasos

        # ── 2. PUERTOS DE ALTA CONFIANZA ─────────────────────────────────────
        for port in open_ports:
            if port in PORT_DEVICE_MAP_HIGH:
                return PORT_DEVICE_MAP_HIGH[port]

        # ── 3. HOSTNAME — muy confiable ───────────────────────────────────────
        if hostname_lower != "unknown":
            # Patrones de hostname de Windows
            if re.match(r'^desktop-[a-z0-9]+$', hostname_lower):
                return "windows_pc"
            if re.match(r'^laptop-[a-z0-9]+$', hostname_lower):
                return "laptop"
            if re.match(r'^server-[a-z0-9]+$', hostname_lower) or 'server' in hostname_lower:
                return "server"
            # Buscar en firmas
            for dtype, keywords in DEVICE_SIGNATURES.items():
                if any(kw in hostname_lower for kw in keywords):
                    return dtype

        # ── 4. KEYWORD MATCHING en OS info ───────────────────────────────────
        if os_info:
            for dtype, keywords in DEVICE_SIGNATURES.items():
                if any(kw in os_lower for kw in keywords):
                    return dtype

        # ── 5. TTL fingerprinting ─────────────────────────────────────────────
        if ttl > 0:
            ttl_os = self._fingerprint_by_ttl(ttl)
            if "windows" in ttl_os.lower():
                return "windows_pc"
            # Linux/Android por TTL es ambiguo — NO retornar "phone" todavía
            # porque puede ser un router o PC Linux

        # ── 6. VENDOR — último recurso con lógica mejorada ───────────────────
        if vendor != "Unknown":
            # Si el vendor es una NIC de PC (Samsung, Realtek, Intel)
            # Y el TTL indica Windows → es una PC, no un teléfono
            if any(x in vendor_lower for x in PC_NIC_VENDORS):
                ttl_os = self._fingerprint_by_ttl(ttl)
                if "windows" in ttl_os.lower() or ttl > 100:
                    return "windows_pc"
                # Si TTL es Linux y el vendor es Samsung → podría ser phone O PC
                # Usar puertos de baja confianza como desempate
                for port in open_ports:
                    if port in PORT_DEVICE_MAP_LOW:
                        return PORT_DEVICE_MAP_LOW[port]
                # Sin más info → unknown es mejor que phone incorrecto
                return "unknown"

            # Vendors que SÍ indican teléfono con alta confianza
            if any(x in vendor_lower for x in ["xiaomi", "huawei", "oneplus", "motorola", "lg"]):
                # Pero si tiene puertos de Windows → es PC
                if any(p in open_ports for p in [5357, 3389, 135, 445]):
                    return "windows_pc"
                return "phone"

            if any(x in vendor_lower for x in ["epson", "canon", "brother", "xerox"]):
                return "printer"
            if any(x in vendor_lower for x in ["tp-link", "netgear", "cisco", "ubiquiti", "mikrotik"]):
                return "router"
            if any(x in vendor_lower for x in ["raspberry"]):
                return "raspberry"
            if any(x in vendor_lower for x in ["amazon"]):
                return "iot"
            if any(x in vendor_lower for x in ["apple"]):
                # Apple puede ser MacBook, iPhone, iPad
                if any(p in open_ports for p in [62078]):
                    return "iphone"
                return "laptop"  # default Apple → MacBook

        # ── 7. Linux/Android por TTL — ahora sí, como último recurso ─────────
        if ttl > 0:
            ttl_os = self._fingerprint_by_ttl(ttl)
            if "android" in ttl_os.lower() or "linux" in ttl_os.lower():
                # Si no tiene ningún puerto abierto conocido → phone es razonable
                if not open_ports:
                    return "phone"

        return "unknown"

    def _nmap_scan(self, ip: str) -> dict:
        if not self._nmap_path:
            return {}
        try:
            result = subprocess.run(
                [self._nmap_path, '-O', '--osscan-guess',
                 '-sV', '--version-intensity', '3',
                 '-T4', '--open',
                 '-p', '21,22,23,25,53,80,110,135,137,139,143,443,445,548,'
                       '554,631,1900,3306,3389,5000,5353,5357,5900,8080,8443,9100,62078',
                 ip],
                capture_output=True, text=True,
                encoding='utf-8', errors='replace', timeout=30
            )
            output = result.stdout
            info   = {}

            os_match = re.search(r'OS details:\s*(.+)', output)
            if os_match:
                info['os_info'] = os_match.group(1).strip()
            else:
                ag_match = re.search(r'Aggressive OS guesses:\s*(.+?)(?:\n|$)', output)
                if ag_match:
                    first = ag_match.group(1).split(',')[0].strip()
                    first = re.sub(r'\s*\(\d+%\)', '', first).strip()
                    info['os_info'] = first

            open_ports    = []
            port_services = {}
            for m in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', output):
                port    = int(m.group(1))
                service = m.group(2)
                version = (m.group(3) or "").strip()
                open_ports.append(port)
                label = service.upper()
                if version:
                    version = version.split(' ')[0] + (' ' + version.split(' ')[1] if len(version.split(' ')) > 1 else '')
                    label = f"{service.upper()} {version[:20]}"
                port_services[port] = label

            info['open_ports']    = open_ports
            info['port_services'] = port_services
            return info

        except subprocess.TimeoutExpired:
            logger.warning(f"Nmap timeout en {ip}")
            return {}
        except Exception as e:
            logger.error(f"Error nmap en {ip}: {e}")
            return {}

    def _quick_port_scan(self, ip: str) -> tuple:
        ports = [21, 22, 80, 135, 139, 443, 445, 548, 631, 1900, 3389, 5353, 5357, 8080, 9100, 62078]
        open_ports    = []
        port_services = {}
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
                    port_services[port] = PORT_SERVICES.get(port, f"PORT-{port}")
                s.close()
            except Exception:
                pass
        return open_ports, port_services

    def _enrich_device(self, ip: str, mac: str) -> Device:
        hostname = self._resolve_hostname(ip)
        vendor   = self._get_vendor(mac)
        ttl      = self._get_ttl(ip)
        ttl_os   = self._fingerprint_by_ttl(ttl)

        if self._nmap_path:
            nmap_data     = self._nmap_scan(ip)
            open_ports    = nmap_data.get('open_ports', [])
            port_services = nmap_data.get('port_services', {})
            os_info       = nmap_data.get('os_info', ttl_os)
        else:
            open_ports, port_services = self._quick_port_scan(ip)
            os_info = ttl_os

        device_type = self._fingerprint_device(hostname, vendor, ip, open_ports, os_info, ttl)
        is_gateway  = (ip == self._gateway_ip)

        device = Device(
            ip=ip, mac=mac, hostname=hostname, vendor=vendor,
            device_type=device_type, os_info=os_info,
            is_gateway=is_gateway, open_ports=open_ports,
            port_services=port_services, ttl=ttl,
        )

        os_str = f" | {os_info[:30]}" if os_info else ""
        print(f"\033[32m  [+] {ip:16s}  {hostname:20s}  {vendor:15s}  [{device_type}]{os_str}\033[0m")
        return device

    def nmap_scan_device(self, ip: str) -> dict:
        """Scan profundo ON-DEMAND para un dispositivo específico."""
        if not self._nmap_path:
            _, port_services = self._quick_port_scan(ip)
            return {'open_ports': list(port_services.keys()), 'port_services': port_services, 'os_info': ''}
        try:
            print(f"\033[36m[~] Nmap deep scan: {ip}...\033[0m")
            result = subprocess.run(
                [self._nmap_path, '-O', '--osscan-guess',
                 '-sV', '--version-intensity', '5',
                 '-T4', '--open', '-p', '1-1024,3389,5900,8080,8443,9100,62078',
                 ip],
                capture_output=True, text=True,
                encoding='utf-8', errors='replace', timeout=60
            )
            output = result.stdout
            info   = {'raw': output}

            os_match = re.search(r'OS details:\s*(.+)', output)
            if os_match:
                info['os_info'] = os_match.group(1).strip()
            else:
                ag = re.search(r'Aggressive OS guesses:\s*(.+?)(?:\n|$)', output)
                if ag:
                    first = ag.group(1).split(',')[0].strip()
                    first = re.sub(r'\s*\(\d+%\)', '', first).strip()
                    info['os_info'] = first
                else:
                    info['os_info'] = ''

            # Re-fingerprint con la nueva info
            open_ports    = []
            port_services = {}
            for m in re.finditer(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?', output):
                port    = int(m.group(1))
                service = m.group(2)
                version = (m.group(3) or "").strip()
                open_ports.append(port)
                label = f"{service.upper()}"
                if version:
                    label += f" {version[:25]}"
                port_services[port] = label

            info['open_ports']    = open_ports
            info['port_services'] = port_services
            return info

        except subprocess.TimeoutExpired:
            return {'os_info': 'Timeout', 'open_ports': [], 'port_services': {}}
        except Exception as e:
            return {'os_info': f'Error: {e}', 'open_ports': [], 'port_services': {}}

    def scan(self) -> List[Device]:
        print(f"\033[36m[~] Ping sweep a {self.subnet}...\033[0m")
        base_ip = self.subnet.rsplit('.', 1)[0]

        def ping_silent(i):
            subprocess.run(
                ['ping', '-n', '1', '-w', '300', f"{base_ip}.{i}"],
                capture_output=True, timeout=1
            )

        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            list(ex.map(ping_silent, range(1, 255)))

        arp_entries = self._read_arp_table()
        print(f"\033[36m[~] ARP table: {len(arp_entries)} entradas encontradas\033[0m")

        gateway_in = any(ip == self._gateway_ip for ip, _ in arp_entries)
        if not gateway_in:
            arp_entries.insert(0, (self._gateway_ip, "??:??:??:??:??:??"))

        devices = []
        lock    = threading.Lock()

        def enrich(entry):
            ip, mac = entry
            device  = self._enrich_device(ip, mac)
            with lock:
                devices.append(device)

        with ThreadPoolExecutor(max_workers=16) as ex:
            list(ex.map(enrich, arp_entries))

        devices.sort(key=lambda d: (not d.is_gateway, list(map(int, d.ip.split('.')))))
        logger.info(f"Scan completo: {len(devices)} dispositivos")
        return devices
