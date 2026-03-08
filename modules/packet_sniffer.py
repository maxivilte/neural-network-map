"""
modules/packet_sniffer.py
Captura de paquetes en tiempo real usando Scapy.
Detecta DNS, HTTP, ARP, ICMP y trafico general por dispositivo.
Auto-detecta la interfaz correcta en Windows.
"""

import threading
import time
import logging
from collections import defaultdict, deque
from typing import Dict, List, Callable

logger = logging.getLogger(__name__)

try:
    from scapy.all import sniff, ARP, DNS, DNSQR, IP, TCP, UDP, ICMP, Raw, get_if_list, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy no disponible")


def _autodetect_interface(preferred: str = None, subnet: str = "192.168.1") -> str:
    """
    Detecta automáticamente la interfaz de red correcta en Windows/Linux.
    Prioriza la interfaz que tenga una IP en la subnet indicada.
    """
    if not SCAPY_AVAILABLE:
        return preferred or "eth0"

    try:
        from scapy.all import get_if_list, get_if_addr
        interfaces = get_if_list()

        print(f"\033[36m[~] Interfaces disponibles: {len(interfaces)}\033[0m")

        # 1. Buscar interfaz con IP en la subnet objetivo
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and ip.startswith(subnet.rsplit('.', 1)[0]):
                    print(f"\033[32m[+] Interfaz detectada: {iface} ({ip})\033[0m")
                    return iface
            except Exception:
                continue

        # 2. Buscar interfaz con IP 192.168.x.x o 10.x.x.x
        for iface in interfaces:
            try:
                ip = get_if_addr(iface)
                if ip and (ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.")):
                    print(f"\033[32m[+] Interfaz detectada (fallback): {iface} ({ip})\033[0m")
                    return iface
            except Exception:
                continue

        # 3. Usar la interfaz por defecto de Scapy
        default = conf.iface
        if default:
            print(f"\033[33m[~] Usando interfaz default de Scapy: {default}\033[0m")
            return str(default)

        # 4. Usar la primera que no sea loopback
        for iface in interfaces:
            if "loopback" not in iface.lower() and "lo" != iface.lower():
                print(f"\033[33m[~] Usando primera interfaz disponible: {iface}\033[0m")
                return iface

    except Exception as e:
        print(f"\033[33m[~] Error en autodetección: {e}\033[0m")

    # Último recurso
    fallback = preferred or "Ethernet"
    print(f"\033[33m[~] Usando interfaz fallback: {fallback}\033[0m")
    return fallback


class PacketEvent:
    def __init__(self, src_ip, dst_ip, protocol, info="", size=0):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.info = info
        self.size = size
        self.timestamp = time.time()

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] {self.protocol:6s} {self.src_ip:16s} -> {self.dst_ip:16s} {self.info}"


class PacketSniffer:
    def __init__(self, settings):
        self.settings = settings
        self._running = False
        self._thread = None
        self._lock = threading.Lock()
        self.interface = None  # se asigna en start()

        # Subnet para autodetección
        self._subnet = getattr(settings, 'subnet', '192.168.1.0/24')
        self._subnet_prefix = self._subnet.rsplit('.', 1)[0] if self._subnet else "192.168.1"

        # Interfaz preferida desde settings (puede ser eth0, None, "auto", etc.)
        self._preferred_iface = getattr(settings, 'interface', None)
        if self._preferred_iface in (None, 'eth0', 'auto', ''):
            self._preferred_iface = None  # forzar autodetección

        # Historial de paquetes por IP
        self.events: deque = deque(maxlen=200)
        self.device_stats: Dict[str, Dict] = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'dns_queries': [],
            'protocols': defaultdict(int),
            'last_seen': 0,
        })

        # Callbacks para el renderer
        self.callbacks: List[Callable] = []

        # DPI Engine — asignado desde main.py
        self.dpi = None

        if not SCAPY_AVAILABLE:
            print("\033[31m[!] Scapy no disponible - sniffer desactivado\033[0m")

    def register_callback(self, cb: Callable):
        self.callbacks.append(cb)

    def _process_packet(self, pkt):
        try:
            src_ip = ""
            dst_ip = ""
            protocol = "OTHER"
            info = ""
            size = len(pkt)

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst

                if ICMP in pkt:
                    protocol = "ICMP"
                    info = "ping"

                elif TCP in pkt:
                    protocol = "TCP"
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport
                    if dport == 80 or sport == 80:
                        protocol = "HTTP"
                    elif dport == 443 or sport == 443:
                        protocol = "HTTPS"
                    elif dport == 22 or sport == 22:
                        protocol = "SSH"
                    elif dport == 3389 or sport == 3389:
                        protocol = "RDP"
                    info = f":{dport}"

                elif UDP in pkt:
                    protocol = "UDP"
                    if DNS in pkt and DNSQR in pkt:
                        protocol = "DNS"
                        try:
                            query = pkt[DNSQR].qname.decode('utf-8', errors='replace').rstrip('.')
                            info = query
                            with self._lock:
                                stats = self.device_stats[src_ip]
                                if query not in stats['dns_queries']:
                                    stats['dns_queries'].append(query)
                                    if len(stats['dns_queries']) > 20:
                                        stats['dns_queries'].pop(0)
                            # DPI: analizar dominio
                            if self.dpi:
                                self.dpi.process_dns(src_ip, query)
                        except Exception:
                            pass

            elif ARP in pkt:
                protocol = "ARP"
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                info = "who-has" if pkt[ARP].op == 1 else "is-at"

            if not src_ip:
                return

            event = PacketEvent(src_ip, dst_ip, protocol, info, size)

            with self._lock:
                self.events.append(event)
                stats = self.device_stats[src_ip]
                stats['packets'] += 1
                stats['bytes'] += size
                stats['protocols'][protocol] += 1
                stats['last_seen'] = time.time()

            # DPI: acumular tráfico
            if self.dpi and src_ip:
                self.dpi.process_traffic(src_ip, size)

            for cb in self.callbacks:
                try:
                    cb(event)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Error procesando paquete: {e}")

    def start(self):
        if not SCAPY_AVAILABLE:
            return

        # Autodetectar interfaz
        self.interface = _autodetect_interface(
            preferred=self._preferred_iface,
            subnet=self._subnet_prefix
        )

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()
        print(f"\033[32m[+] Sniffer iniciado en: {self.interface}\033[0m")

    def _sniff_loop(self):
        """Intenta sniffear en la interfaz detectada. Si falla, prueba sin especificar interfaz."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self._running
            )
        except Exception as e:
            print(f"\033[33m[~] Reintentando sniffer sin iface específica... ({e})\033[0m")
            try:
                # Fallback: sin especificar interfaz (Scapy elige la default)
                sniff(
                    prn=self._process_packet,
                    store=False,
                    stop_filter=lambda p: not self._running
                )
                print(f"\033[32m[+] Sniffer activo (interfaz default)\033[0m")
            except Exception as e2:
                logger.error(f"Error en sniffer fallback: {e2}")
                print(f"\033[31m[!] Sniffer desactivado: {e2}\033[0m")

    def stop(self):
        self._running = False

    def get_recent_events(self, limit=50) -> List[PacketEvent]:
        with self._lock:
            return list(self.events)[-limit:]

    def get_device_stats(self, ip: str) -> Dict:
        with self._lock:
            return dict(self.device_stats.get(ip, {}))

    def get_top_talkers(self, limit=5) -> List[tuple]:
        with self._lock:
            sorted_devices = sorted(
                self.device_stats.items(),
                key=lambda x: x[1]['bytes'],
                reverse=True
            )
            return [(ip, stats['bytes'], stats['packets']) for ip, stats in sorted_devices[:limit]]

    def get_active_protocols(self) -> Dict[str, int]:
        with self._lock:
            totals = defaultdict(int)
            for stats in self.device_stats.values():
                for proto, count in stats['protocols'].items():
                    totals[proto] += count
            return dict(totals)
