"""
plugins/plugin_manager.py
FASE 7 + FASE 11 — Sistema de Plugins v2 para Neural Network Map v2.0

NUEVO en Fase 11:
  - Hooks: on_packet(pkt), on_device_new(dev), on_alert(alert), on_tick()
  - Plugins externos desde carpetas con plugin.json + main.py
  - Carga dinámica de plugins externos en plugins/external/
  - EventBus central para comunicación entre plugins
  - Plugin: DNSMonitor — detecta dominios sospechosos en tiempo real
  - Plugin: MalwareTraffic — detecta patrones de tráfico malware
"""

import time
import json
import logging
import threading
import os
import socket
import urllib.request
import urllib.parse
import importlib.util
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Callable

logger = logging.getLogger(__name__)


# ─── EventBus (NUEVO Fase 11) ─────────────────────────────────────────────────

class EventBus:
    """
    Bus de eventos central. Todos los plugins pueden publicar y suscribirse.
    Permite comunicación entre plugins sin acoplamiento directo.
    """
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable):
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(callback)

    def publish(self, event_type: str, data: Any = None):
        with self._lock:
            callbacks = list(self._subscribers.get(event_type, []))
        for cb in callbacks:
            try:
                cb(data)
            except Exception as e:
                logger.error(f"[EventBus] Error en subscriber {event_type}: {e}")

    def get_event_types(self) -> List[str]:
        with self._lock:
            return list(self._subscribers.keys())


# Instancia global del bus
_event_bus = EventBus()


# ─── Base Plugin v2 ───────────────────────────────────────────────────────────

class BasePlugin(ABC):
    name        = "BasePlugin"
    description = "Plugin base"
    version     = "2.0"

    def __init__(self, settings, db=None, ids=None, dpi=None, graph=None, sniffer=None):
        self.settings = settings
        self.db       = db
        self.ids      = ids
        self.dpi      = dpi
        self.graph    = graph
        self.sniffer  = sniffer   # NUEVO Fase 11
        self.enabled  = True
        self.status   = "idle"
        self._thread  = None
        self.event_bus = _event_bus  # acceso al bus global

    def start(self):
        if not self.enabled:
            return
        self.status  = "running"
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        logger.info(f"[Plugin] {self.name} iniciado")
        print(f"\033[36m[Plugin] {self.name} iniciado\033[0m")

    def _run_loop(self):
        pass

    # ── Hooks v1 (compatibilidad) ──────────────────────────────────────────
    def on_ids_alert(self, alert):
        pass

    def on_new_device(self, device):
        pass

    def on_device_left(self, ip: str):
        pass

    # ── Hooks v2 (NUEVO Fase 11) ───────────────────────────────────────────
    def on_packet(self, packet):
        """Llamado por cada paquete capturado por el sniffer."""
        pass

    def on_alert(self, alert):
        """Alias de on_ids_alert para compatibilidad v2."""
        self.on_ids_alert(alert)

    def on_tick(self):
        """Llamado cada 30 segundos — útil para chequeos periódicos."""
        pass

    def on_threat_detected(self, ip: str, result: dict):
        """Llamado cuando Threat Intel detecta una IP maliciosa."""
        pass


# ─── Plugin: GeoIP ───────────────────────────────────────────────────────────

class GeoIPPlugin(BasePlugin):
    """
    Geolocaliza IPs externas detectadas por el DPI.
    Usa la API pública ip-api.com (sin key, 45 req/min gratis).
    Los resultados se cachean en memoria y en disco.
    """
    name        = "GeoIP"
    description = "Geolocaliza IPs externas detectadas en el tráfico"

    # IPs privadas — no se geolocaliza
    PRIVATE_RANGES = [
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "0.", "169.254.", "224.", "255.",
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache: Dict[str, dict] = {}
        self._cache_file = "logs/geoip_cache.json"
        self._load_cache()
        self._queue = []
        self._lock  = threading.Lock()

    def _load_cache(self):
        try:
            if os.path.exists(self._cache_file):
                with open(self._cache_file, 'r') as f:
                    self._cache = json.load(f)
                print(f"\033[36m[GeoIP] Cache cargado: {len(self._cache)} IPs\033[0m")
        except Exception:
            pass

    def _save_cache(self):
        try:
            os.makedirs("logs", exist_ok=True)
            with open(self._cache_file, 'w') as f:
                json.dump(self._cache, f, indent=2)
        except Exception:
            pass

    def _is_private(self, ip: str) -> bool:
        return any(ip.startswith(prefix) for prefix in self.PRIVATE_RANGES)

    def lookup(self, ip: str) -> Optional[dict]:
        """Retorna info geográfica del IP. Usa cache si disponible."""
        if self._is_private(ip):
            return None
        if ip in self._cache:
            return self._cache[ip]

        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org,lat,lon"
            req = urllib.request.Request(url, headers={'User-Agent': 'NeuralNetworkMap/2.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get('status') == 'success':
                    result = {
                        'ip':      ip,
                        'country': data.get('country', ''),
                        'code':    data.get('countryCode', ''),
                        'city':    data.get('city', ''),
                        'isp':     data.get('isp', ''),
                        'org':     data.get('org', ''),
                        'lat':     data.get('lat', 0),
                        'lon':     data.get('lon', 0),
                        'flag':    self._country_flag(data.get('countryCode', '')),
                    }
                    with self._lock:
                        self._cache[ip] = result
                    self._save_cache()
                    return result
        except Exception as e:
            logger.debug(f"[GeoIP] Error lookup {ip}: {e}")
        return None

    def _country_flag(self, code: str) -> str:
        """Convierte código de país a emoji de bandera."""
        if len(code) != 2:
            return "🌐"
        return chr(0x1F1E6 + ord(code[0]) - ord('A')) + chr(0x1F1E6 + ord(code[1]) - ord('A'))

    def get_map_data(self) -> List[dict]:
        """Retorna todas las IPs geolocalizadas para el mapa."""
        with self._lock:
            return list(self._cache.values())

    def get_ip_info(self, ip: str) -> Optional[dict]:
        """Obtiene info de un IP específico (con lookup si no está en cache)."""
        if ip in self._cache:
            return self._cache[ip]
        return self.lookup(ip)

    def _run_loop(self):
        """Geolocaliza IPs externas detectadas por el DPI en background."""
        # Espera inicial corta para que el sniffer capture algunas IPs
        time.sleep(5)
        while True:
            try:
                if self.dpi:
                    # Obtener IPs externas del DPI
                    external_ips = getattr(self.dpi, '_external_ips', set())
                    new_count = 0
                    for ip in list(external_ips):
                        if ip not in self._cache and not self._is_private(ip):
                            result = self.lookup(ip)
                            if result:
                                new_count += 1
                                print(f"\033[36m[GeoIP] {ip} → {result.get('country','')} {result.get('flag','')}\033[0m")
                            time.sleep(1.5)  # rate limit: 45 req/min
                    if new_count > 0:
                        print(f"\033[36m[GeoIP] {new_count} IPs nuevas — cache total: {len(self._cache)}\033[0m")
            except Exception as e:
                logger.error(f"[GeoIP] Error en loop: {e}")
            time.sleep(20)


# ─── Plugin: Telegram ─────────────────────────────────────────────────────────

class TelegramPlugin(BasePlugin):
    """
    Envía alertas del IDS por Telegram.

    Configurar en settings o variables de entorno:
        TELEGRAM_BOT_TOKEN=xxx
        TELEGRAM_CHAT_ID=yyy

    O directamente:
        plugin.configure(bot_token="xxx", chat_id="yyy")
    """
    name        = "Telegram"
    description = "Envía alertas IDS críticas por Telegram"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
        self.chat_id   = os.environ.get('TELEGRAM_CHAT_ID', '')
        self._queue    = []
        self._lock     = threading.Lock()
        self._last_sent = 0
        self._min_interval = 30  # mínimo 30s entre mensajes

    def configure(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id   = chat_id
        print(f"\033[32m[Telegram] Configurado ✓\033[0m")

    def _is_configured(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send(self, message: str) -> bool:
        """Envía un mensaje por Telegram."""
        if not self._is_configured():
            logger.warning("[Telegram] No configurado — falta BOT_TOKEN o CHAT_ID")
            return False

        # Rate limiting
        now = time.time()
        if now - self._last_sent < self._min_interval:
            return False

        try:
            url  = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id':    self.chat_id,
                'text':       message,
                'parse_mode': 'HTML',
            }).encode()
            req  = urllib.request.Request(url, data=data)
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read().decode())
                if result.get('ok'):
                    self._last_sent = now
                    logger.info(f"[Telegram] Mensaje enviado")
                    return True
        except Exception as e:
            logger.error(f"[Telegram] Error enviando mensaje: {e}")
        return False

    def on_ids_alert(self, alert):
        """Envía alerta por Telegram solo si es CRITICAL o WARN."""
        if alert.severity not in ('CRITICAL', 'WARN'):
            return

        ts  = time.strftime('%H:%M:%S', time.localtime(alert.timestamp))
        sev = "🔴 CRÍTICO" if alert.severity == 'CRITICAL' else "🟡 ADVERTENCIA"

        msg = (
            f"<b>⬡ NEURAL NETWORK MAP</b>\n"
            f"{sev}\n\n"
            f"⏰ {ts}\n"
            f"📍 IP: <code>{alert.ip}</code>\n"
            f"{alert.icon} {alert.message}"
        )

        with self._lock:
            self._queue.append(msg)

    def on_new_device(self, device):
        """Notifica cuando aparece un dispositivo nuevo."""
        msg = (
            f"<b>⬡ NEURAL NETWORK MAP</b>\n"
            f"🆕 Nuevo dispositivo detectado\n\n"
            f"📍 IP: <code>{device.ip}</code>\n"
            f"🏷 Vendor: {device.vendor}\n"
            f"💻 Tipo: {device.device_type}"
        )
        with self._lock:
            self._queue.append(msg)

    def _run_loop(self):
        """Procesa la cola de mensajes."""
        while True:
            with self._lock:
                if self._queue:
                    msg = self._queue.pop(0)
            if 'msg' in dir():
                self.send(msg)
                del msg
            time.sleep(5)


# ─── Plugin: BandwidthAlert ───────────────────────────────────────────────────

class BandwidthAlertPlugin(BasePlugin):
    """
    Alerta cuando un dispositivo supera un umbral de ancho de banda.
    Configurable por dispositivo o umbral global.
    """
    name        = "BandwidthAlert"
    description = "Alerta cuando un dispositivo supera X MB/s de tráfico"

    def __init__(self, *args, threshold_mb=10, **kwargs):
        super().__init__(*args, **kwargs)
        self.threshold_bytes = threshold_mb * 1024 * 1024
        self._alerted: Dict[str, float] = {}  # ip -> último tiempo de alerta
        self._cooldown = 300  # 5 minutos entre alertas del mismo dispositivo

    def _run_loop(self):
        """Monitorea el tráfico por dispositivo cada 10 segundos."""
        while True:
            time.sleep(10)
            try:
                if not self.dpi:
                    continue
                now = time.time()
                for ip, bytes_total in self.dpi.get_top_talkers(20):
                    # Verificar cooldown
                    if now - self._alerted.get(ip, 0) < self._cooldown:
                        continue
                    # Verificar umbral (bytes_total es acumulado, comparar con ventana)
                    rate = getattr(self.dpi, 'get_device_rate', lambda x: 0)(ip)
                    if rate > self.threshold_bytes:
                        self._alerted[ip] = now
                        human = f"{rate / 1024 / 1024:.1f} MB/s"
                        dev   = self.graph.get_device_info(ip) if self.graph else {}
                        host  = dev.get('hostname', ip)
                        msg   = f"Tráfico alto: {host} ({ip}) → {human}"
                        logger.warning(f"[BandwidthAlert] {msg}")
                        print(f"\033[33m[BandwidthAlert] {msg}\033[0m")
                        # Crear alerta en IDS si está disponible
                        if self.ids and hasattr(self.ids, '_create_alert'):
                            self.ids._create_alert(ip, "WARN", msg, "📶")
            except Exception as e:
                logger.error(f"[BandwidthAlert] Error: {e}")


# ─── Plugin: PortAlert ────────────────────────────────────────────────────────

class PortAlertPlugin(BasePlugin):
    """
    Alerta cuando un dispositivo abre un puerto que antes no tenía.
    Útil para detectar servicios nuevos o backdoors.
    """
    name        = "PortAlert"
    description = "Alerta cuando un dispositivo abre un nuevo puerto"

    # Puertos sospechosos que siempre alertan
    SUSPICIOUS_PORTS = {
        23: "Telnet (inseguro)",
        4444: "Metasploit",
        5900: "VNC expuesto",
        6666: "IRC/Malware",
        31337: "Back Orifice",
        12345: "NetBus",
        1337: "Hacking port",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._known_ports: Dict[str, set] = {}  # ip -> set de puertos conocidos

    def register_baseline(self, devices):
        """Registra el baseline de puertos conocidos al iniciar."""
        for dev in devices:
            self._known_ports[dev.ip] = set(dev.open_ports)
        print(f"\033[36m[PortAlert] Baseline: {len(self._known_ports)} dispositivos registrados\033[0m")

    def check_device(self, ip: str, current_ports: List[int]):
        """Compara puertos actuales con el baseline."""
        known    = self._known_ports.get(ip, set())
        new_ports = set(current_ports) - known

        for port in new_ports:
            if port in self.SUSPICIOUS_PORTS:
                msg = f"Puerto SOSPECHOSO abierto en {ip}: {port} ({self.SUSPICIOUS_PORTS[port]})"
                severity = "CRITICAL"
                icon = "🚨"
            else:
                svc_name = f":{port}"
                msg      = f"Nuevo puerto abierto en {ip}: {port}{svc_name}"
                severity = "WARN"
                icon     = "🔓"

            logger.warning(f"[PortAlert] {msg}")
            print(f"\033[33m[PortAlert] {msg}\033[0m")

            if self.ids and hasattr(self.ids, '_create_alert'):
                self.ids._create_alert(ip, severity, msg, icon)

        # Actualizar known
        self._known_ports[ip] = set(current_ports)


# ─── Plugin: AutoReport ───────────────────────────────────────────────────────

class AutoReportPlugin(BasePlugin):
    """
    Genera un reporte HTML de la sesión automáticamente.
    Por defecto cada 24 horas, guardado en logs/reports/.
    """
    name        = "AutoReport"
    description = "Genera reporte HTML diario de la red"

    def __init__(self, *args, interval_hours=24, **kwargs):
        super().__init__(*args, **kwargs)
        self.interval = interval_hours * 3600
        os.makedirs("logs/reports", exist_ok=True)

    def generate_report(self) -> str:
        """Genera el reporte HTML y retorna la ruta del archivo."""
        now      = time.strftime('%Y-%m-%d_%H-%M-%S')
        filename = f"logs/reports/nnm_report_{now}.html"

        devices    = self.db.get_all_devices() if self.db else []
        summary    = self.db.get_summary()     if self.db else {}
        alert_stat = self.db.get_alert_stats() if self.db else {}

        # Top servicios DPI
        top_svcs = []
        if self.dpi:
            top_svcs = self.dpi.get_top_services(10)

        # Top talkers
        top_talkers = []
        if self.dpi:
            top_talkers = self.dpi.get_top_talkers(10)

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>NNM Report — {now}</title>
<style>
  body {{ font-family: monospace; background: #05050f; color: #b4ffff; padding: 20px; }}
  h1   {{ color: #ff3c78; }}
  h2   {{ color: #00c8ff; border-bottom: 1px solid #00c8ff; padding-bottom: 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
  th   {{ background: #0a1a2a; color: #00c8ff; padding: 8px; text-align: left; }}
  td   {{ padding: 6px 8px; border-bottom: 1px solid #0a1a2a; }}
  tr:hover {{ background: #0a1020; }}
  .active  {{ color: #00ffa0; }}
  .offline {{ color: #666; }}
  .crit    {{ color: #ff3c78; }}
  .warn    {{ color: #ffcc00; }}
  .stat    {{ display: inline-block; background: #0a1a2a; padding: 12px 24px;
              margin: 8px; border: 1px solid #00c8ff; border-radius: 4px; }}
  .stat-n  {{ font-size: 2em; color: #00c8ff; display: block; }}
</style>
</head>
<body>
<h1>⬡ NEURAL NETWORK MAP — Reporte</h1>
<p>Generado: {time.strftime('%d/%m/%Y %H:%M:%S')}</p>

<h2>Resumen</h2>
<span class="stat"><span class="stat-n">{summary.get('total_devices', 0)}</span>Dispositivos</span>
<span class="stat"><span class="stat-n">{summary.get('active_devices', 0)}</span>Activos</span>
<span class="stat"><span class="stat-n">{alert_stat.get('total', 0)}</span>Alertas totales</span>
<span class="stat"><span class="stat-n">{alert_stat.get('today', 0)}</span>Alertas hoy</span>

<h2>Dispositivos en la Red</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Tipo</th><th>OS</th><th>Estado</th><th>Visto</th></tr>
"""
        for dev in devices:
            status   = dev.get('status', 'offline')
            sc       = 'active' if status == 'active' else 'offline'
            seen     = time.strftime('%d/%m %H:%M', time.localtime(dev.get('last_seen', 0)))
            html += f"""<tr>
  <td>{dev.get('ip','')}</td>
  <td>{dev.get('hostname','Unknown')}</td>
  <td>{dev.get('vendor','Unknown')}</td>
  <td>{dev.get('device_type','unknown')}</td>
  <td>{dev.get('os_info','')[:40]}</td>
  <td class="{sc}">{status.upper()}</td>
  <td>{seen}</td>
</tr>"""

        html += "</table>\n<h2>Top Servicios (DPI)</h2>\n<table><tr><th>Servicio</th><th>Detecciones</th></tr>\n"
        for svc, count in top_svcs:
            html += f"<tr><td>{svc}</td><td>{count}</td></tr>\n"

        html += "</table>\n<h2>Top Talkers (Tráfico)</h2>\n<table><tr><th>IP</th><th>Bytes</th></tr>\n"
        for ip, bytes_ in top_talkers:
            human = f"{bytes_ / 1024 / 1024:.1f} MB"
            html += f"<tr><td>{ip}</td><td>{human}</td></tr>\n"

        html += f"\n</table>\n<p style='color:#406070'>Neural Network Map v2.0 — {time.strftime('%Y')}</p>\n</body>\n</html>"

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"\033[32m[AutoReport] Reporte generado: {filename}\033[0m")
        logger.info(f"[AutoReport] Reporte: {filename}")
        return filename

    def _run_loop(self):
        while True:
            time.sleep(self.interval)
            try:
                self.generate_report()
            except Exception as e:
                logger.error(f"[AutoReport] Error generando reporte: {e}")


# ─── Plugin: DNS Monitor (NUEVO Fase 11) ──────────────────────────────────────

class DNSMonitorPlugin(BasePlugin):
    """Monitorea consultas DNS y detecta dominios sospechosos (DGA, TLDs maliciosos, túneles)."""
    name        = "DNSMonitor"
    description = "Detecta dominios DNS sospechosos en tiempo real"

    SUSPICIOUS_TLDS = {'.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.pw', '.click'}
    WHITELIST = {
        'google.com', 'googleapis.com', 'gstatic.com', 'youtube.com',
        'cloudflare.com', 'amazonaws.com', 'microsoft.com', 'windows.com',
        'apple.com', 'icloud.com', 'facebook.com', 'instagram.com',
        'tiktok.com', 'twitch.tv', 'netflix.com', 'spotify.com',
        'whatsapp.com', 'telegram.org', 'github.com', 'windowsupdate.com',
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._alerted: Dict[str, float] = {}
        self._cooldown = 300

    def _is_suspicious_dga(self, name: str) -> bool:
        if len(name) < 8:
            return False
        consonants = sum(1 for c in name.lower() if c in 'bcdfghjklmnpqrstvwxyz')
        if consonants / max(len(name), 1) > 0.75 and len(name) > 10:
            return True
        if sum(1 for c in name if c.isdigit()) > 4 and len(name) > 12:
            return True
        return False

    def check_domain(self, ip: str, domain: str):
        if not domain:
            return
        domain = domain.lower().rstrip('.')
        now = time.time()
        for safe in self.WHITELIST:
            if domain.endswith(safe):
                return
        if now - self._alerted.get(domain, 0) < self._cooldown:
            return
        reasons = []
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"TLD sospechoso: {tld}")
                break
        parts = domain.split('.')
        if parts and self._is_suspicious_dga(parts[0]):
            reasons.append("Posible dominio DGA")
        if len(domain) > 60:
            reasons.append(f"Query DNS muy larga ({len(domain)} chars) — posible túnel")
        if reasons:
            self._alerted[domain] = now
            msg = f"DNS sospechoso desde {ip}: {domain} — {reasons[0]}"
            print(f"\033[33m[DNSMonitor] ⚠ {msg}\033[0m")
            if self.ids and hasattr(self.ids, '_create_alert'):
                self.ids._create_alert(ip, "WARN", msg, "🔍", "DNS_SUSPICIOUS")
            self.event_bus.publish("dns_suspicious", {'ip': ip, 'domain': domain, 'reasons': reasons})

    def _run_loop(self):
        time.sleep(10)
        while True:
            time.sleep(5)
            try:
                if not self.sniffer:
                    continue
                for event in self.sniffer.get_recent_events(limit=100):
                    if event.protocol == 'DNS' and event.info:
                        self.check_domain(event.src_ip, event.info)
                for ip, stats in list(self.sniffer.device_stats.items()):
                    for domain in stats.get('dns_queries', []):
                        self.check_domain(ip, domain)
            except Exception as e:
                logger.debug(f"[DNSMonitor] Error: {e}")


# ─── Plugin: Malware Traffic Detector (NUEVO Fase 11) ─────────────────────────

class MalwareTrafficPlugin(BasePlugin):
    """Detecta beaconing (conexiones periódicas regulares) y puertos C2 típicos de malware."""
    name        = "MalwareTraffic"
    description = "Detecta patrones de tráfico de malware (beaconing, C2)"

    C2_PORTS = {4444, 4445, 1234, 31337, 8888, 9999, 6667, 6666, 12345, 54321, 1337, 7777}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._conn_times: Dict[str, List[float]] = {}
        self._alerted:    Dict[str, float]       = {}
        self._lock        = threading.Lock()
        self._cooldown    = 600

    def on_packet(self, packet):
        if not packet or not hasattr(packet, 'dst_ip'):
            return
        dst = packet.dst_ip
        if not dst or dst.startswith('192.168.') or dst.startswith('10.'):
            return
        now = time.time()
        with self._lock:
            if dst not in self._conn_times:
                self._conn_times[dst] = []
            self._conn_times[dst].append(now)
            self._conn_times[dst] = [t for t in self._conn_times[dst] if now - t < 7200]
        # C2 ports
        try:
            port = int(str(packet.info).lstrip(':'))
            if port in self.C2_PORTS:
                key = f"c2_{dst}_{port}"
                if now - self._alerted.get(key, 0) > self._cooldown:
                    self._alerted[key] = now
                    msg = f"Puerto C2 sospechoso: {packet.src_ip} → {dst}:{port}"
                    print(f"\033[31m[MalwareTraffic] 🚨 {msg}\033[0m")
                    if self.ids:
                        self.ids._create_alert(packet.src_ip, "CRITICAL", msg, "☠", "C2_PORT")
        except Exception:
            pass

    def _run_loop(self):
        time.sleep(60)
        while True:
            time.sleep(120)
            try:
                now = time.time()
                with self._lock:
                    snapshot = dict(self._conn_times)
                for dst_ip, times in snapshot.items():
                    if len(times) < 5:
                        continue
                    ts = sorted(times[-20:])
                    intervals = [ts[i+1]-ts[i] for i in range(len(ts)-1)]
                    if not intervals:
                        continue
                    mean = sum(intervals) / len(intervals)
                    if mean < 5:
                        continue
                    cv = (sum((x-mean)**2 for x in intervals)/len(intervals))**0.5 / max(mean, 1)
                    if cv < 0.15 and 10 <= mean <= 3600:
                        key = f"beacon_{dst_ip}"
                        if now - self._alerted.get(key, 0) > self._cooldown:
                            self._alerted[key] = now
                            msg = f"Beaconing detectado → {dst_ip} cada ~{mean:.0f}s (CV:{cv:.2f})"
                            print(f"\033[31m[MalwareTraffic] 🚨 {msg}\033[0m")
                            if self.ids:
                                self.ids._create_alert("", "CRITICAL", msg, "📡", "BEACONING")
            except Exception as e:
                logger.debug(f"[MalwareTraffic] Error: {e}")


# ─── Plugin Manager v2 ────────────────────────────────────────────────────────

class PluginManager:
    """Plugin Manager v2 — Fase 7 + Fase 11. Hooks, plugins externos, EventBus."""

    def __init__(self, settings, db=None, ids=None, dpi=None, graph=None, sniffer=None):
        self.settings         = settings
        self.db               = db
        self.ids              = ids
        self.dpi              = dpi
        self.graph            = graph
        self.sniffer          = sniffer
        self._plugins:        List[BasePlugin]           = []
        self.geoip:           Optional[GeoIPPlugin]      = None
        self.telegram:        Optional[TelegramPlugin]   = None
        self.dns_monitor:     Optional[DNSMonitorPlugin] = None
        self.malware_traffic: Optional[MalwareTrafficPlugin] = None
        self.event_bus        = _event_bus

    def _make(self, cls, **kwargs):
        return cls(self.settings, db=self.db, ids=self.ids,
                   dpi=self.dpi, graph=self.graph, sniffer=self.sniffer, **kwargs)

    def load_all(self):
        self.geoip = self._make(GeoIPPlugin)
        self._plugins.append(self.geoip)

        self.telegram = self._make(TelegramPlugin)
        if not self.telegram._is_configured():
            self.telegram.enabled = False
            self.telegram.status  = "not_configured"
        self._plugins.append(self.telegram)

        self._plugins.append(self._make(BandwidthAlertPlugin, threshold_mb=10))
        pa = self._make(PortAlertPlugin)
        self._plugins.append(pa)
        self._plugins.append(self._make(AutoReportPlugin, interval_hours=24))

        # Fase 11: nuevos plugins
        self.dns_monitor = self._make(DNSMonitorPlugin)
        self._plugins.append(self.dns_monitor)
        self.malware_traffic = self._make(MalwareTrafficPlugin)
        self._plugins.append(self.malware_traffic)

        self._load_external_plugins()

        enabled = sum(1 for p in self._plugins if p.enabled)
        print(f"\033[32m[Plugins] {len(self._plugins)} plugins cargados ({enabled} activos)\033[0m")

    def _load_external_plugins(self):
        """Carga plugins externos desde plugins/external/*/main.py"""
        import importlib.util
        external_dir = os.path.join(os.path.dirname(__file__), 'external')
        os.makedirs(external_dir, exist_ok=True)
        readme = os.path.join(external_dir, 'README.txt')
        if not os.path.exists(readme):
            with open(readme, 'w') as f:
                f.write(
                    "PLUGINS EXTERNOS\n\n"
                    "Crear carpeta: plugins/external/mi_plugin/\n"
                    "Agregar plugin.json: {\"name\": \"MiPlugin\", \"enabled\": true}\n"
                    "Agregar main.py con clase Plugin(BasePlugin)\n\n"
                    "Hooks disponibles:\n"
                    "  on_packet(pkt), on_ids_alert(alert), on_new_device(dev)\n"
                    "  on_device_left(ip), on_tick(), on_threat_detected(ip, result)\n"
                )
        loaded = 0
        if not os.path.isdir(external_dir):
            return
        for plugin_dir in os.listdir(external_dir):
            full  = os.path.join(external_dir, plugin_dir)
            jpath = os.path.join(full, 'plugin.json')
            mpath = os.path.join(full, 'main.py')
            if not os.path.isdir(full) or not os.path.exists(jpath) or not os.path.exists(mpath):
                continue
            try:
                with open(jpath) as f:
                    meta = json.load(f)
                if not meta.get('enabled', True):
                    continue
                spec   = importlib.util.spec_from_file_location(f"ext_{plugin_dir}", mpath)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, 'Plugin'):
                    plugin = module.Plugin(self.settings, db=self.db, ids=self.ids,
                                           dpi=self.dpi, graph=self.graph, sniffer=self.sniffer)
                    self._plugins.append(plugin)
                    loaded += 1
                    print(f"\033[36m[Plugins] Externo: {meta.get('name', plugin_dir)}\033[0m")
            except Exception as e:
                logger.error(f"[Plugins] Error cargando {plugin_dir}: {e}")
        if loaded:
            print(f"\033[32m[Plugins] {loaded} plugins externos cargados\033[0m")

    def start(self):
        for plugin in self._plugins:
            if plugin.enabled:
                plugin.start()
        threading.Thread(target=self._tick_loop, daemon=True).start()

    def _tick_loop(self):
        while True:
            time.sleep(30)
            for plugin in self._plugins:
                if plugin.enabled:
                    try:
                        plugin.on_tick()
                    except Exception:
                        pass

    def register_baseline(self, devices):
        for plugin in self._plugins:
            if hasattr(plugin, 'register_baseline'):
                plugin.register_baseline(devices)

    def on_ids_alert(self, alert):
        self.event_bus.publish("ids_alert", alert)
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    plugin.on_ids_alert(alert)
                except Exception as e:
                    logger.error(f"[PluginManager] {plugin.name}.on_ids_alert: {e}")

    def on_new_device(self, device):
        self.event_bus.publish("new_device", device)
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    plugin.on_new_device(device)
                except Exception as e:
                    logger.error(f"[PluginManager] {plugin.name}.on_new_device: {e}")

    def on_device_left(self, ip: str):
        self.event_bus.publish("device_left", ip)
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    plugin.on_device_left(ip)
                except Exception:
                    pass

    def on_packet(self, packet):
        """NUEVO Fase 11 — distribuye cada paquete a plugins."""
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    plugin.on_packet(packet)
                except Exception:
                    pass

    def on_threat_detected(self, ip: str, result: dict):
        """NUEVO Fase 11 — IP maliciosa detectada por Threat Intel."""
        self.event_bus.publish("threat_detected", {'ip': ip, 'result': result})
        for plugin in self._plugins:
            if plugin.enabled:
                try:
                    plugin.on_threat_detected(ip, result)
                except Exception:
                    pass

    def list_plugins(self) -> List[BasePlugin]:
        return self._plugins

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        for p in self._plugins:
            if p.name == name:
                return p
        return None

    def configure_telegram(self, bot_token: str, chat_id: str):
        if self.telegram:
            self.telegram.configure(bot_token, chat_id)
            self.telegram.enabled = True
            self.telegram.status  = "running"
            if not self.telegram._thread or not self.telegram._thread.is_alive():
                self.telegram.start()
            print(f"\033[32m[Plugins] Telegram habilitado ✓\033[0m")

    def get_geoip_data(self) -> List[dict]:
        if self.geoip:
            return self.geoip.get_map_data()
        return []

    def get_plugin_status(self) -> List[dict]:
        return [{'name': p.name, 'version': getattr(p, 'version', '1.0'),
                 'description': p.description, 'enabled': p.enabled,
                 'status': p.status} for p in self._plugins]

