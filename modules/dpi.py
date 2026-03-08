"""
modules/dpi.py
Deep Packet Inspection — FASE 8
- Análisis DNS en tiempo real
- Tracking de IPs externas para GeoIP
- Tasas de tráfico por dispositivo (para ML)
- Historial temporal para Isolation Forest
"""

import time
import threading
import logging
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─── Base de datos de servicios por dominio ───────────────────────────────────
SERVICE_MAP = {
    # ── Video / Streaming
    "youtube":          ("YouTube",       "▶",  "streaming", (255, 0,   0  )),
    "googlevideo":      ("YouTube",       "▶",  "streaming", (255, 0,   0  )),
    "ytimg":            ("YouTube",       "▶",  "streaming", (255, 0,   0  )),
    "netflix":          ("Netflix",       "▶",  "streaming", (229, 9,   20 )),
    "nflxvideo":        ("Netflix",       "▶",  "streaming", (229, 9,   20 )),
    "nflximg":          ("Netflix",       "▶",  "streaming", (229, 9,   20 )),
    "twitch":           ("Twitch",        "▶",  "streaming", (145, 70,  255)),
    "twitchsvc":        ("Twitch",        "▶",  "streaming", (145, 70,  255)),
    "disney-plus":      ("Disney+",       "▶",  "streaming", (17,  60,  207)),
    "disneyplus":       ("Disney+",       "▶",  "streaming", (17,  60,  207)),
    "hbomax":           ("HBO Max",       "▶",  "streaming", (100, 0,   200)),
    "primevideo":       ("Prime Video",   "▶",  "streaming", (0,   168, 225)),
    "amazonvideo":      ("Prime Video",   "▶",  "streaming", (0,   168, 225)),
    "vimeo":            ("Vimeo",         "▶",  "streaming", (26,  183, 234)),
    "dailymotion":      ("Dailymotion",   "▶",  "streaming", (0,   100, 200)),
    "pluto":            ("Pluto TV",      "▶",  "streaming", (100, 200, 100)),
    # ── Música
    "spotify":          ("Spotify",       "♫",  "music",     (30,  215, 96 )),
    "scdn":             ("Spotify",       "♫",  "music",     (30,  215, 96 )),
    "deezer":           ("Deezer",        "♫",  "music",     (255, 160, 0  )),
    "soundcloud":       ("SoundCloud",    "♫",  "music",     (255, 85,  0  )),
    "apple.com/music":  ("Apple Music",   "♫",  "music",     (250, 60,  60 )),
    "tidal":            ("Tidal",         "♫",  "music",     (0,   230, 230)),
    # ── Redes sociales
    "instagram":        ("Instagram",     "📷", "social",    (225, 48,  108)),
    "cdninstagram":     ("Instagram",     "📷", "social",    (225, 48,  108)),
    "facebook":         ("Facebook",      "👤", "social",    (24,  119, 242)),
    "fbcdn":            ("Facebook",      "👤", "social",    (24,  119, 242)),
    "twitter":          ("Twitter/X",     "🐦", "social",    (29,  161, 242)),
    "twimg":            ("Twitter/X",     "🐦", "social",    (29,  161, 242)),
    "tiktok":           ("TikTok",        "♪",  "social",    (255, 0,   80 )),
    "tiktokcdn":        ("TikTok",        "♪",  "social",    (255, 0,   80 )),
    "snapchat":         ("Snapchat",      "👻", "social",    (255, 252, 0  )),
    "reddit":           ("Reddit",        "👾", "social",    (255, 69,  0  )),
    "linkedin":         ("LinkedIn",      "💼", "social",    (0,   119, 181)),
    "pinterest":        ("Pinterest",     "📌", "social",    (230, 0,   35 )),
    # ── Mensajería
    "whatsapp":         ("WhatsApp",      "💬", "chat",      (37,  211, 102)),
    "wa.me":            ("WhatsApp",      "💬", "chat",      (37,  211, 102)),
    "telegram":         ("Telegram",      "✈",  "chat",      (0,   136, 204)),
    "discord":          ("Discord",       "🎮", "chat",      (114, 137, 218)),
    "discordapp":       ("Discord",       "🎮", "chat",      (114, 137, 218)),
    "signal":           ("Signal",        "🔒", "chat",      (59,  165, 93 )),
    "slack":            ("Slack",         "💬", "chat",      (74,  21,  75 )),
    # ── Gaming
    "steampowered":     ("Steam",         "🎮", "gaming",    (23,  26,  33 )),
    "steamcontent":     ("Steam",         "🎮", "gaming",    (23,  26,  33 )),
    "epicgames":        ("Epic Games",    "🎮", "gaming",    (35,  35,  35 )),
    "playstation":      ("PlayStation",   "🎮", "gaming",    (0,   70,  175)),
    "xboxlive":         ("Xbox",          "🎮", "gaming",    (16,  124, 16 )),
    "riotgames":        ("Riot/Valorant", "🎮", "gaming",    (215, 30,  30 )),
    "minecraft":        ("Minecraft",     "🎮", "gaming",    (100, 180, 60 )),
    "ea.com":           ("EA Games",      "🎮", "gaming",    (255, 79,  0  )),
    # ── Google
    "google.com":       ("Google",        "🔍", "search",    (66,  133, 244)),
    "googleapis":       ("Google API",    "🔍", "search",    (66,  133, 244)),
    "gstatic":          ("Google",        "🔍", "search",    (66,  133, 244)),
    "gmail":            ("Gmail",         "✉",  "email",     (234, 67,  53 )),
    "googledrive":      ("Google Drive",  "☁",  "cloud",     (66,  133, 244)),
    "meet.google":      ("Google Meet",   "📹", "video",     (0,   167, 112)),
    # ── Microsoft
    "microsoft":        ("Microsoft",     "🪟", "system",    (0,   120, 215)),
    "office365":        ("Office 365",    "🪟", "system",    (0,   120, 215)),
    "outlook":          ("Outlook",       "✉",  "email",     (0,   114, 198)),
    "teams":            ("Teams",         "📹", "video",     (69,  66,  211)),
    "onedrive":         ("OneDrive",      "☁",  "cloud",     (0,   120, 215)),
    "xbox":             ("Xbox",          "🎮", "gaming",    (16,  124, 16 )),
    "windows":          ("Windows Update","🪟", "system",    (0,   120, 215)),
    # ── Apple
    "apple.com":        ("Apple",         "🍎", "system",    (150, 150, 150)),
    "icloud":           ("iCloud",        "☁",  "cloud",     (100, 180, 255)),
    "itunes":           ("iTunes",        "♫",  "music",     (250, 60,  60 )),
    "appstore":         ("App Store",     "📱", "system",    (0,   122, 255)),
    # ── Noticias
    "bbc":              ("BBC",           "📰", "news",      (187, 20,  20 )),
    "cnn":              ("CNN",           "📰", "news",      (204, 0,   0  )),
    "wikipedia":        ("Wikipedia",     "📖", "info",      (100, 100, 100)),
    # ── Compras
    "amazon.com":       ("Amazon",        "🛒", "shopping",  (255, 153, 0  )),
    "mercadolibre":     ("MercadoLibre",  "🛒", "shopping",  (255, 230, 0  )),
    "ebay":             ("eBay",          "🛒", "shopping",  (0,   100, 200)),
    # ── Sistema / Red
    "cloudflare":       ("Cloudflare",    "🛡", "cdn",       (255, 102, 0  )),
    "akamai":           ("Akamai CDN",    "🛡", "cdn",       (0,   100, 200)),
    "amazonaws":        ("AWS",           "☁",  "cloud",     (255, 153, 0  )),
    "azure":            ("Azure",         "☁",  "cloud",     (0,   120, 215)),
    "ocsp":             ("SSL Check",     "🔒", "security",  (100, 200, 100)),
    "ntp":              ("NTP (Hora)",    "🕐", "system",    (150, 150, 200)),
    "pool.ntp":         ("NTP (Hora)",    "🕐", "system",    (150, 150, 200)),
}

CATEGORY_COLORS = {
    "streaming": (255, 80,  80 ),
    "music":     (30,  215, 96 ),
    "social":    (225, 48,  108),
    "chat":      (37,  211, 102),
    "gaming":    (114, 137, 218),
    "search":    (66,  133, 244),
    "email":     (234, 67,  53 ),
    "cloud":     (100, 180, 255),
    "video":     (0,   230, 200),
    "system":    (150, 150, 150),
    "cdn":       (255, 102, 0  ),
    "security":  (100, 200, 100),
    "news":      (187, 20,  20 ),
    "shopping":  (255, 153, 0  ),
    "info":      (180, 180, 180),
    "other":     (120, 120, 120),
}

# IPs privadas — no son "externas"
PRIVATE_PREFIXES = (
    "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "0.", "169.254.", "224.", "255.", "::1",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


class ServiceActivity:
    def __init__(self, service: str, icon: str, category: str, color: tuple, domain: str):
        self.service    = service
        self.icon       = icon
        self.category   = category
        self.color      = color
        self.domain     = domain
        self.first_seen = time.time()
        self.last_seen  = time.time()
        self.count      = 1

    def update(self):
        self.last_seen = time.time()
        self.count    += 1

    @property
    def is_recent(self) -> bool:
        return time.time() - self.last_seen < 300

    @property
    def age_str(self) -> str:
        ago = int(time.time() - self.last_seen)
        if ago < 60:   return f"{ago}s"
        if ago < 3600: return f"{ago//60}m"
        return f"{ago//3600}h"


class DPIEngine:
    """
    Motor de Deep Packet Inspection — FASE 8.
    Agrega: tracking de IPs externas, tasas de tráfico,
    historial temporal por dispositivo para ML.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Actividad por servicio
        self._device_activity: Dict[str, Dict[str, ServiceActivity]] = defaultdict(dict)
        self._recent_domains:  Dict[str, deque] = defaultdict(lambda: deque(maxlen=30))

        # Bytes totales acumulados
        self._device_bytes: Dict[str, int] = defaultdict(int)

        # ── FASE 8: IPs externas para GeoIP ──────────────────────────────────
        # ip_local -> set de IPs externas con las que habló
        self._external_connections: Dict[str, set] = defaultdict(set)
        # set global de IPs externas detectadas
        self._external_ips: set = set()
        # ip_externa -> {domain, service, count, last_seen}
        self._external_ip_info: Dict[str, dict] = {}

        # ── FASE 8: Historial temporal para ML ───────────────────────────────
        # ip -> deque de muestras {timestamp, bytes, dns_count, hour}
        self._traffic_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=500))
        # ip -> bytes en la última ventana de 10s (para tasa)
        self._rate_window: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        # ip -> timestamp del último byte registrado
        self._last_rate_ts: Dict[str, float] = defaultdict(float)

        # Muestras de tráfico cada 60s para ML
        self._sample_thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._sample_thread.start()

        logger.info("DPI Engine Fase 8 iniciado")

    # ── Procesamiento ─────────────────────────────────────────────────────────

    def process_dns(self, src_ip: str, domain: str, dst_ip: str = ""):
        """Procesa una query DNS. dst_ip es la IP del servidor DNS o destino."""
        domain_lower = domain.lower().rstrip('.')
        service_info = self._match_service(domain_lower)

        with self._lock:
            self._recent_domains[src_ip].appendleft({
                'domain':    domain_lower,
                'service':   service_info[0] if service_info else None,
                'icon':      service_info[1] if service_info else '·',
                'color':     service_info[3] if service_info else (150, 150, 150),
                'timestamp': time.time(),
            })

            if service_info:
                name, icon, category, color = service_info
                activities = self._device_activity[src_ip]
                if name in activities:
                    activities[name].update()
                else:
                    activities[name] = ServiceActivity(name, icon, category, color, domain_lower)

            # Registrar IP externa si la tenemos
            if dst_ip and not _is_private(dst_ip) and dst_ip not in ('0.0.0.0', ''):
                self._external_ips.add(dst_ip)
                self._external_connections[src_ip].add(dst_ip)
                if dst_ip not in self._external_ip_info:
                    self._external_ip_info[dst_ip] = {
                        'ip':        dst_ip,
                        'domain':    domain_lower,
                        'service':   service_info[0] if service_info else 'Unknown',
                        'count':     0,
                        'last_seen': time.time(),
                        'first_seen': time.time(),
                        'src_ips':   set(),
                    }
                self._external_ip_info[dst_ip]['count']     += 1
                self._external_ip_info[dst_ip]['last_seen']  = time.time()
                self._external_ip_info[dst_ip]['src_ips'].add(src_ip)

    def process_traffic(self, src_ip: str, size: int, dst_ip: str = ""):
        """Acumula bytes y registra IPs externas de destino."""
        now = time.time()
        with self._lock:
            self._device_bytes[src_ip] += size
            # Ventana de tasa (últimos 10s)
            self._rate_window[src_ip].append((now, size))
            # Limpiar entradas viejas (>10s)
            while self._rate_window[src_ip] and now - self._rate_window[src_ip][0][0] > 10:
                self._rate_window[src_ip].popleft()

            # Registrar IP externa de destino
            if dst_ip and not _is_private(dst_ip) and dst_ip not in ('0.0.0.0', ''):
                self._external_ips.add(dst_ip)
                self._external_connections[src_ip].add(dst_ip)
                if dst_ip not in self._external_ip_info:
                    self._external_ip_info[dst_ip] = {
                        'ip':         dst_ip,
                        'domain':     '',
                        'service':    'Unknown',
                        'count':      0,
                        'last_seen':  now,
                        'first_seen': now,
                        'src_ips':    set(),
                    }
                self._external_ip_info[dst_ip]['count']    += 1
                self._external_ip_info[dst_ip]['last_seen'] = now
                self._external_ip_info[dst_ip]['src_ips'].add(src_ip)

    def _sample_loop(self):
        """Guarda muestras de tráfico cada 60s para el modelo ML."""
        while True:
            time.sleep(60)
            now  = time.time()
            hour = int(time.strftime('%H'))
            with self._lock:
                for ip in list(self._device_bytes.keys()):
                    rate = self.get_device_rate(ip)
                    dns  = len(self._recent_domains.get(ip, []))
                    self._traffic_history[ip].append({
                        'ts':        now,
                        'bytes':     self._device_bytes[ip],
                        'rate':      rate,
                        'dns_count': dns,
                        'hour':      hour,
                        'services':  len(self._device_activity.get(ip, {})),
                    })

    # ── API pública ───────────────────────────────────────────────────────────

    def _match_service(self, domain: str) -> Optional[Tuple]:
        for keyword, info in SERVICE_MAP.items():
            if keyword in domain:
                return info
        return None

    def get_device_activity(self, ip: str, limit: int = 8) -> List[ServiceActivity]:
        with self._lock:
            activities = self._device_activity.get(ip, {})
            recent = [a for a in activities.values() if a.is_recent]
            recent.sort(key=lambda a: a.last_seen, reverse=True)
            return recent[:limit]

    def get_all_activity(self, ip: str) -> List[ServiceActivity]:
        with self._lock:
            all_acts = list(self._device_activity.get(ip, {}).values())
            all_acts.sort(key=lambda a: a.last_seen, reverse=True)
            return all_acts

    def get_recent_domains(self, ip: str, limit: int = 10) -> List[dict]:
        with self._lock:
            return list(self._recent_domains.get(ip, []))[:limit]

    def get_top_services(self, limit: int = 5) -> List[tuple]:
        with self._lock:
            totals: Dict[str, int] = defaultdict(int)
            for activities in self._device_activity.values():
                for name, act in activities.items():
                    if act.is_recent:
                        totals[name] += act.count
            return sorted(totals.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_active_devices(self) -> List[str]:
        with self._lock:
            return [ip for ip, acts in self._device_activity.items()
                    if any(a.is_recent for a in acts.values())]

    def get_device_bytes(self, ip: str) -> int:
        with self._lock:
            return self._device_bytes.get(ip, 0)

    def get_top_talkers(self, limit: int = 5) -> List[Tuple[str, int]]:
        with self._lock:
            return sorted(self._device_bytes.items(), key=lambda x: x[1], reverse=True)[:limit]

    def get_device_rate(self, ip: str) -> float:
        """Bytes/segundo en los últimos 10 segundos."""
        now = time.time()
        window = self._rate_window.get(ip, deque())
        total  = sum(size for ts, size in window if now - ts <= 10)
        return total / 10.0

    def get_traffic_history(self, ip: str) -> List[dict]:
        """Historial de muestras de tráfico para ML."""
        with self._lock:
            return list(self._traffic_history.get(ip, []))

    def get_all_traffic_history(self) -> Dict[str, List[dict]]:
        """Todo el historial para entrenar el modelo ML."""
        with self._lock:
            return {ip: list(hist) for ip, hist in self._traffic_history.items()}

    # ── GeoIP helpers ─────────────────────────────────────────────────────────

    def get_external_ips(self) -> set:
        """Todas las IPs externas detectadas (para GeoIP plugin)."""
        with self._lock:
            return set(self._external_ips)

    def get_external_ip_info(self, ip: str = None) -> dict:
        """Info de IPs externas para el mapa GeoIP."""
        with self._lock:
            if ip:
                info = self._external_ip_info.get(ip, {})
                # Convertir set a lista para JSON
                result = dict(info)
                result['src_ips'] = list(info.get('src_ips', set()))
                return result
            # Retornar todas
            result = {}
            for ext_ip, info in self._external_ip_info.items():
                d = dict(info)
                d['src_ips'] = list(info.get('src_ips', set()))
                result[ext_ip] = d
            return result

    def get_device_external_ips(self, ip: str) -> List[str]:
        """IPs externas con las que habló un dispositivo específico."""
        with self._lock:
            return list(self._external_connections.get(ip, set()))

    def format_bytes(self, b: int) -> str:
        if b < 1024:       return f"{b}B"
        if b < 1024**2:    return f"{b/1024:.1f}KB"
        if b < 1024**3:    return f"{b/1024**2:.1f}MB"
        return f"{b/1024**3:.1f}GB"
