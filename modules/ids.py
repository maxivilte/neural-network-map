"""
modules/ids.py
Intrusion Detection System — FASE 1 + FASE 8
- Detección de nuevos dispositivos, ARP spoofing, tráfico alto, port scan
- _create_alert() para uso externo (ML, plugins, BandwidthAlert, PortAlert)
- icon_override en Alert para iconos custom desde ML/plugins
"""

import time
import logging
import threading
import math
from typing import Set, Dict, List, Callable

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "INFO":     (0, 200, 255),
    "WARN":     (255, 200, 0),
    "CRITICAL": (255, 50, 50),
}

# ─── Whitelist de servicios de streaming ─────────────────────────────────────
# IPs/dominios de estos servicios nunca generan alertas de tráfico alto
STREAMING_KEYWORDS = {
    "netflix", "nflx", "fast.com",
    "youtube", "googlevideo", "ytimg",
    "twitch", "twitchsvc", "jtvnw",
    "disney", "bamgrid", "disneyplus",
    "spotify", "scdn.co",
    "amazon", "primevideo", "aiv-cdn",
    "hbo", "hbomax", "warnermedia",
    "tiktok", "tiktokcdn", "musical.ly",
    "facebook", "fbcdn", "instagram",
    "steam", "steampowered", "steamcontent",
    "epicgames", "epiccdn",
    "cloudfront", "akamai", "fastly",  # CDNs de streaming
}

def _is_streaming_traffic(ip: str, message: str = "") -> bool:
    """Retorna True si el tráfico parece ser de streaming legítimo."""
    msg_lower = message.lower()
    return any(kw in msg_lower for kw in STREAMING_KEYWORDS)


class Alert:
    SEVERITY_INFO     = "INFO"
    SEVERITY_WARN     = "WARN"
    SEVERITY_CRITICAL = "CRITICAL"

    def __init__(self, severity: str, category: str, message: str, ip: str = ""):
        self.severity      = severity
        self.category      = category
        self.message       = message
        self.ip            = ip
        self.timestamp     = time.time()
        self.read          = False
        self.icon_override = None   # ← usado por ML/plugins para icon custom

    def __str__(self):
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] [{self.severity}] [{self.category}] {self.message}"

    @property
    def color(self):
        return SEVERITY_COLORS.get(self.severity, (200, 200, 200))

    @property
    def icon(self):
        if self.icon_override:
            return self.icon_override
        return {
            "NEW_DEVICE":   "◈",
            "ARP_SPOOF":    "⚠",
            "HIGH_TRAFFIC": "▲",
            "DEVICE_LEFT":  "◇",
            "PORT_SCAN":    "⬡",
            "ML_ANOMALY":   "🤖",
            "BANDWIDTH":    "📶",
            "PORT_ALERT":   "🔓",
            "HONEYPOT":     "🍯",
        }.get(self.category, "●")

    def to_dict(self) -> dict:
        return {
            'severity':  self.severity,
            'category':  self.category,
            'message':   self.message,
            'ip':        self.ip,
            'timestamp': self.timestamp,
            'read':      self.read,
            'icon':      self.icon,
        }


def _generate_beep(frequency: float, duration_ms: int, volume: float = 0.4):
    try:
        import pygame
        import numpy as np
        sample_rate = 22050
        n_samples   = int(sample_rate * duration_ms / 1000)
        t           = np.linspace(0, duration_ms / 1000, n_samples, False)
        wave        = np.sin(2 * np.pi * frequency * t)
        fade_start  = int(n_samples * 0.9)
        fade_len    = n_samples - fade_start
        if fade_len > 0:
            wave[fade_start:] *= np.linspace(1, 0, fade_len)
        buf = (wave * 32767 * volume).astype(np.int16)
        buf_stereo = np.column_stack([buf, buf])
        return pygame.sndarray.make_sound(buf_stereo)
    except Exception as e:
        logger.debug(f"Error generando beep: {e}")
        return None


class SoundAlerts:
    SOUNDS = {
        "NEW_DEVICE":   (880, 200),
        "ARP_SPOOF":    (220, 700),
        "HIGH_TRAFFIC": (660, 150),
        "DEVICE_LEFT":  (440, 350),
        "PORT_SCAN":    (550, 400),
        "ML_ANOMALY":   (330, 500),
        "PORT_ALERT":   (770, 300),
    }

    def __init__(self):
        self._ready = False
        self._cache: Dict[str, object] = {}
        self._lock  = threading.Lock()
        self._init_mixer()

    def _init_mixer(self):
        try:
            import pygame
            if not pygame.mixer.get_init():
                pygame.mixer.pre_init(frequency=22050, size=-16, channels=2, buffer=512)
                pygame.mixer.init()
            self._ready = True
            for name, (freq, dur) in self.SOUNDS.items():
                snd = _generate_beep(freq, dur)
                if snd:
                    self._cache[name] = snd
            logger.info("SoundAlerts: listo")
        except Exception as e:
            logger.warning(f"SoundAlerts no disponible: {e}")

    def play(self, category: str):
        if not self._ready:
            return
        try:
            snd = self._cache.get(category)
            if snd:
                with self._lock:
                    snd.play()
        except Exception as e:
            logger.debug(f"Error sonido: {e}")


class IntrusionDetector:
    def __init__(self, settings):
        self.settings  = settings
        self.sound     = SoundAlerts()

        self.known_devices:     Set[str]         = set()
        self.device_macs:       Dict[str, str]   = {}
        self.device_first_seen: Dict[str, float] = {}
        self.device_last_seen:  Dict[str, float] = {}
        self.previously_seen:   Set[str]         = set()

        self.alerts:    List[Alert]    = []
        self.callbacks: List[Callable] = []
        self._lock      = threading.Lock()

        self._traffic_threshold_mb = 50
        self._port_scan_threshold  = 8
        self._port_scan_window:    Dict[str, List[float]] = {}
        self._cooldowns:           Dict[str, float]       = {}
        self._cooldown_sec         = 30

    def register_callback(self, cb: Callable):
        self.callbacks.append(cb)

    def _emit(self, alert: Alert):
        """Emite una alerta con cooldown para evitar spam."""
        key = f"{alert.ip}:{alert.category}"
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self._cooldown_sec:
            return
        self._cooldowns[key] = now
        with self._lock:
            self.alerts.append(alert)
        logger.warning(str(alert))
        self.sound.play(alert.category)
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def _create_alert(self, ip: str, severity: str, message: str,
                      icon: str = None, category: str = None) -> Alert:
        """
        API pública para que módulos externos (ML, plugins, API REST)
        puedan crear y emitir alertas sin acceso a la clase Alert directamente.
        """
        cat = category or (
            "ML_ANOMALY"  if "anomal" in message.lower() or "ml" in message.lower() else
            "HIGH_TRAFFIC" if "tráfico" in message.lower() or "traffic" in message.lower() else
            "PORT_ALERT"  if "puerto" in message.lower() or "port" in message.lower() else
            "NEW_DEVICE"
        )
        alert = Alert(severity, cat, message, ip=ip)
        if icon:
            alert.icon_override = icon
        self._emit(alert)
        return alert

    def register_known_devices(self, devices: list):
        for dev in devices:
            ip  = dev.ip  if hasattr(dev, 'ip')  else dev.get('ip', '')
            mac = dev.mac if hasattr(dev, 'mac') else dev.get('mac', '')
            if not ip:
                continue
            self.known_devices.add(ip)
            if mac and '??' not in mac:
                self.device_macs[ip] = mac
            t = time.time()
            self.device_first_seen.setdefault(ip, t)
            self.device_last_seen[ip] = t
        logger.info(f"IDS baseline: {len(self.known_devices)} dispositivos")

    def check_new_devices(self, current_devices: list):
        now = time.time()
        for dev in current_devices:
            ip  = dev.ip  if hasattr(dev, 'ip')  else dev.get('ip', '')
            mac = dev.mac if hasattr(dev, 'mac') else dev.get('mac', '')
            if not ip:
                continue
            self.device_last_seen[ip] = now

            if ip not in self.known_devices:
                # No alertar si es un dispositivo confiable conocido
                trusted = getattr(self.settings, 'trusted_devices', {})
                if ip in trusted:
                    self.known_devices.add(ip)
                    self.device_first_seen[ip] = now
                    if mac and '??' not in mac:
                        self.device_macs[ip] = mac
                    continue

                if ip in self.previously_seen:
                    msg = f"Dispositivo volvio a la red: {ip}"
                    sev = Alert.SEVERITY_INFO
                else:
                    msg = f"NUEVO dispositivo: {ip}  MAC: {mac}"
                    sev = Alert.SEVERITY_WARN
                self._emit(Alert(sev, "NEW_DEVICE", msg, ip=ip))
                self.known_devices.add(ip)
                self.device_first_seen[ip] = now
                if mac and '??' not in mac:
                    self.device_macs[ip] = mac

            if mac and '??' not in mac and ip in self.device_macs:
                known_mac = self.device_macs[ip]
                if mac != known_mac:
                    self.check_arp_spoofing(ip, mac, known_mac)
                    self.device_macs[ip] = mac

    def check_devices_left(self, current_ips: Set[str]):
        gone = self.known_devices - current_ips
        now  = time.time()
        for ip in gone:
            last = self.device_last_seen.get(ip, 0)
            if now - last < 300:
                self._emit(Alert(
                    Alert.SEVERITY_INFO, "DEVICE_LEFT",
                    f"Dispositivo desconectado: {ip}", ip=ip
                ))
            self.previously_seen.add(ip)
            self.known_devices.discard(ip)

    def check_arp_spoofing(self, ip: str, mac: str, known_mac: str):
        # Ignorar si la IP es confiable
        trusted_ips  = getattr(self.settings, 'trusted_devices', {})
        trusted_macs = getattr(self.settings, 'trusted_macs', set())
        if ip in trusted_ips:
            logger.debug(f"ARP change ignorado para dispositivo confiable {ip} ({trusted_ips[ip]})")
            return
        # Ignorar si alguna de las MACs pertenece a un prefijo confiable
        mac_prefix = mac[:8].upper() if mac else ''
        known_prefix = known_mac[:8].upper() if known_mac else ''
        if any(mac_prefix.startswith(t.upper()) or known_prefix.startswith(t.upper())
               for t in trusted_macs):
            logger.debug(f"ARP change ignorado para MAC confiable {ip}: {known_mac} -> {mac}")
            return
        self._emit(Alert(
            Alert.SEVERITY_CRITICAL, "ARP_SPOOF",
            f"ARP SPOOFING en {ip}: {known_mac} -> {mac}", ip=ip
        ))

    def check_traffic_anomaly(self, ip: str, bytes_per_sec: float, service_hint: str = ""):
        mb = bytes_per_sec / (1024 * 1024)
        if mb > self._traffic_threshold_mb:
            # No alertar si es tráfico de streaming conocido
            if _is_streaming_traffic(ip, service_hint):
                logger.debug(f"[IDS] Tráfico alto ignorado (streaming): {ip} {mb:.1f} MB/s")
                return
            self._emit(Alert(
                Alert.SEVERITY_WARN, "HIGH_TRAFFIC",
                f"{ip} generando {mb:.1f} MB/s — anomalia", ip=ip
            ))

    def check_port_scan(self, ip: str, port: int):
        now = time.time()
        self._port_scan_window.setdefault(ip, [])
        self._port_scan_window[ip].append(now)
        self._port_scan_window[ip] = [t for t in self._port_scan_window[ip] if now - t < 10]
        if len(self._port_scan_window[ip]) >= self._port_scan_threshold:
            self._emit(Alert(
                Alert.SEVERITY_CRITICAL, "PORT_SCAN",
                f"Port scan desde {ip} ({len(self._port_scan_window[ip])} puertos/10s)", ip=ip
            ))
            self._port_scan_window[ip] = []

    def get_recent_alerts(self, limit: int = 20) -> List[Alert]:
        with self._lock:
            return list(reversed(self.alerts[-limit:]))

    def get_unread_count(self) -> int:
        with self._lock:
            return sum(1 for a in self.alerts if not a.read)

    def mark_all_read(self):
        with self._lock:
            for a in self.alerts:
                a.read = True

    def get_alert_count(self) -> Dict[str, int]:
        with self._lock:
            counts = {
                Alert.SEVERITY_INFO: 0,
                Alert.SEVERITY_WARN: 0,
                Alert.SEVERITY_CRITICAL: 0,
            }
            for a in self.alerts:
                counts[a.severity] = counts.get(a.severity, 0) + 1
            return counts
