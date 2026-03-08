"""
modules/honeypot.py
FASE EXTRA — Honeypot: trampa para intrusos en la red local

Crea un dispositivo virtual que escucha en puertos atractivos para atacantes.
Cualquier conexión a estos puertos dispara una alerta CRITICAL inmediata.

Puertos simulados:
  21   → FTP server falso
  23   → Telnet server falso
  80   → HTTP server falso (responde HTML básico)
  443  → HTTPS server falso
  3389 → RDP server falso (Windows Remote Desktop)
  8080 → HTTP alternativo falso
  4444 → Puerto típico de reverse shells (Metasploit default)

Uso en main.py:
    from modules.honeypot import Honeypot
    honeypot = Honeypot(settings=settings, ids=ids)
    honeypot.start()
"""

import socket
import threading
import time
import logging
import os
from typing import List, Dict, Optional, Callable

logger = logging.getLogger(__name__)


# ─── Registro de intento ──────────────────────────────────────────────────────

class HoneypotHit:
    """Registro de un intento de conexión al honeypot."""
    def __init__(self, src_ip: str, src_port: int, dst_port: int, data: bytes = b''):
        self.src_ip   = src_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.data     = data[:256]  # primeros 256 bytes
        self.timestamp = time.time()
        self.service  = HONEYPOT_PORTS.get(dst_port, {}).get('name', f'PORT-{dst_port}')

    def to_dict(self) -> dict:
        return {
            'src_ip':    self.src_ip,
            'src_port':  self.src_port,
            'dst_port':  self.dst_port,
            'service':   self.service,
            'data':      self.data.decode('utf-8', errors='replace')[:100],
            'timestamp': self.timestamp,
        }

    def __str__(self):
        ts = time.strftime('%H:%M:%S', time.localtime(self.timestamp))
        return (f"[{ts}] 🍯 HONEYPOT HIT: {self.src_ip}:{self.src_port} "
                f"→ {self.service} (:{self.dst_port})")


# ─── Puertos y respuestas falsas ──────────────────────────────────────────────

HONEYPOT_PORTS: Dict[int, dict] = {
    21: {
        'name':    'FTP',
        'banner':  b'220 FTP server ready\r\n',
        'prompt':  b'331 Password required\r\n',
    },
    23: {
        'name':    'Telnet',
        'banner':  b'\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27'
                   b'\r\nWelcome\r\nlogin: ',
        'prompt':  b'Password: ',
    },
    80: {
        'name':    'HTTP',
        'banner':  (b'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n'
                    b'Content-Type: text/html\r\n\r\n'
                    b'<html><body><h1>It works!</h1></body></html>'),
        'prompt':  b'',
    },
    443: {
        'name':    'HTTPS',
        'banner':  b'',   # TLS handshake — solo registrar la conexión
        'prompt':  b'',
    },
    3389: {
        'name':    'RDP',
        'banner':  b'\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00',
        'prompt':  b'',
    },
    8080: {
        'name':    'HTTP-Alt',
        'banner':  (b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n'
                    b'Content-Type: text/html\r\n\r\n'
                    b'<html><body>Admin Panel</body></html>'),
        'prompt':  b'',
    },
    4444: {
        'name':    'Backdoor',
        'banner':  b'',
        'prompt':  b'',
    },
}


# ─── Listener por puerto ──────────────────────────────────────────────────────

class HoneypotListener:
    """Escucha en un puerto específico y registra conexiones."""

    def __init__(self, port: int, config: dict, on_hit: Callable):
        self.port    = port
        self.config  = config
        self.on_hit  = on_hit
        self._sock:  Optional[socket.socket] = None
        self._running = False

    def start(self) -> bool:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)
            self._sock.bind(('0.0.0.0', self.port))
            self._sock.listen(5)
            self._running = True
            threading.Thread(target=self._accept_loop, daemon=True).start()
            return True
        except OSError as e:
            # Puerto en uso o sin permisos — saltar silenciosamente
            logger.debug(f"[Honeypot] Puerto {self.port} no disponible: {e}")
            return False

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(
                    target=self._handle_conn,
                    args=(conn, addr),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _handle_conn(self, conn: socket.socket, addr):
        src_ip, src_port = addr
        data = b''
        try:
            conn.settimeout(3.0)
            # Enviar banner falso
            banner = self.config.get('banner', b'')
            if banner:
                try:
                    conn.send(banner)
                except Exception:
                    pass
            # Intentar leer datos del atacante
            try:
                data = conn.recv(256)
            except Exception:
                pass
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

        hit = HoneypotHit(src_ip, src_port, self.port, data)
        self.on_hit(hit)


# ─── Motor principal ──────────────────────────────────────────────────────────

class Honeypot:
    """
    Honeypot de red local — trampa para intrusos.

    Escucha en puertos atractivos y alerta cuando alguien intenta conectarse.
    Integrado con el IDS para generar alertas CRITICAL automáticas.
    """

    def __init__(self, settings=None, ids=None, ports: List[int] = None):
        self.settings  = settings
        self.ids       = ids
        self._hits:    List[HoneypotHit] = []
        self._lock     = threading.Lock()
        self._listeners: List[HoneypotListener] = []
        self._callbacks: List[Callable] = []

        # Cooldown por IP para no spamear alertas
        self._cooldowns: Dict[str, float] = {}
        self._cooldown_sec = 60

        # Ports a usar — default todos, o los que pase el usuario
        self._ports = ports or list(HONEYPOT_PORTS.keys())

        # IP del honeypot en la red (esta misma máquina)
        self.host_ip = self._get_local_ip()
        self.active_ports: List[int] = []

        logger.info("[Honeypot] Motor inicializado")

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start(self):
        """Inicia todos los listeners en background."""
        started = 0
        for port in self._ports:
            config = HONEYPOT_PORTS.get(port, {'name': f'PORT-{port}', 'banner': b''})
            listener = HoneypotListener(port, config, self._on_hit)
            if listener.start():
                self._listeners.append(listener)
                self.active_ports.append(port)
                started += 1

        if started:
            ports_str = ', '.join(str(p) for p in self.active_ports)
            print(f"\033[33m[🍯 Honeypot] Activo en {self.host_ip} "
                  f"— {started} puertos: {ports_str}\033[0m")
            logger.info(f"[Honeypot] {started} puertos activos: {self.active_ports}")
        else:
            print(f"\033[33m[Honeypot] Sin puertos disponibles — "
                  f"puede requerir permisos de administrador\033[0m")

    def stop(self):
        for listener in self._listeners:
            listener.stop()
        self._listeners.clear()

    def register_callback(self, cb: Callable):
        """Callback llamado con cada HoneypotHit."""
        self._callbacks.append(cb)

    def _on_hit(self, hit: HoneypotHit):
        """Procesamiento de un hit al honeypot."""
        # Cooldown por IP
        now = time.time()
        if now - self._cooldowns.get(hit.src_ip, 0) < self._cooldown_sec:
            return
        self._cooldowns[hit.src_ip] = now

        # Registrar
        with self._lock:
            self._hits.append(hit)
            if len(self._hits) > 500:
                self._hits = self._hits[-400:]

        print(f"\033[31m{hit}\033[0m")
        logger.warning(str(hit))

        # Alerta CRITICAL al IDS
        if self.ids:
            try:
                msg = (f"🍯 HONEYPOT: {hit.src_ip} intentó conectarse a "
                       f"{hit.service} (:{hit.dst_port})")
                self.ids._create_alert(
                    ip       = hit.src_ip,
                    severity = "CRITICAL",
                    message  = msg,
                    icon     = "🍯",
                    category = "HONEYPOT",
                )
            except Exception as e:
                logger.error(f"[Honeypot] Error enviando alerta IDS: {e}")

        # Callbacks externos
        for cb in self._callbacks:
            try:
                cb(hit)
            except Exception:
                pass

    # ── API pública ───────────────────────────────────────────────────────────

    def get_hits(self, limit: int = 50) -> List[dict]:
        """Retorna los últimos hits."""
        with self._lock:
            return [h.to_dict() for h in reversed(self._hits[-limit:])]

    def get_stats(self) -> dict:
        """Estadísticas del honeypot."""
        with self._lock:
            by_ip   = {}
            by_port = {}
            for h in self._hits:
                by_ip[h.src_ip]     = by_ip.get(h.src_ip, 0) + 1
                by_port[h.dst_port] = by_port.get(h.dst_port, 0) + 1
            return {
                'total_hits':    len(self._hits),
                'active_ports':  self.active_ports,
                'host_ip':       self.host_ip,
                'top_attackers': sorted(by_ip.items(),   key=lambda x: -x[1])[:5],
                'top_ports':     sorted(by_port.items(), key=lambda x: -x[1])[:5],
                'enabled':       len(self._listeners) > 0,
            }

    def get_attacker_ips(self) -> List[str]:
        """Retorna IPs únicas que han tocado el honeypot."""
        with self._lock:
            return list({h.src_ip for h in self._hits})

    def is_active(self) -> bool:
        return len(self._listeners) > 0
