"""
modules/threat_intel.py
FASE 12 — Threat Intelligence

Verifica IPs externas contra:
  1. AbuseIPDB API  (gratis: 1000 req/día)   → score de abuso 0-100
  2. VirusTotal API (gratis: 4 req/min)       → detecciones de antivirus
  3. Emerging Threats IP list (público)       → IPs maliciosas conocidas
  4. Feodo Tracker (público)                  → botnets C2 activos

Características:
  - Cache SQLite con TTL 24h (no repite consultas)
  - Si IP es maliciosa → alerta CRITICAL en IDS + punto ROJO en mapa GeoIP
  - Funciona sin API keys usando solo feeds públicos gratuitos
  - Thread background que chequea IPs nuevas cada 5 minutos
  - API pública para consultar estado de cualquier IP

Configuración en settings.py:
  settings.abuseipdb_key   = 'TU_KEY'   (o env ABUSEIPDB_KEY)
  settings.virustotal_key  = 'TU_KEY'   (o env VIRUSTOTAL_KEY)
  settings.threat_intel_abuse_threshold = 25  (score mínimo para alertar)

Obtener keys gratis:
  AbuseIPDB:  https://www.abuseipdb.com/register
  VirusTotal: https://www.virustotal.com/gui/join-us
"""

import time
import threading
import logging
import json
import os
import sqlite3
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

# IPs privadas — nunca consultar
PRIVATE_PREFIXES = (
    "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.2", "172.3", "127.", "0.", "169.254.", "224.", "255.", "::1"
)

# URLs de feeds públicos gratuitos
FEED_EMERGING_THREATS = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
FEED_FEODO_TRACKER    = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"


def is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


# ─── Resultado de análisis de una IP ──────────────────────────────────────────

class ThreatResult:
    def __init__(self, ip: str):
        self.ip               = ip
        self.is_malicious     = False
        self.threat_score     = 0      # 0-100, donde 100 = máxima amenaza
        self.sources          = []     # qué fuentes lo marcaron
        self.categories       = []     # tipos de amenaza
        self.country          = ''
        self.isp              = ''
        self.last_reported    = None
        self.abuseipdb_score  = 0
        self.virustotal_hits  = 0
        self.virustotal_total = 0
        self.in_blocklist     = False  # Emerging Threats / Feodo
        self.checked_at       = time.time()
        self.error            = None

    @property
    def level(self) -> str:
        if self.threat_score >= 75:
            return "critical"
        if self.threat_score >= 40:
            return "high"
        if self.threat_score >= 15:
            return "medium"
        return "clean"

    @property
    def color_hex(self) -> str:
        return {
            "critical": "#FF1E1E",
            "high":     "#FF6B00",
            "medium":   "#FFD700",
            "clean":    "#00C864",
        }.get(self.level, "#888888")

    @property
    def marker_color(self) -> str:
        """Color para el mapa GeoIP."""
        return self.color_hex

    def to_dict(self) -> dict:
        return {
            'ip':               self.ip,
            'is_malicious':     self.is_malicious,
            'threat_score':     self.threat_score,
            'level':            self.level,
            'sources':          self.sources,
            'categories':       self.categories,
            'country':          self.country,
            'isp':              self.isp,
            'last_reported':    self.last_reported,
            'abuseipdb_score':  self.abuseipdb_score,
            'virustotal_hits':  self.virustotal_hits,
            'virustotal_total': self.virustotal_total,
            'in_blocklist':     self.in_blocklist,
            'checked_at':       self.checked_at,
            'color':            self.color_hex,
            'error':            self.error,
        }


# ─── Cache SQLite ──────────────────────────────────────────────────────────────

class ThreatCache:
    """Cache persistente en SQLite para resultados de Threat Intelligence."""

    def __init__(self, db_path: str = "logs/threat_intel.db", ttl: int = 86400):
        self.db_path = db_path
        self.ttl     = ttl
        self._lock   = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS threat_cache (
                        ip              TEXT PRIMARY KEY,
                        is_malicious    INTEGER DEFAULT 0,
                        threat_score    INTEGER DEFAULT 0,
                        level           TEXT DEFAULT 'clean',
                        sources         TEXT,       -- JSON list
                        categories      TEXT,       -- JSON list
                        country         TEXT,
                        isp             TEXT,
                        abuseipdb_score INTEGER DEFAULT 0,
                        virustotal_hits INTEGER DEFAULT 0,
                        virustotal_total INTEGER DEFAULT 0,
                        in_blocklist    INTEGER DEFAULT 0,
                        last_reported   TEXT,
                        checked_at      REAL,
                        raw_data        TEXT        -- JSON completo
                    );

                    CREATE TABLE IF NOT EXISTS blocklists (
                        ip          TEXT PRIMARY KEY,
                        source      TEXT,
                        added_at    REAL
                    );

                    CREATE INDEX IF NOT EXISTS idx_threat_ip    ON threat_cache(ip);
                    CREATE INDEX IF NOT EXISTS idx_threat_score ON threat_cache(threat_score);
                    CREATE INDEX IF NOT EXISTS idx_blocklist_ip ON blocklists(ip);
                """)
                conn.commit()
            finally:
                conn.close()

    def get(self, ip: str) -> Optional[ThreatResult]:
        """Retorna resultado cacheado si no expiró."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM threat_cache WHERE ip = ?", (ip,)
                ).fetchone()
                if row:
                    if time.time() - row['checked_at'] < self.ttl:
                        r = ThreatResult(ip)
                        r.is_malicious     = bool(row['is_malicious'])
                        r.threat_score     = row['threat_score']
                        r.sources          = json.loads(row['sources'] or '[]')
                        r.categories       = json.loads(row['categories'] or '[]')
                        r.country          = row['country'] or ''
                        r.isp              = row['isp'] or ''
                        r.abuseipdb_score  = row['abuseipdb_score']
                        r.virustotal_hits  = row['virustotal_hits']
                        r.virustotal_total = row['virustotal_total']
                        r.in_blocklist     = bool(row['in_blocklist'])
                        r.last_reported    = row['last_reported']
                        r.checked_at       = row['checked_at']
                        return r
            finally:
                conn.close()
        return None

    def save(self, result: ThreatResult):
        """Guarda resultado en cache."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO threat_cache
                        (ip, is_malicious, threat_score, level, sources, categories,
                         country, isp, abuseipdb_score, virustotal_hits, virustotal_total,
                         in_blocklist, last_reported, checked_at, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        is_malicious     = excluded.is_malicious,
                        threat_score     = excluded.threat_score,
                        level            = excluded.level,
                        sources          = excluded.sources,
                        categories       = excluded.categories,
                        country          = excluded.country,
                        isp              = excluded.isp,
                        abuseipdb_score  = excluded.abuseipdb_score,
                        virustotal_hits  = excluded.virustotal_hits,
                        virustotal_total = excluded.virustotal_total,
                        in_blocklist     = excluded.in_blocklist,
                        last_reported    = excluded.last_reported,
                        checked_at       = excluded.checked_at,
                        raw_data         = excluded.raw_data
                """, (
                    result.ip,
                    1 if result.is_malicious else 0,
                    result.threat_score,
                    result.level,
                    json.dumps(result.sources),
                    json.dumps(result.categories),
                    result.country,
                    result.isp,
                    result.abuseipdb_score,
                    result.virustotal_hits,
                    result.virustotal_total,
                    1 if result.in_blocklist else 0,
                    result.last_reported,
                    result.checked_at,
                    json.dumps(result.to_dict()),
                ))
                conn.commit()
            except Exception as e:
                logger.error(f"[TI] Error guardando cache {result.ip}: {e}")
            finally:
                conn.close()

    def save_blocklist(self, ips: Set[str], source: str):
        """Guarda IPs de blocklists públicas."""
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM blocklists WHERE source = ?", (source,))
                for ip in ips:
                    conn.execute(
                        "INSERT OR REPLACE INTO blocklists (ip, source, added_at) VALUES (?, ?, ?)",
                        (ip.strip(), source, now)
                    )
                conn.commit()
                logger.info(f"[TI] Blocklist {source}: {len(ips)} IPs guardadas")
            finally:
                conn.close()

    def is_in_blocklist(self, ip: str) -> Optional[str]:
        """Retorna el nombre de la fuente si la IP está en alguna blocklist."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT source FROM blocklists WHERE ip = ?", (ip,)
                ).fetchone()
                return row['source'] if row else None
            finally:
                conn.close()

    def get_all_threats(self, min_score: int = 1) -> List[dict]:
        """Todas las IPs con amenaza detectada."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM threat_cache WHERE threat_score >= ? ORDER BY threat_score DESC",
                    (min_score,)
                ).fetchall()
                results = []
                for row in rows:
                    results.append({
                        'ip':           row['ip'],
                        'threat_score': row['threat_score'],
                        'level':        row['level'],
                        'sources':      json.loads(row['sources'] or '[]'),
                        'categories':   json.loads(row['categories'] or '[]'),
                        'country':      row['country'],
                        'checked_at':   row['checked_at'],
                        'color':        ThreatResult(row['ip']).color_hex,
                    })
                return results
            finally:
                conn.close()

    def cleanup(self, max_age_days: int = 7):
        """Elimina entradas viejas del cache."""
        cutoff = time.time() - max_age_days * 86400
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM threat_cache WHERE checked_at < ?", (cutoff,))
                conn.commit()
            finally:
                conn.close()


# ─── Motor principal ───────────────────────────────────────────────────────────

class ThreatIntelEngine:
    """
    Motor de Threat Intelligence para Neural Network Map.

    Flujo:
    1. Recibe IPs externas del sniffer/DPI
    2. Consulta cache SQLite (TTL 24h)
    3. Si no está en cache → consulta AbuseIPDB, VirusTotal, blocklists
    4. Si es maliciosa → alerta CRITICAL al IDS + marca rojo en mapa
    5. Expone API para el dashboard web
    """

    def __init__(self, settings, ids=None, sniffer=None, dpi=None):
        self.settings = settings
        self.ids      = ids
        self.sniffer  = sniffer
        self.dpi      = dpi

        self._lock    = threading.Lock()
        self._running = False

        # Cache persistente
        self.cache = ThreatCache(
            db_path="logs/threat_intel.db",
            ttl=getattr(settings, 'threat_intel_cache_ttl', 86400)
        )

        # IPs ya alertadas (evitar spam)
        self._alerted_ips: Set[str] = set()
        # Cola de IPs pendientes de verificar
        self._pending_ips: Set[str] = set()
        # Resultados en memoria para acceso rápido
        self._results: Dict[str, ThreatResult] = {}

        # Blocklists en memoria
        self._blocklist_ips: Set[str] = set()

        # Rate limiting
        self._abuseipdb_calls   = 0
        self._abuseipdb_reset   = time.time()
        self._virustotal_calls  = 0
        self._virustotal_reset  = time.time()

        # Configuración
        self.abuseipdb_key  = getattr(settings, 'abuseipdb_key', '')
        self.virustotal_key = getattr(settings, 'virustotal_key', '')
        self.abuse_threshold = getattr(settings, 'threat_intel_abuse_threshold', 25)
        self.check_interval  = getattr(settings, 'threat_intel_check_interval', 300)

        self._print_status()

    def _print_status(self):
        has_abuse = bool(self.abuseipdb_key)
        has_vt    = bool(self.virustotal_key)
        print(f"\033[36m[TI] Threat Intelligence inicializado\033[0m")
        print(f"\033[36m[TI] AbuseIPDB: {'✓ API key' if has_abuse else '✗ sin key (feeds públicos solo)'}\033[0m")
        print(f"\033[36m[TI] VirusTotal: {'✓ API key' if has_vt else '✗ sin key'}\033[0m")
        print(f"\033[36m[TI] Feeds públicos: Emerging Threats + Feodo Tracker\033[0m")

    def start(self):
        self._running = True
        threading.Thread(target=self._main_loop,      daemon=True).start()
        threading.Thread(target=self._blocklist_loop, daemon=True).start()
        print(f"\033[32m[TI] Motor Threat Intelligence iniciado\033[0m")

    def stop(self):
        self._running = False

    # ── Loop principal ────────────────────────────────────────────────────────

    def _main_loop(self):
        """Chequea IPs externas periódicamente."""
        time.sleep(15)  # esperar que el sniffer capture tráfico
        while self._running:
            self._collect_external_ips()
            self._process_pending()
            time.sleep(self.check_interval)

    def _collect_external_ips(self):
        """Recolecta IPs externas del sniffer y DPI."""
        new_ips = set()

        try:
            if self.sniffer:
                for ip in list(self.sniffer.device_stats.keys()):
                    if ip and not is_private(ip):
                        new_ips.add(ip)
                for ip, _, _ in self.sniffer.get_top_talkers(20):
                    if ip and not is_private(ip):
                        new_ips.add(ip)
        except Exception:
            pass

        try:
            if self.dpi:
                for ip in self.dpi.get_external_ips():
                    if ip and not is_private(ip):
                        new_ips.add(ip)
        except Exception:
            pass

        # Solo agregar las que no están en cache válido
        for ip in new_ips:
            cached = self.cache.get(ip)
            if cached:
                with self._lock:
                    self._results[ip] = cached
            else:
                with self._lock:
                    self._pending_ips.add(ip)

    def _process_pending(self):
        """Procesa la cola de IPs pendientes."""
        with self._lock:
            pending = list(self._pending_ips)
            self._pending_ips.clear()

        if not pending:
            return

        print(f"\033[36m[TI] Verificando {len(pending)} IPs externas...\033[0m")

        for ip in pending:
            if not self._running:
                break
            try:
                result = self._check_ip(ip)
                self.cache.save(result)
                with self._lock:
                    self._results[ip] = result

                if result.is_malicious:
                    self._emit_threat_alert(result)
                    print(f"\033[31m[TI] 🚨 IP MALICIOSA: {ip} "
                          f"(score:{result.threat_score}) "
                          f"[{', '.join(result.sources)}]\033[0m")
                else:
                    logger.debug(f"[TI] {ip} → clean (score:{result.threat_score})")

                time.sleep(1.5)  # respetar rate limits

            except Exception as e:
                logger.error(f"[TI] Error verificando {ip}: {e}")

    # ── Verificación de IP individual ─────────────────────────────────────────

    def _check_ip(self, ip: str) -> ThreatResult:
        """Verifica una IP contra todas las fuentes disponibles."""
        result = ThreatResult(ip)

        # 1. Blocklists públicas (siempre, sin API key)
        bl_source = self.cache.is_in_blocklist(ip)
        if not bl_source and ip in self._blocklist_ips:
            bl_source = "blocklist_memory"

        if bl_source:
            result.in_blocklist = True
            result.threat_score = max(result.threat_score, 60)
            result.sources.append(bl_source)
            result.categories.append("blocklist")
            result.is_malicious = True

        # 2. AbuseIPDB (si hay key)
        if self.abuseipdb_key:
            self._check_abuseipdb(ip, result)
            time.sleep(0.5)

        # 3. VirusTotal (si hay key)
        if self.virustotal_key:
            self._check_virustotal(ip, result)
            time.sleep(0.5)

        # Determinar si es maliciosa
        result.is_malicious = (
            result.threat_score >= self.abuse_threshold or
            result.in_blocklist or
            result.virustotal_hits >= 3
        )

        return result

    def _check_abuseipdb(self, ip: str, result: ThreatResult):
        """Consulta AbuseIPDB API."""
        # Rate limit: 1000/día → ~1 req/86s, pero en ráfagas está bien
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(url)
            req.add_header("Key", self.abuseipdb_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            d = data.get('data', {})
            score = d.get('abuseConfidenceScore', 0)
            result.abuseipdb_score = score
            result.country = d.get('countryCode', '')
            result.isp     = d.get('isp', '')

            if d.get('lastReportedAt'):
                result.last_reported = d['lastReportedAt']

            # Categorías de abuso
            categories_map = {
                3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force',
                6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
                9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam',
                12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan',
                15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
                18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
                21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted',
            }
            for cat_id in d.get('usageType', {}).get('categories', []):
                cat_name = categories_map.get(cat_id, f"cat_{cat_id}")
                if cat_name not in result.categories:
                    result.categories.append(cat_name)

            if score >= self.abuse_threshold:
                result.threat_score = max(result.threat_score, score)
                result.sources.append("AbuseIPDB")
                logger.info(f"[TI] AbuseIPDB {ip}: score={score}")

        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("[TI] AbuseIPDB rate limit alcanzado")
            else:
                logger.error(f"[TI] AbuseIPDB error {e.code}: {e}")
        except Exception as e:
            logger.error(f"[TI] AbuseIPDB error para {ip}: {e}")

    def _check_virustotal(self, ip: str, result: ThreatResult):
        """Consulta VirusTotal API v3."""
        # Rate limit: 4 req/min gratuito
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            req = urllib.request.Request(url)
            req.add_header("x-apikey", self.virustotal_key)

            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())

            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious  = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total      = sum(stats.values()) if stats else 0

            result.virustotal_hits  = malicious + suspicious
            result.virustotal_total = total

            if malicious >= 3:
                vt_score = min(100, malicious * 5)
                result.threat_score = max(result.threat_score, vt_score)
                result.sources.append("VirusTotal")
                result.categories.append("malware")
                logger.info(f"[TI] VirusTotal {ip}: {malicious}/{total} detecciones")

        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("[TI] VirusTotal rate limit — esperando 60s")
                time.sleep(60)
            elif e.code == 404:
                pass  # IP no en base de datos VT, es normal
            else:
                logger.error(f"[TI] VirusTotal error {e.code}")
        except Exception as e:
            logger.error(f"[TI] VirusTotal error para {ip}: {e}")

    # ── Feeds públicos ────────────────────────────────────────────────────────

    def _blocklist_loop(self):
        """Descarga y actualiza blocklists públicas cada 6 horas."""
        time.sleep(5)
        while self._running:
            self._update_blocklists()
            time.sleep(6 * 3600)

    def _update_blocklists(self):
        """Descarga Emerging Threats y Feodo Tracker."""
        feeds = [
            (FEED_EMERGING_THREATS, "EmergingThreats"),
            (FEED_FEODO_TRACKER,    "FeodoTracker"),
        ]
        for url, name in feeds:
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "NeuralNetworkMap/2.0")
                with urllib.request.urlopen(req, timeout=15) as resp:
                    content = resp.read().decode('utf-8', errors='replace')

                ips = set()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Extraer solo la IP (ignorar CIDRs y comentarios)
                        ip = line.split()[0].split('/')[0]
                        if ip and not is_private(ip):
                            ips.add(ip)

                if ips:
                    self.cache.save_blocklist(ips, name)
                    self._blocklist_ips.update(ips)
                    print(f"\033[36m[TI] {name}: {len(ips)} IPs cargadas\033[0m")

            except Exception as e:
                logger.warning(f"[TI] Error descargando {name}: {e}")
                # No es crítico — continuar sin este feed

    # ── Emisión de alertas ────────────────────────────────────────────────────

    def _emit_threat_alert(self, result: ThreatResult):
        """Emite alerta CRITICAL al IDS para IPs maliciosas."""
        ip = result.ip
        if ip in self._alerted_ips:
            return
        self._alerted_ips.add(ip)

        sources_str = ", ".join(result.sources[:3])
        cats_str    = ", ".join(result.categories[:2]) if result.categories else "unknown"
        msg = (f"IP MALICIOSA detectada: {ip} "
               f"(score:{result.threat_score}) "
               f"[{sources_str}] — {cats_str}")

        if self.ids:
            try:
                from modules.ids import Alert
                alert = Alert("CRITICAL", "THREAT_INTEL", msg, ip=ip)
                alert.icon_override = "☠"
                self.ids._emit(alert)
            except Exception as e:
                logger.error(f"[TI] Error emitiendo alerta IDS: {e}")

        logger.warning(f"[TI] {msg}")

    # ── API pública ───────────────────────────────────────────────────────────

    def check_ip_now(self, ip: str) -> ThreatResult:
        """Verifica una IP inmediatamente (consulta + cache)."""
        if is_private(ip):
            r = ThreatResult(ip)
            r.error = "IP privada"
            return r

        cached = self.cache.get(ip)
        if cached:
            return cached

        result = self._check_ip(ip)
        self.cache.save(result)
        with self._lock:
            self._results[ip] = result
        return result

    def get_result(self, ip: str) -> Optional[ThreatResult]:
        """Retorna el resultado en memoria para una IP."""
        with self._lock:
            return self._results.get(ip)

    def get_all_results(self) -> Dict[str, dict]:
        """Todos los resultados en memoria."""
        with self._lock:
            return {ip: r.to_dict() for ip, r in self._results.items()}

    def get_threats(self) -> List[dict]:
        """Solo IPs marcadas como maliciosas."""
        return self.cache.get_all_threats(min_score=self.abuse_threshold)

    def get_stats(self) -> dict:
        """Estadísticas del motor."""
        with self._lock:
            total    = len(self._results)
            threats  = sum(1 for r in self._results.values() if r.is_malicious)
            pending  = len(self._pending_ips)
        return {
            'total_checked':   total,
            'threats_found':   threats,
            'pending':         pending,
            'blocklist_size':  len(self._blocklist_ips),
            'has_abuseipdb':   bool(self.abuseipdb_key),
            'has_virustotal':  bool(self.virustotal_key),
            'cache_db':        self.cache.db_path,
        }

    def is_malicious(self, ip: str) -> bool:
        """Chequeo rápido si una IP está marcada como maliciosa."""
        with self._lock:
            r = self._results.get(ip)
            if r:
                return r.is_malicious
        return ip in self._blocklist_ips
