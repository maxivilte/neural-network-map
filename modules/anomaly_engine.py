"""
modules/anomaly_engine.py
FASE 9 — ML Avanzado: Perfiles por dispositivo + Port Scan + Exfiltración

NUEVO en Fase 9:
  - Perfiles de comportamiento individual por dispositivo (baseline propio)
  - Detección de port scan: muchos puertos distintos en poco tiempo
  - Detección de exfiltración: gran volumen saliente a IPs externas inusuales
  - Z-score estadístico para detección rápida sin modelo entrenado
  - DBSCAN clustering para agrupar comportamientos similares
  - Features extendidas: paquetes/s, puertos únicos, ratio tx/rx, países únicos
  - Ventana deslizante de 5 minutos para detecciones en tiempo real

MANTIENE de Fase 8:
  - Isolation Forest por dispositivo
  - StandardScaler
  - AnomalyScore con niveles normal/suspicious/anomaly/critical
  - Callbacks al IDS
  - API pública get_score / get_all_scores / get_scores_summary

Instalar: pip install scikit-learn numpy scipy
"""

import time
import threading
import logging
import math
import os
import json
from typing import Dict, List, Optional, Callable, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("[ML] scikit-learn no disponible — pip install scikit-learn numpy")

try:
    from scipy import stats as scipy_stats
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False


# ─── Score de anomalía por dispositivo ───────────────────────────────────────

class AnomalyScore:
    def __init__(self, ip: str):
        self.ip        = ip
        self.score     = 0.0       # 0 = normal, 1 = máxima anomalía
        self.level     = "normal"  # normal / suspicious / anomaly / critical
        self.reasons:  List[str] = []
        self.timestamp = time.time()
        self.trained   = False
        # NUEVO Fase 9
        self.detection_method = "rules"  # rules / zscore / isolation_forest / dbscan
        self.port_scan_detected    = False
        self.exfiltration_detected = False

    @property
    def color(self) -> tuple:
        return {
            "normal":     (0, 200, 100),
            "suspicious": (255, 200, 0),
            "anomaly":    (255, 100, 0),
            "critical":   (255, 30, 30),
        }.get(self.level, (150, 150, 150))

    @property
    def icon(self) -> str:
        if self.port_scan_detected:
            return "🔍"
        if self.exfiltration_detected:
            return "📤"
        return {
            "normal":     "✓",
            "suspicious": "?",
            "anomaly":    "⚠",
            "critical":   "🚨",
        }.get(self.level, "·")

    def to_dict(self) -> dict:
        return {
            'ip':                   self.ip,
            'score':                round(self.score, 3),
            'level':                self.level,
            'reasons':              self.reasons,
            'trained':              self.trained,
            'timestamp':            self.timestamp,
            'icon':                 self.icon,
            'detection_method':     self.detection_method,
            'port_scan_detected':   self.port_scan_detected,
            'exfiltration_detected': self.exfiltration_detected,
        }


# ─── Perfil baseline por dispositivo ─────────────────────────────────────────

class DeviceProfile:
    """
    Perfil de comportamiento normal aprendido para un dispositivo específico.
    Mantiene estadísticas históricas para calcular Z-scores.
    """
    WINDOW_SIZE = 200  # máximo de muestras históricas

    def __init__(self, ip: str):
        self.ip = ip
        self.created_at = time.time()
        self.last_updated = time.time()

        # Historial de métricas (ventana deslizante)
        self._bytes_history:    deque = deque(maxlen=self.WINDOW_SIZE)
        self._packets_history:  deque = deque(maxlen=self.WINDOW_SIZE)
        self._ports_history:    deque = deque(maxlen=self.WINDOW_SIZE)
        self._dns_history:      deque = deque(maxlen=self.WINDOW_SIZE)
        self._hour_distribution: Dict[int, int] = defaultdict(int)  # hora -> frecuencia

        # Detección port scan: puertos vistos en ventana de tiempo
        self._recent_ports:     deque = deque(maxlen=500)  # (timestamp, port, dst_ip)
        self._recent_packets:   deque = deque(maxlen=1000) # (timestamp, dst_ip, size)

        # Baseline calculado
        self.baseline_bytes_mean   = 0.0
        self.baseline_bytes_std    = 1.0
        self.baseline_packets_mean = 0.0
        self.baseline_packets_std  = 1.0
        self.baseline_ports_mean   = 0.0
        self.baseline_ports_std    = 1.0
        self.sample_count          = 0

    def add_sample(self, bytes_val: float, packets: int, unique_ports: int, dns_count: int):
        """Agrega una muestra al perfil y recalcula el baseline."""
        hour = int(time.strftime('%H'))
        self._bytes_history.append(bytes_val)
        self._packets_history.append(packets)
        self._ports_history.append(unique_ports)
        self._dns_history.append(dns_count)
        self._hour_distribution[hour] += 1
        self.sample_count += 1
        self.last_updated = time.time()

        if self.sample_count >= 10:
            self._recalculate_baseline()

    def _recalculate_baseline(self):
        """Recalcula medias y desviaciones estándar del baseline."""
        if ML_AVAILABLE:
            self.baseline_bytes_mean   = float(np.mean(self._bytes_history))
            self.baseline_bytes_std    = max(1.0, float(np.std(self._bytes_history)))
            self.baseline_packets_mean = float(np.mean(self._packets_history))
            self.baseline_packets_std  = max(1.0, float(np.std(self._packets_history)))
            self.baseline_ports_mean   = float(np.mean(self._ports_history))
            self.baseline_ports_std    = max(0.5, float(np.std(self._ports_history)))
        else:
            # Fallback sin numpy
            blist = list(self._bytes_history)
            self.baseline_bytes_mean = sum(blist) / len(blist)
            self.baseline_bytes_std  = max(1.0, self._std_fallback(blist))
            plist = list(self._packets_history)
            self.baseline_packets_mean = sum(plist) / len(plist)
            self.baseline_packets_std  = max(1.0, self._std_fallback(plist))

    def _std_fallback(self, values: list) -> float:
        if len(values) < 2:
            return 1.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def get_zscore_bytes(self, current: float) -> float:
        """Z-score del volumen de bytes actual vs baseline."""
        if self.baseline_bytes_std == 0:
            return 0.0
        return (current - self.baseline_bytes_mean) / self.baseline_bytes_std

    def get_zscore_packets(self, current: int) -> float:
        if self.baseline_packets_std == 0:
            return 0.0
        return (current - self.baseline_packets_mean) / self.baseline_packets_std

    def is_unusual_hour(self, hour: int) -> bool:
        """Devuelve True si esta hora es inusual para este dispositivo."""
        if sum(self._hour_distribution.values()) < 50:
            return False  # sin suficientes datos
        total = sum(self._hour_distribution.values())
        freq = self._hour_distribution.get(hour, 0) / total
        return freq < 0.02  # menos del 2% de actividad histórica en esta hora

    def add_port_event(self, port: int, dst_ip: str):
        """Registra acceso a un puerto para detección de port scan."""
        self._recent_ports.append((time.time(), port, dst_ip))

    def add_packet_event(self, dst_ip: str, size: int):
        """Registra un paquete para detección de exfiltración."""
        self._recent_packets.append((time.time(), dst_ip, size))

    def detect_port_scan(self, window_seconds: int = 60, threshold: int = 15) -> Tuple[bool, str]:
        """
        Detecta port scan: muchos puertos distintos a distintas IPs en poco tiempo.
        Retorna (detectado, descripción).
        """
        now = time.time()
        cutoff = now - window_seconds

        # Filtrar eventos recientes
        recent = [(ts, port, dst) for ts, port, dst in self._recent_ports if ts > cutoff]
        if len(recent) < threshold:
            return False, ""

        unique_ports = len(set(port for _, port, _ in recent))
        unique_dsts  = len(set(dst for _, _, dst in recent))

        if unique_ports >= threshold:
            return True, f"Port scan: {unique_ports} puertos únicos en {window_seconds}s → {unique_dsts} destinos"

        return False, ""

    def detect_exfiltration(self, window_seconds: int = 300,
                             threshold_mb: float = 50.0,
                             local_prefix: str = "192.168.") -> Tuple[bool, str]:
        """
        Detecta exfiltración: gran volumen saliente a IPs externas en ventana de tiempo.
        Retorna (detectado, descripción).
        """
        now = time.time()
        cutoff = now - window_seconds

        # Solo paquetes a IPs externas
        external_bytes = sum(
            size for ts, dst_ip, size in self._recent_packets
            if ts > cutoff and not dst_ip.startswith(local_prefix)
            and not dst_ip.startswith("10.") and not dst_ip.startswith("172.")
        )

        mb = external_bytes / (1024 * 1024)
        if mb >= threshold_mb:
            return True, f"Posible exfiltración: {mb:.1f} MB a IPs externas en {window_seconds//60}min"

        return False, ""

    @property
    def is_ready(self) -> bool:
        return self.sample_count >= 10

    def to_dict(self) -> dict:
        return {
            'ip':           self.ip,
            'sample_count': self.sample_count,
            'baseline_bytes_mean':   round(self.baseline_bytes_mean, 2),
            'baseline_packets_mean': round(self.baseline_packets_mean, 2),
            'created_at':   self.created_at,
            'last_updated': self.last_updated,
            'is_ready':     self.is_ready,
        }


# ─── Motor principal ──────────────────────────────────────────────────────────

class AnomalyEngine:
    """
    Motor de detección de anomalías — Fase 9.

    Combina tres capas de detección:
    1. REGLAS básicas (siempre activo, sin ML)
    2. Z-SCORE estadístico por dispositivo (desde 10 muestras)
    3. ISOLATION FOREST por dispositivo (desde 20 muestras)
    + DBSCAN para clustering de comportamientos similares

    Detecciones especializadas:
    - Port scan en tiempo real (ventana 60s)
    - Exfiltración de datos (ventana 5min)
    - Actividad en hora inusual para ese dispositivo específico
    """

    MIN_SAMPLES_TO_TRAIN   = 20
    MIN_SAMPLES_FOR_ZSCORE = 10
    EVAL_INTERVAL          = 60      # evaluar cada 60s (antes 120s)
    TRAIN_INTERVAL         = 600
    ANOMALY_THRESHOLD      = 0.6
    CRITICAL_THRESHOLD     = 0.85
    MODEL_DIR              = "logs/ml_models"

    # Parámetros detección especializada
    PORT_SCAN_WINDOW       = 60      # segundos
    PORT_SCAN_THRESHOLD    = 15      # puertos únicos
    EXFIL_WINDOW           = 300     # segundos (5 min)
    EXFIL_THRESHOLD_MB     = 50.0    # MB

    # IPs/rangos de streaming — nunca marcar como exfiltración
    STREAMING_IP_PREFIXES = (
        "23.246.", "37.77.", "198.38.", "208.75.",   # Netflix
        "142.250.", "142.251.", "172.217.", "216.58.", # Google/YouTube
        "151.101.",                                    # Twitch/Fastly
        "205.251.", "13.224.", "13.225.", "13.226.",  # Amazon CloudFront
        "104.16.", "104.17.", "104.18.", "104.19.",   # Cloudflare
        "172.64.", "172.65.", "172.66.", "172.67.",   # Cloudflare
    )

    # Tipos de dispositivos que hacen streaming legítimo a cualquier hora
    STREAMING_DEVICE_TYPES = {"smart_tv", "game"}

    def __init__(self, dpi, ids=None, sniffer=None, host_ip=None):
        self.dpi     = dpi
        self.ids     = ids
        self.sniffer = sniffer
        self.host_ip = host_ip  # IP del host que corre NNM — excluir de alertas
        self._lock   = threading.Lock()

        # ip -> IsolationForest
        self._models:  Dict[str, object] = {}
        # ip -> StandardScaler
        self._scalers: Dict[str, object] = {}
        # ip -> AnomalyScore
        self._scores:  Dict[str, AnomalyScore] = {}
        # ip -> DeviceProfile (NUEVO Fase 9)
        self._profiles: Dict[str, DeviceProfile] = {}

        self._callbacks: List[Callable] = []
        self._running    = False
        self._last_train = defaultdict(float)

        os.makedirs(self.MODEL_DIR, exist_ok=True)

        if not ML_AVAILABLE:
            print("\033[33m[ML] scikit-learn no disponible — modo reglas + Z-score básico\033[0m")
        else:
            print("\033[32m[ML] Isolation Forest + Z-score + DBSCAN disponibles\033[0m")

    def register_callback(self, cb: Callable):
        self._callbacks.append(cb)

    def start(self):
        self._running = True
        threading.Thread(target=self._eval_loop,         daemon=True).start()
        threading.Thread(target=self._train_loop,        daemon=True).start()
        threading.Thread(target=self._profile_loop,      daemon=True).start()  # NUEVO
        threading.Thread(target=self._realtime_loop,     daemon=True).start()  # NUEVO
        print("\033[32m[ML] Motor de anomalías Fase 9 iniciado\033[0m")

    def stop(self):
        self._running = False

    # ── Perfil por dispositivo (NUEVO Fase 9) ─────────────────────────────────

    def _get_or_create_profile(self, ip: str) -> DeviceProfile:
        """Obtiene o crea el perfil de un dispositivo."""
        with self._lock:
            if ip not in self._profiles:
                self._profiles[ip] = DeviceProfile(ip)
            return self._profiles[ip]

    def _profile_loop(self):
        """Actualiza los perfiles de dispositivos cada 60s."""
        time.sleep(30)
        while self._running:
            self._update_all_profiles()
            time.sleep(60)

    def _update_all_profiles(self):
        """Recolecta muestras del DPI y actualiza todos los perfiles."""
        if not self.dpi:
            return

        for ip in self.dpi.get_active_devices():
            try:
                profile = self._get_or_create_profile(ip)

                bytes_val   = self.dpi.get_device_bytes(ip)
                rate        = self.dpi.get_device_rate(ip)
                activities  = self.dpi.get_device_activity(ip, limit=100)
                unique_ports = len(set(a.get('port', 0) for a in activities if a.get('port')))
                dns_count   = len(self.dpi.get_device_dns(ip)) if hasattr(self.dpi, 'get_device_dns') else 0

                profile.add_sample(
                    bytes_val   = bytes_val,
                    packets     = int(rate / max(1, 1500)),  # estimación
                    unique_ports = unique_ports,
                    dns_count   = dns_count,
                )
            except Exception as e:
                logger.debug(f"[ML] Error actualizando perfil {ip}: {e}")

    # ── Loop en tiempo real para port scan y exfiltración (NUEVO) ────────────

    def _realtime_loop(self):
        """
        Monitorea en tiempo real eventos del sniffer para detectar
        port scan y exfiltración sin esperar al ciclo de evaluación.
        """
        if not self.sniffer:
            return

        checked_at = defaultdict(float)

        while self._running:
            time.sleep(10)  # chequear cada 10 segundos
            now = time.time()

            # Alimentar perfiles con eventos recientes del sniffer
            try:
                events = self.sniffer.get_recent_events(limit=200)
                for event in events:
                    if not event.src_ip:
                        continue
                    profile = self._get_or_create_profile(event.src_ip)

                    # Registrar puertos accedidos
                    if hasattr(event, 'info') and event.info.startswith(':'):
                        try:
                            port = int(event.info[1:])
                            profile.add_port_event(port, event.dst_ip)
                        except ValueError:
                            pass

                    # Registrar paquetes para exfiltración
                    profile.add_packet_event(event.dst_ip, event.size)

                # Chequear port scan y exfiltración por dispositivo
                for ip, profile in list(self._profiles.items()):
                    if now - checked_at[ip] < 30:  # no más de cada 30s por IP
                        continue
                    checked_at[ip] = now

                    self._check_port_scan(ip, profile)
                    self._check_exfiltration(ip, profile)

            except Exception as e:
                logger.debug(f"[ML] Error en realtime_loop: {e}")

    def _check_port_scan(self, ip: str, profile: DeviceProfile):
        """Chequea y alerta si hay port scan activo."""
        # El host NNM hace scans propios — nunca alertar
        if self._is_host_ip(ip):
            return
        detected, description = profile.detect_port_scan(
            window_seconds=self.PORT_SCAN_WINDOW,
            threshold=self.PORT_SCAN_THRESHOLD,
        )
        if detected:
            with self._lock:
                if ip not in self._scores:
                    self._scores[ip] = AnomalyScore(ip)
                score = self._scores[ip]
                if not score.port_scan_detected:  # evitar spam de alertas
                    score.port_scan_detected = True
                    score.score = max(score.score, 0.75)
                    score.level = "critical"
                    score.reasons = [description] + score.reasons[:2]
                    score.detection_method = "realtime_portscan"

            self._emit_alert_msg(ip, "CRITICAL", "PORT_SCAN", description)

    def _check_exfiltration(self, ip: str, profile: DeviceProfile):
        """Chequea y alerta si hay posible exfiltración."""
        # El host NNM genera tráfico legítimo — nunca alertar
        if self._is_host_ip(ip):
            return
        detected, description = profile.detect_exfiltration(
            window_seconds=self.EXFIL_WINDOW,
            threshold_mb=self.EXFIL_THRESHOLD_MB,
        )
        if detected:
            # No alertar si el tráfico va a IPs de streaming conocidas
            if self._is_streaming_ip(ip):
                logger.debug(f"[ML] Exfiltración ignorada (streaming): {ip}")
                return
            with self._lock:
                if ip not in self._scores:
                    self._scores[ip] = AnomalyScore(ip)
                score = self._scores[ip]
                if not score.exfiltration_detected:
                    score.exfiltration_detected = True
                    score.score = max(score.score, 0.80)
                    score.level = "critical"
                    score.reasons = [description] + score.reasons[:2]
                    score.detection_method = "realtime_exfiltration"

            self._emit_alert_msg(ip, "CRITICAL", "EXFILTRATION", description)

    # ── Feature extraction (extendido Fase 9) ────────────────────────────────

    def _extract_features(self, sample: dict, profile: Optional[DeviceProfile] = None) -> Optional[List[float]]:
        """
        Vector de features extendido para el modelo ML.

        Features (11 en total):
        0:  hora del día normalizada (0-1)
        1:  bytes acumulados (log scale)
        2:  tasa de bytes/s normalizada
        3:  cantidad DNS queries normalizada
        4:  servicios distintos normalizados
        5:  es horario nocturno (binario)
        6:  es horario laboral (binario)
        7:  [NUEVO] paquetes por segundo estimado
        8:  [NUEVO] puertos únicos normalizados
        9:  [NUEVO] Z-score de bytes (vs baseline propio)
        10: [NUEVO] Z-score de packets (vs baseline propio)
        """
        try:
            hour      = sample.get('hour', 12)
            bytes_val = max(1, sample.get('bytes', 0))
            rate      = sample.get('rate', 0.0)
            dns       = sample.get('dns_count', 0)
            services  = sample.get('services', 0)
            packets   = sample.get('packets', 0)
            ports     = sample.get('unique_ports', 0)

            # Z-scores individuales si hay perfil
            z_bytes   = 0.0
            z_packets = 0.0
            if profile and profile.is_ready:
                z_bytes   = max(-3.0, min(3.0, profile.get_zscore_bytes(bytes_val)))
                z_packets = max(-3.0, min(3.0, profile.get_zscore_packets(packets)))
                z_bytes   = (z_bytes + 3.0) / 6.0    # normalizar a [0,1]
                z_packets = (z_packets + 3.0) / 6.0

            return [
                hour / 23.0,
                math.log10(bytes_val),
                min(rate / 1e6, 1.0),
                min(dns / 50.0, 1.0),
                min(services / 20.0, 1.0),
                1.0 if hour < 6 else 0.0,
                1.0 if 9 <= hour <= 18 else 0.0,
                min(packets / 1000.0, 1.0),          # paquetes/s normalizado
                min(ports / 50.0, 1.0),              # puertos únicos normalizados
                z_bytes,                             # Z-score bytes individual
                z_packets,                           # Z-score packets individual
            ]
        except Exception:
            return None

    # ── Z-score standalone (sin modelo entrenado) ─────────────────────────────

    def _eval_zscore(self, ip: str, profile: DeviceProfile) -> Tuple[float, List[str]]:
        """
        Evaluación rápida por Z-score usando el perfil baseline del dispositivo.
        Disponible desde 10 muestras (antes que el Isolation Forest con 20).
        """
        if not profile.is_ready or not self.dpi:
            return 0.0, []

        score   = 0.0
        reasons = []

        try:
            bytes_val = self.dpi.get_device_bytes(ip)
            rate      = self.dpi.get_device_rate(ip)
            hour      = int(time.strftime('%H'))

            # Z-score de bytes
            z = profile.get_zscore_bytes(bytes_val)
            if z > 3.0:
                score += min(0.4, (z - 3.0) * 0.1)
                reasons.append(f"Volumen {z:.1f}σ sobre su propio baseline ({bytes_val/1024/1024:.1f} MB)")

            # Z-score de tasa
            if rate > profile.baseline_bytes_mean * 5 and profile.baseline_bytes_mean > 0:
                score += 0.3
                reasons.append(f"Tasa 5x sobre su normal ({rate/1024:.0f} KB/s)")

            # Hora inusual para este dispositivo específico
            if profile.is_unusual_hour(hour):
                score += 0.25
                reasons.append(f"Activo a las {hour}:00 — hora inusual para este dispositivo")

        except Exception as e:
            logger.debug(f"[ML] Error Z-score {ip}: {e}")

        return min(score, 1.0), reasons

    # ── DBSCAN clustering (NUEVO Fase 9) ─────────────────────────────────────

    def _run_dbscan(self):
        """
        Agrupa dispositivos por comportamiento similar con DBSCAN.
        Los dispositivos que no pertenecen a ningún cluster = outliers.
        """
        if not ML_AVAILABLE:
            return

        try:
            profiles_ready = {
                ip: p for ip, p in self._profiles.items() if p.is_ready
            }
            if len(profiles_ready) < 3:
                return

            ips = list(profiles_ready.keys())
            features = []
            for ip in ips:
                p = profiles_ready[ip]
                features.append([
                    p.baseline_bytes_mean / max(1, p.baseline_bytes_mean + 1),
                    p.baseline_packets_mean / max(1, p.baseline_packets_mean + 1),
                    p.baseline_ports_mean / max(1, 50),
                ])

            X = np.array(features)
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            db = DBSCAN(eps=0.5, min_samples=2)
            labels = db.fit_predict(X_scaled)

            # Outliers (label = -1) son dispositivos con comportamiento único
            for i, (ip, label) in enumerate(zip(ips, labels)):
                if label == -1:
                    with self._lock:
                        if ip not in self._scores:
                            self._scores[ip] = AnomalyScore(ip)
                        s = self._scores[ip]
                        if s.score < 0.35:  # solo agregar si no hay alerta mayor
                            s.score = max(s.score, 0.35)
                            s.detection_method = "dbscan"
                            if "Comportamiento único (outlier DBSCAN)" not in s.reasons:
                                s.reasons.append("Comportamiento único (outlier DBSCAN)")
                            if s.level == "normal":
                                s.level = "suspicious"

        except Exception as e:
            logger.debug(f"[ML] Error DBSCAN: {e}")

    # ── Entrenamiento ─────────────────────────────────────────────────────────

    def _train_loop(self):
        time.sleep(60)
        while self._running:
            self._train_all()
            self._run_dbscan()  # NUEVO: ejecutar DBSCAN también
            time.sleep(self.TRAIN_INTERVAL)

    def _train_all(self):
        if not ML_AVAILABLE:
            return

        history = self.dpi.get_all_traffic_history()

        for ip, samples in history.items():
            if len(samples) < self.MIN_SAMPLES_TO_TRAIN:
                continue

            now = time.time()
            if now - self._last_train.get(ip, 0) < self.TRAIN_INTERVAL:
                continue

            profile = self._profiles.get(ip)
            features = []
            for s in samples:
                f = self._extract_features(s, profile)
                if f:
                    features.append(f)

            if len(features) < self.MIN_SAMPLES_TO_TRAIN:
                continue

            try:
                X = np.array(features)
                scaler = StandardScaler()
                X_scaled = scaler.fit_transform(X)

                model = IsolationForest(
                    n_estimators=100,
                    contamination=0.1,
                    random_state=42,
                    n_jobs=-1,
                )
                model.fit(X_scaled)

                with self._lock:
                    self._models[ip]  = model
                    self._scalers[ip] = scaler
                    self._last_train[ip] = now
                    if ip not in self._scores:
                        self._scores[ip] = AnomalyScore(ip)
                    self._scores[ip].trained = True

                print(f"\033[32m[ML] ✓ Modelo IF entrenado: {ip} ({len(features)} muestras)\033[0m")

            except Exception as e:
                logger.error(f"[ML] Error entrenando modelo {ip}: {e}")

    # ── Evaluación ────────────────────────────────────────────────────────────

    def _eval_loop(self):
        while self._running:
            time.sleep(self.EVAL_INTERVAL)
            self._eval_all()

    def _eval_all(self):
        # Dispositivos con Isolation Forest entrenado
        for ip in list(self._models.keys()):
            self._eval_device_if(ip)

        # Dispositivos con perfil pero sin modelo (usar Z-score)
        for ip, profile in list(self._profiles.items()):
            if ip not in self._models and profile.is_ready:
                self._eval_device_zscore(ip, profile)

        # Dispositivos sin perfil (reglas básicas)
        if self.dpi:
            for ip in self.dpi.get_active_devices():
                if ip not in self._models and ip not in self._profiles:
                    self._eval_rules(ip)

    def _eval_device_if(self, ip: str):
        """Evalúa con Isolation Forest + Z-score combinados."""
        if not ML_AVAILABLE:
            self._eval_rules(ip)
            return

        history = self.dpi.get_traffic_history(ip)
        if not history:
            return

        latest  = history[-1]
        profile = self._profiles.get(ip)
        features = self._extract_features(latest, profile)
        if not features:
            return

        try:
            model  = self._models.get(ip)
            scaler = self._scalers.get(ip)
            if not model or not scaler:
                return

            X        = np.array([features])
            X_scaled = scaler.transform(X)
            raw_score = model.decision_function(X_scaled)[0]
            if_score  = max(0.0, min(1.0, (-raw_score + 0.5)))

            # Combinar con Z-score si hay perfil
            z_score, z_reasons = 0.0, []
            if profile and profile.is_ready:
                z_score, z_reasons = self._eval_zscore(ip, profile)

            # Score final: máximo ponderado entre IF y Z-score
            final_score = max(if_score, z_score * 0.8)

            reasons = self._explain_anomaly(ip, latest, features, final_score)
            reasons = (z_reasons + reasons)[:4]  # combinar razones

            method = "isolation_forest"
            if z_score > if_score:
                method = "zscore+isolation_forest"

            self._update_score(ip, final_score, reasons, trained=True, method=method)

        except Exception as e:
            logger.error(f"[ML] Error evaluando IF {ip}: {e}")

    def _eval_device_zscore(self, ip: str, profile: DeviceProfile):
        """Evalúa solo con Z-score cuando no hay modelo IF aún."""
        z_score, reasons = self._eval_zscore(ip, profile)
        self._update_score(ip, z_score, reasons, trained=False, method="zscore")

    def _is_streaming_ip(self, ip: str) -> bool:
        """Retorna True si la IP pertenece a un servicio de streaming conocido."""
        return any(ip.startswith(prefix) for prefix in self.STREAMING_IP_PREFIXES)

    def _is_host_ip(self, ip: str) -> bool:
        """Retorna True si la IP es el host que corre NNM — nunca alertar."""
        if not ip:
            return False
        if self.host_ip and ip == self.host_ip:
            return True
        # También excluir IPs del host en ambas interfaces (192.168.1.41 y .4)
        if self.ids and hasattr(self.ids, 'settings'):
            trusted = getattr(self.ids.settings, 'trusted_devices', {})
            if ip in trusted and trusted[ip] == "NNM_HOST":
                return True
        return False

    def _is_streaming_device(self, ip: str) -> bool:
        """Retorna True si el dispositivo es Smart TV o consola (streaming legítimo)."""
        if self.dpi:
            try:
                activity = self.dpi.get_device_activity(ip, limit=10)
                for a in activity:
                    service = a.get('service', '').lower()
                    if any(s in service for s in ['netflix', 'youtube', 'twitch',
                                                   'disney', 'spotify', 'prime',
                                                   'tiktok', 'hbo', 'steam']):
                        return True
            except Exception:
                pass
        return False

    def _eval_rules(self, ip: str):
        """Detección basada en reglas (siempre disponible)."""
        # Nunca evaluar el host que corre NNM
        if self._is_host_ip(ip):
            return
        if not self.dpi:
            return

        hour    = int(time.strftime('%H'))
        score   = 0.0
        reasons = []

        rate        = self.dpi.get_device_rate(ip)
        bytes_total = self.dpi.get_device_bytes(ip)
        activities  = self.dpi.get_device_activity(ip, limit=50)

        if 0 <= hour <= 5 and rate > 10000:
            # No alertar si es dispositivo de streaming (Smart TV, consola)
            if not self._is_streaming_device(ip):
                score   += 0.3
                reasons.append(f"Tráfico nocturno ({hour}h): {rate/1024:.1f} KB/s")

        if bytes_total > 500 * 1024 * 1024:
            # No alertar si el tráfico va a IPs de streaming
            if not self._is_streaming_ip(ip) and not self._is_streaming_device(ip):
                score   += 0.2
                reasons.append(f"Volumen alto: {bytes_total/1024/1024:.0f} MB acumulados")

        if rate > 5 * 1024 * 1024:
            score   += 0.4
            reasons.append(f"Tasa extrema: {rate/1024/1024:.1f} MB/s")

        if len(activities) > 15:
            score   += 0.2
            reasons.append(f"Muchos servicios distintos: {len(activities)}")

        self._update_score(ip, min(score, 1.0), reasons, trained=False, method="rules")

    def _explain_anomaly(self, ip: str, sample: dict,
                          features: List[float], score: float) -> List[str]:
        reasons = []
        hour = sample.get('hour', 12)
        rate = sample.get('rate', 0)
        dns  = sample.get('dns_count', 0)

        if score > self.ANOMALY_THRESHOLD:
            if hour < 5:
                reasons.append(f"Activo a las {hour}:00 AM (inusual)")
            if rate > 1_000_000:
                reasons.append(f"Tasa alta: {rate/1024/1024:.1f} MB/s")
            if dns > 30:
                reasons.append(f"DNS excesivo: {dns} queries/min")
            # NUEVO: explicar Z-scores altos
            if len(features) > 9 and features[9] > 0.75:  # z_bytes normalizado
                reasons.append("Volumen muy por encima del baseline personal")
            if len(features) > 10 and features[10] > 0.75:
                reasons.append("Paquetes muy por encima del baseline personal")

        return reasons if reasons else ["Patrón de tráfico inusual"]

    def _update_score(self, ip: str, score: float, reasons: List[str],
                       trained: bool = True, method: str = "rules"):
        with self._lock:
            if ip not in self._scores:
                self._scores[ip] = AnomalyScore(ip)

            prev_level = self._scores[ip].level
            s          = self._scores[ip]
            s.score    = score
            s.reasons  = reasons
            s.trained  = trained
            s.timestamp = time.time()
            s.detection_method = method

            if score >= self.CRITICAL_THRESHOLD:
                s.level = "critical"
            elif score >= self.ANOMALY_THRESHOLD:
                s.level = "anomaly"
            elif score >= 0.35:
                s.level = "suspicious"
            else:
                s.level = "normal"
                # Reset flags cuando vuelve a normal
                s.port_scan_detected    = False
                s.exfiltration_detected = False

        if s.level in ("anomaly", "critical") and prev_level in ("normal", "suspicious"):
            self._emit_alert(ip, s)

    # ── Emisión de alertas ────────────────────────────────────────────────────

    def _emit_alert(self, ip: str, score: AnomalyScore):
        reasons_str = " | ".join(score.reasons[:2])
        severity    = "CRITICAL" if score.level == "critical" else "WARN"
        method_tag  = f"[{score.detection_method.upper()}]"
        msg         = f"Anomalía {method_tag} en {ip} (score:{score.score:.2f}): {reasons_str}"

        logger.warning(f"[ML] {msg}")
        print(f"\033[31m[ML] 🚨 {msg}\033[0m")

        if self.ids:
            try:
                from modules.ids import Alert
                alert = Alert(severity, "ML_ANOMALY", msg, ip=ip)
                alert.icon_override = score.icon
                self.ids._emit(alert)
            except Exception as e:
                logger.error(f"[ML] Error enviando alerta al IDS: {e}")

        for cb in self._callbacks:
            try:
                cb(ip, score)
            except Exception:
                pass

    def _emit_alert_msg(self, ip: str, severity: str, category: str, message: str):
        """Emite alerta directa al IDS (para port scan / exfiltración en tiempo real)."""
        print(f"\033[31m[ML] 🚨 {category} {ip}: {message}\033[0m")
        if self.ids:
            try:
                from modules.ids import Alert
                alert = Alert(severity, f"ML_{category}", message, ip=ip)
                self.ids._emit(alert)
            except Exception as e:
                logger.error(f"[ML] Error emitiendo alerta {category}: {e}")

    # ── API pública ───────────────────────────────────────────────────────────

    def get_score(self, ip: str) -> Optional[AnomalyScore]:
        with self._lock:
            return self._scores.get(ip)

    def get_all_scores(self) -> Dict[str, AnomalyScore]:
        with self._lock:
            return dict(self._scores)

    def get_scores_summary(self) -> List[dict]:
        with self._lock:
            result = [s.to_dict() for s in self._scores.values()]
            result.sort(key=lambda x: x['score'], reverse=True)
            return result

    def get_anomalies(self) -> List[dict]:
        return [s for s in self.get_scores_summary()
                if s['level'] in ('anomaly', 'critical', 'suspicious')]

    def get_device_profile(self, ip: str) -> Optional[dict]:
        """NUEVO: Retorna el perfil baseline de un dispositivo."""
        with self._lock:
            p = self._profiles.get(ip)
            return p.to_dict() if p else None

    def get_all_profiles(self) -> List[dict]:
        """NUEVO: Retorna todos los perfiles de dispositivos."""
        with self._lock:
            return [p.to_dict() for p in self._profiles.values()]

    def is_trained(self, ip: str) -> bool:
        return ip in self._models

    def get_model_stats(self) -> dict:
        with self._lock:
            profiles_ready = sum(1 for p in self._profiles.values() if p.is_ready)
            return {
                'total_models':        len(self._models),
                'ml_available':        ML_AVAILABLE,
                'scipy_available':     SCIPY_AVAILABLE,
                'devices_scored':      len(self._scores),
                'devices_profiled':    len(self._profiles),
                'profiles_ready':      profiles_ready,
                'anomalies':           sum(1 for s in self._scores.values()
                                          if s.level in ('anomaly', 'critical')),
                'port_scans_active':   sum(1 for s in self._scores.values()
                                          if s.port_scan_detected),
                'exfiltrations_active': sum(1 for s in self._scores.values()
                                           if s.exfiltration_detected),
            }
