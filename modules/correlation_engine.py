"""
modules/correlation_engine.py
FASE 14 — Motor de Correlación de Eventos

Detecta ataques complejos cruzando datos de múltiples fuentes:
  IDS + ML Anomaly + Threat Intel + DPI

Patrones detectados:
  - RECON_TO_EXPLOIT   : port scan seguido de conexión a puerto descubierto
  - LATERAL_MOVEMENT   : un dispositivo interno ataca a otro interno
  - DATA_EXFILTRATION  : anomalía ML + tráfico saliente alto + IP maliciosa
  - BRUTE_FORCE        : múltiples alertas de AUTH en corto tiempo
  - C2_BEACON_CONFIRM  : beaconing confirmado + IP en Threat Intel
  - MULTI_STAGE_ATTACK : 3+ etapas de un ataque en secuencia
  - COMPROMISED_HOST   : dispositivo interno contacta C2 + exfiltra datos
  - INSIDER_THREAT     : dispositivo normal escanea la red interna

Uso en main.py:
    from modules.correlation_engine import CorrelationEngine
    correlator = CorrelationEngine(ids=ids, anomaly_engine=anomaly_engine,
                                   threat_intel=threat_intel, dpi=dpi, db=db)
    correlator.start()
"""

import time
import threading
import logging
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


# ─── Evento normalizado ───────────────────────────────────────────────────────

@dataclass
class CorrelationEvent:
    """Evento normalizado desde cualquier fuente."""
    source:    str        # 'ids' | 'ml' | 'threat_intel' | 'dpi'
    event_type: str       # 'port_scan' | 'ml_anomaly' | 'threat_ip' | 'high_traffic' etc.
    ip:        str
    severity:  str        # INFO | WARN | CRITICAL
    data:      dict = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


# ─── Incidente correlacionado ─────────────────────────────────────────────────

@dataclass
class CorrelatedIncident:
    """Incidente detectado por correlación de múltiples eventos."""
    incident_id:  str
    pattern:      str        # nombre del patrón detectado
    severity:     str        # WARN | CRITICAL | EMERGENCY
    ip:           str        # IP principal involucrada
    related_ips:  List[str]
    events:       List[CorrelationEvent]
    description:  str
    confidence:   float      # 0.0 – 1.0
    timestamp:    float = field(default_factory=time.time)
    resolved:     bool = False

    @property
    def icon(self) -> str:
        return {
            'RECON_TO_EXPLOIT':   '🎯',
            'LATERAL_MOVEMENT':   '↔',
            'DATA_EXFILTRATION':  '📤',
            'BRUTE_FORCE':        '🔨',
            'C2_BEACON_CONFIRM':  '📡',
            'MULTI_STAGE_ATTACK': '⚔',
            'COMPROMISED_HOST':   '☠',
            'INSIDER_THREAT':     '🕵',
        }.get(self.pattern, '⚡')

    def to_dict(self) -> dict:
        return {
            'id':          self.incident_id,
            'pattern':     self.pattern,
            'severity':    self.severity,
            'icon':        self.icon,
            'ip':          self.ip,
            'related_ips': self.related_ips,
            'description': self.description,
            'confidence':  round(self.confidence, 2),
            'timestamp':   self.timestamp,
            'resolved':    self.resolved,
            'event_count': len(self.events),
        }


# ─── Motor de correlación ─────────────────────────────────────────────────────

class CorrelationEngine:
    """
    Motor de correlación de eventos — Fase 14.
    Cruza datos de IDS, ML, Threat Intel y DPI para detectar ataques complejos.
    """

    # Ventana de tiempo para correlacionar eventos (segundos)
    WINDOW_RECON        = 300   # 5 min: port scan → exploit
    WINDOW_LATERAL      = 600   # 10 min: movimiento lateral
    WINDOW_EXFIL        = 900   # 15 min: exfiltración
    WINDOW_BRUTE        = 120   # 2 min: brute force
    WINDOW_MULTISTAGE   = 1800  # 30 min: ataque multi-etapa

    # Umbrales
    MIN_BRUTE_ALERTS    = 5     # alertas para considerar brute force
    MIN_STAGES          = 3     # etapas para multi-stage

    # IPs de la red local — se actualiza desde settings
    PRIVATE_PREFIXES = ('192.168.', '10.', '172.16.', '172.17.', '172.18.',
                        '172.19.', '172.2', '172.3')

    def __init__(self, ids=None, anomaly_engine=None, threat_intel=None,
                 dpi=None, db=None, settings=None):
        self.ids            = ids
        self.anomaly_engine = anomaly_engine
        self.threat_intel   = threat_intel
        self.dpi            = dpi
        self.db             = db
        self.settings       = settings

        # Historial de eventos por IP — deque con límite de tiempo
        self._events:    Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # Todos los eventos recientes (ventana deslizante global)
        self._all_events: deque = deque(maxlen=2000)

        # Incidentes detectados
        self._incidents: List[CorrelatedIncident] = []
        self._incident_counter = 0

        # Set de IDs de alertas ya procesadas (evitar duplicados)
        self._processed_alert_ids: Set[str] = set()

        # Cooldown por patrón+IP para no re-emitir el mismo incidente
        self._cooldowns: Dict[str, float] = {}
        self._cooldown_sec = 300  # 5 min entre incidentes del mismo tipo+IP

        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

        logger.info("[Correlator] Motor de correlación inicializado")
        print("\033[35m[Correlator] Motor de correlación Fase 14 inicializado\033[0m")

    # ── Inicio ────────────────────────────────────────────────────────────────

    def start(self):
        """Inicia el motor en background."""
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        print("\033[32m[+] Motor de correlación de eventos iniciado\033[0m")

    def _run_loop(self):
        """Loop principal — analiza eventos cada 15 segundos."""
        time.sleep(30)  # esperar que los otros módulos inicien
        while True:
            try:
                self._ingest_from_ids()
                self._ingest_from_ml()
                self._ingest_from_threat_intel()
                self._run_correlations()
                self._cleanup_old_events()
            except Exception as e:
                logger.error(f"[Correlator] Error en loop: {e}")
            time.sleep(15)

    # ── Ingesta de eventos ────────────────────────────────────────────────────

    def _ingest_from_ids(self):
        """Lee alertas recientes del IDS y las normaliza."""
        if not self.ids:
            return
        try:
            for alert in self.ids.get_recent_alerts(50):
                alert_id = f"ids_{alert.ip}_{alert.timestamp:.0f}_{alert.category}"
                if alert_id in self._processed_alert_ids:
                    continue
                self._processed_alert_ids.add(alert_id)

                event = CorrelationEvent(
                    source='ids',
                    event_type=alert.category.lower(),
                    ip=alert.ip or '',
                    severity=alert.severity,
                    data={
                        'message':  alert.message,
                        'category': alert.category,
                    },
                    timestamp=alert.timestamp,
                )
                self._add_event(event)
        except Exception as e:
            logger.debug(f"[Correlator] Error ingesta IDS: {e}")

    def _ingest_from_ml(self):
        """Lee scores de anomalía del motor ML."""
        if not self.anomaly_engine:
            return
        try:
            for score in self.anomaly_engine.get_scores_summary():
                if score['level'] not in ('anomaly', 'critical', 'suspicious'):
                    continue
                event_id = f"ml_{score['ip']}_{int(score['timestamp'])}"
                if event_id in self._processed_alert_ids:
                    continue
                self._processed_alert_ids.add(event_id)

                event = CorrelationEvent(
                    source='ml',
                    event_type='ml_anomaly',
                    ip=score['ip'],
                    severity='CRITICAL' if score['level'] == 'critical' else 'WARN',
                    data={
                        'score':   score['score'],
                        'level':   score['level'],
                        'reasons': score.get('reasons', []),
                        'port_scan':   score.get('port_scan_detected', False),
                        'exfiltration': score.get('exfiltration_detected', False),
                        'method':  score.get('detection_method', 'rules'),
                    },
                    timestamp=score['timestamp'],
                )
                self._add_event(event)
        except Exception as e:
            logger.debug(f"[Correlator] Error ingesta ML: {e}")

    def _ingest_from_threat_intel(self):
        """Lee IPs maliciosas de Threat Intel."""
        if not self.threat_intel:
            return
        try:
            threats = self.threat_intel.get_threats() if hasattr(self.threat_intel, 'get_threats') else []
            for threat in threats:
                event_id = f"ti_{threat.get('ip','')}_{int(threat.get('timestamp', time.time()))}"
                if event_id in self._processed_alert_ids:
                    continue
                self._processed_alert_ids.add(event_id)

                event = CorrelationEvent(
                    source='threat_intel',
                    event_type='threat_ip',
                    ip=threat.get('ip', ''),
                    severity='CRITICAL',
                    data={
                        'threat_score': threat.get('threat_score', 0),
                        'sources':      threat.get('sources', []),
                        'categories':   threat.get('categories', []),
                        'level':        threat.get('level', 'medium'),
                    },
                    timestamp=threat.get('timestamp', time.time()),
                )
                self._add_event(event)
        except Exception as e:
            logger.debug(f"[Correlator] Error ingesta ThreatIntel: {e}")

    def _add_event(self, event: CorrelationEvent):
        """Agrega un evento al historial."""
        with self._lock:
            if event.ip:
                self._events[event.ip].append(event)
            self._all_events.append(event)

    # ── Correlaciones ─────────────────────────────────────────────────────────

    def _run_correlations(self):
        """Ejecuta todos los patrones de correlación."""
        self._detect_recon_to_exploit()
        self._detect_lateral_movement()
        self._detect_data_exfiltration()
        self._detect_brute_force()
        self._detect_c2_beacon_confirm()
        self._detect_compromised_host()
        self._detect_insider_threat()
        self._detect_multi_stage()

    def _get_events_for_ip(self, ip: str, window: float,
                           event_types: List[str] = None) -> List[CorrelationEvent]:
        """Retorna eventos de una IP dentro de la ventana de tiempo."""
        cutoff = time.time() - window
        with self._lock:
            events = list(self._events.get(ip, []))
        result = [e for e in events if e.timestamp >= cutoff]
        if event_types:
            result = [e for e in result if e.event_type in event_types]
        return result

    def _get_all_events_window(self, window: float,
                               event_types: List[str] = None) -> List[CorrelationEvent]:
        """Retorna todos los eventos dentro de la ventana."""
        cutoff = time.time() - window
        with self._lock:
            events = list(self._all_events)
        result = [e for e in events if e.timestamp >= cutoff]
        if event_types:
            result = [e for e in result if e.event_type in event_types]
        return result

    def _is_private(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.PRIVATE_PREFIXES)

    def _can_emit(self, pattern: str, ip: str) -> bool:
        """Verifica cooldown para evitar spam del mismo incidente."""
        key = f"{pattern}_{ip}"
        now = time.time()
        if now - self._cooldowns.get(key, 0) < self._cooldown_sec:
            return False
        self._cooldowns[key] = now
        return True

    def _emit_incident(self, pattern: str, severity: str, ip: str,
                       related_ips: List[str], events: List[CorrelationEvent],
                       description: str, confidence: float):
        """Crea y emite un incidente correlacionado."""
        if not self._can_emit(pattern, ip):
            return

        self._incident_counter += 1
        incident = CorrelatedIncident(
            incident_id  = f"INC-{self._incident_counter:04d}",
            pattern      = pattern,
            severity     = severity,
            ip           = ip,
            related_ips  = related_ips,
            events       = events,
            description  = description,
            confidence   = confidence,
        )

        with self._lock:
            self._incidents.append(incident)
            # Mantener solo los últimos 200 incidentes
            if len(self._incidents) > 200:
                self._incidents = self._incidents[-200:]

        # Log
        logger.warning(f"[Correlator] {incident.icon} {pattern} | {ip} | conf:{confidence:.0%} | {description}")
        color = '\033[31m' if severity == 'CRITICAL' else '\033[33m'
        print(f"{color}[Correlator] {incident.icon} [{incident.incident_id}] {pattern}\033[0m")
        print(f"  IP: {ip}  Confianza: {confidence:.0%}  Severidad: {severity}")
        print(f"  {description}")

        # Emitir alerta al IDS para que aparezca en el dashboard
        if self.ids:
            try:
                msg = f"{incident.icon} [{pattern}] {description} (conf:{confidence:.0%})"
                self.ids._create_alert(ip, severity, msg, incident.icon, f"CORRELATION_{pattern}")
            except Exception as e:
                logger.debug(f"[Correlator] Error emitiendo al IDS: {e}")

        # Guardar en DB si está disponible
        if self.db and hasattr(self.db, 'save_alert'):
            try:
                from modules.ids import Alert
                a = Alert(severity, f"CORRELATION_{pattern}", description, ip=ip)
                a.icon_override = incident.icon
                self.db.save_alert(a)
            except Exception:
                pass

    # ── Patrones de correlación ───────────────────────────────────────────────

    def _detect_recon_to_exploit(self):
        """
        RECON_TO_EXPLOIT: Port scan seguido de conexión al puerto descubierto.
        Patrón: port_scan → nueva conexión al mismo IP (dentro de 5 min)
        """
        scan_events = self._get_all_events_window(
            self.WINDOW_RECON, ['port_scan', 'ml_port_scan']
        )
        for scan in scan_events:
            if not scan.ip:
                continue
            # Buscar conexiones posteriores al scan
            post_events = self._get_events_for_ip(scan.ip, self.WINDOW_RECON)
            connections = [e for e in post_events
                          if e.event_type in ('high_traffic', 'ml_anomaly')
                          and e.timestamp > scan.timestamp]
            if connections:
                self._emit_incident(
                    pattern     = 'RECON_TO_EXPLOIT',
                    severity    = 'CRITICAL',
                    ip          = scan.ip,
                    related_ips = [],
                    events      = [scan] + connections[:2],
                    description = (f"Port scan desde {scan.ip} seguido de "
                                   f"actividad sospechosa ({len(connections)} eventos post-scan)"),
                    confidence  = min(0.6 + len(connections) * 0.1, 0.95),
                )

    def _detect_lateral_movement(self):
        """
        LATERAL_MOVEMENT: Un dispositivo interno ataca a otros internos.
        Patrón: IP privada → múltiples IPs privadas con port_scan o conexiones sospechosas
        """
        window_events = self._get_all_events_window(self.WINDOW_LATERAL)
        # Agrupar por IP origen
        by_ip: Dict[str, List[CorrelationEvent]] = defaultdict(list)
        for e in window_events:
            if e.ip and self._is_private(e.ip):
                by_ip[e.ip].append(e)

        for ip, events in by_ip.items():
            scan_events = [e for e in events if e.event_type in ('port_scan', 'ml_port_scan')]
            if len(scan_events) >= 2:
                # Al menos 2 scans desde el mismo dispositivo interno
                self._emit_incident(
                    pattern     = 'LATERAL_MOVEMENT',
                    severity    = 'CRITICAL',
                    ip          = ip,
                    related_ips = [],
                    events      = scan_events[:3],
                    description = (f"Movimiento lateral detectado: {ip} realizó "
                                   f"{len(scan_events)} scans internos en {self.WINDOW_LATERAL//60} min"),
                    confidence  = min(0.5 + len(scan_events) * 0.15, 0.9),
                )

    def _detect_data_exfiltration(self):
        """
        DATA_EXFILTRATION: Anomalía ML de exfiltración + IP en Threat Intel.
        Patrón: ml_anomaly(exfiltration=True) + threat_ip (mismo origen)
        """
        ml_events = self._get_all_events_window(
            self.WINDOW_EXFIL, ['ml_anomaly']
        )
        exfil_events = [e for e in ml_events if e.data.get('exfiltration')]

        threat_ips = {e.ip for e in self._get_all_events_window(
            self.WINDOW_EXFIL, ['threat_ip']
        )}

        for exfil in exfil_events:
            # Buscar también tráfico alto hacia IPs maliciosas
            traffic_events = self._get_events_for_ip(
                exfil.ip, self.WINDOW_EXFIL, ['high_traffic']
            )
            confidence = 0.5
            if traffic_events:
                confidence += 0.2
            # Si alguna IP de destino del tráfico está en threat intel
            dpi_ips = self._get_dpi_external_ips(exfil.ip)
            threat_matches = dpi_ips & threat_ips
            if threat_matches:
                confidence += 0.3

            if confidence >= 0.5:
                self._emit_incident(
                    pattern     = 'DATA_EXFILTRATION',
                    severity    = 'CRITICAL',
                    ip          = exfil.ip,
                    related_ips = list(threat_matches)[:3],
                    events      = [exfil] + traffic_events[:2],
                    description = (f"Posible exfiltración de datos desde {exfil.ip} "
                                   f"hacia {len(threat_matches)} IPs maliciosas conocidas"
                                   if threat_matches else
                                   f"Exfiltración detectada por ML desde {exfil.ip} "
                                   f"(score:{exfil.data.get('score', 0):.2f})"),
                    confidence  = min(confidence, 0.95),
                )

    def _detect_brute_force(self):
        """
        BRUTE_FORCE: Múltiples alertas de autenticación fallida en poco tiempo.
        Patrón: 5+ eventos de tipo auth/ids desde la misma IP en 2 min
        """
        window_events = self._get_all_events_window(self.WINDOW_BRUTE)
        by_ip: Dict[str, List[CorrelationEvent]] = defaultdict(list)
        for e in window_events:
            if e.ip:
                by_ip[e.ip].append(e)

        for ip, events in by_ip.items():
            # Múltiples alertas CRITICAL/WARN desde la misma IP en poco tiempo
            critical_events = [e for e in events
                               if e.severity in ('CRITICAL', 'WARN')
                               and e.event_type not in ('ml_anomaly',)]
            if len(critical_events) >= self.MIN_BRUTE_ALERTS:
                self._emit_incident(
                    pattern     = 'BRUTE_FORCE',
                    severity    = 'CRITICAL',
                    ip          = ip,
                    related_ips = [],
                    events      = critical_events[:5],
                    description = (f"Posible brute force desde {ip}: "
                                   f"{len(critical_events)} alertas en {self.WINDOW_BRUTE//60} min"),
                    confidence  = min(0.4 + len(critical_events) * 0.1, 0.90),
                )

    def _detect_c2_beacon_confirm(self):
        """
        C2_BEACON_CONFIRM: Beaconing ML confirmado + IP de destino en Threat Intel.
        Patrón: beaconing (MalwareTraffic plugin) + threat_ip relacionada
        """
        # Buscar alertas de beaconing del plugin MalwareTraffic
        beacon_events = [e for e in self._get_all_events_window(self.WINDOW_MULTISTAGE)
                        if 'beaconing' in e.data.get('message', '').lower()
                        or 'beacon' in e.event_type.lower()
                        or 'c2' in e.event_type.lower()]

        threat_ips = {e.ip for e in self._get_all_events_window(
            self.WINDOW_MULTISTAGE, ['threat_ip']
        )}

        for beacon in beacon_events:
            # Extraer IP de destino del beacon si está en el mensaje
            dest_ip = beacon.data.get('dst_ip', '')
            confirmed = dest_ip in threat_ips if dest_ip else False

            confidence = 0.7 if confirmed else 0.5
            self._emit_incident(
                pattern     = 'C2_BEACON_CONFIRM',
                severity    = 'CRITICAL',
                ip          = beacon.ip or dest_ip,
                related_ips = [dest_ip] if dest_ip else [],
                events      = [beacon],
                description = (f"Comunicación C2 confirmada: {beacon.ip} → {dest_ip} "
                               f"(IP en blacklist Threat Intel)"
                               if confirmed else
                               f"Posible comunicación C2: {beacon.ip} beacon periódico detectado"),
                confidence  = confidence,
            )

    def _detect_compromised_host(self):
        """
        COMPROMISED_HOST: Dispositivo interno contacta IP maliciosa + anomalía ML.
        Patrón: IP interna → threat_ip + ml_anomaly del mismo host
        """
        ml_events    = {e.ip: e for e in self._get_all_events_window(
                        self.WINDOW_EXFIL, ['ml_anomaly'])
                        if e.severity == 'CRITICAL'}
        threat_conns = self._get_all_events_window(self.WINDOW_EXFIL, ['threat_ip'])

        # Para cada conexión a IP maliciosa, buscar host interno que la originó
        for threat_event in threat_conns:
            # Buscar qué host interno contactó esta IP maliciosa
            internal_hosts = self._get_internal_hosts_contacting(threat_event.ip)
            for host_ip in internal_hosts:
                if host_ip in ml_events:
                    ml_ev = ml_events[host_ip]
                    self._emit_incident(
                        pattern     = 'COMPROMISED_HOST',
                        severity    = 'CRITICAL',
                        ip          = host_ip,
                        related_ips = [threat_event.ip],
                        events      = [ml_ev, threat_event],
                        description = (f"Host comprometido: {host_ip} contacta IP maliciosa "
                                       f"{threat_event.ip} con anomalía ML activa "
                                       f"(score:{ml_ev.data.get('score', 0):.2f})"),
                        confidence  = 0.85,
                    )

    def _detect_insider_threat(self):
        """
        INSIDER_THREAT: Dispositivo interno conocido empieza a escanear la red.
        Patrón: IP interna "normal" (vista por mucho tiempo) → port_scan interno
        """
        scan_events = self._get_all_events_window(self.WINDOW_LATERAL, ['port_scan'])
        for scan in scan_events:
            if not scan.ip or not self._is_private(scan.ip):
                continue
            # Si es un dispositivo conocido (en DB) que nunca había escaneado
            if self.db:
                try:
                    devices = self.db.get_all_devices()
                    for dev in devices:
                        if dev.get('ip') == scan.ip:
                            first_seen = dev.get('first_seen', time.time())
                            age_days   = (time.time() - first_seen) / 86400
                            if age_days > 3:  # dispositivo conocido hace >3 días
                                self._emit_incident(
                                    pattern     = 'INSIDER_THREAT',
                                    severity    = 'WARN',
                                    ip          = scan.ip,
                                    related_ips = [],
                                    events      = [scan],
                                    description = (f"Dispositivo conocido {scan.ip} "
                                                   f"(en red hace {age_days:.0f} días) "
                                                   f"realizó port scan interno"),
                                    confidence  = 0.65,
                                )
                            break
                except Exception:
                    pass

    def _detect_multi_stage(self):
        """
        MULTI_STAGE_ATTACK: 3+ etapas de ataque distintas desde la misma IP.
        Etapas: recon → explotación → persistencia → exfiltración
        """
        window_events = self._get_all_events_window(self.WINDOW_MULTISTAGE)
        by_ip: Dict[str, List[CorrelationEvent]] = defaultdict(list)
        for e in window_events:
            if e.ip:
                by_ip[e.ip].append(e)

        STAGE_TYPES = {
            'recon':       {'port_scan', 'ml_port_scan'},
            'exploit':     {'ml_anomaly', 'high_traffic'},
            'c2':          {'threat_ip', 'c2_port', 'beaconing'},
            'exfiltration':{'ml_anomaly'},  # exfil=True
        }

        for ip, events in by_ip.items():
            stages_found = set()
            for stage_name, type_set in STAGE_TYPES.items():
                for e in events:
                    if e.event_type in type_set:
                        if stage_name == 'exfiltration' and not e.data.get('exfiltration'):
                            continue
                        stages_found.add(stage_name)
                        break

            if len(stages_found) >= self.MIN_STAGES:
                self._emit_incident(
                    pattern     = 'MULTI_STAGE_ATTACK',
                    severity    = 'CRITICAL',
                    ip          = ip,
                    related_ips = [],
                    events      = events[:5],
                    description = (f"Ataque multi-etapa desde {ip}: "
                                   f"etapas detectadas: {', '.join(sorted(stages_found))} "
                                   f"({len(events)} eventos en {self.WINDOW_MULTISTAGE//60} min)"),
                    confidence  = min(0.5 + len(stages_found) * 0.15, 0.95),
                )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_dpi_external_ips(self, src_ip: str) -> Set[str]:
        """Obtiene IPs externas a las que se conectó un host."""
        result = set()
        if not self.dpi:
            return result
        try:
            external = getattr(self.dpi, '_external_ips', set())
            result.update(external)
        except Exception:
            pass
        return result

    def _get_internal_hosts_contacting(self, dst_ip: str) -> List[str]:
        """Busca qué hosts internos contactaron una IP externa."""
        result = []
        if not self.dpi:
            return result
        try:
            # Buscar en el historial del sniffer
            for src_ip in list(getattr(self.dpi, '_flow_tracker', {}).keys()):
                if self._is_private(src_ip):
                    flows = self.dpi._flow_tracker.get(src_ip, {})
                    if dst_ip in str(flows):
                        result.append(src_ip)
        except Exception:
            pass
        return result

    def _cleanup_old_events(self):
        """Limpia eventos más viejos que la ventana máxima."""
        cutoff = time.time() - self.WINDOW_MULTISTAGE
        with self._lock:
            for ip in list(self._events.keys()):
                new_deque = deque(
                    (e for e in self._events[ip] if e.timestamp >= cutoff),
                    maxlen=200
                )
                if new_deque:
                    self._events[ip] = new_deque
                else:
                    del self._events[ip]
        # Limpiar processed IDs (mantener solo los últimos 5000)
        if len(self._processed_alert_ids) > 5000:
            self._processed_alert_ids = set(
                list(self._processed_alert_ids)[-3000:]
            )

    # ── API pública ───────────────────────────────────────────────────────────

    def get_incidents(self, limit: int = 50) -> List[dict]:
        """Retorna los incidentes más recientes."""
        with self._lock:
            incidents = list(reversed(self._incidents[-limit:]))
        return [i.to_dict() for i in incidents]

    def get_active_incidents(self) -> List[dict]:
        """Retorna incidentes no resueltos."""
        with self._lock:
            active = [i for i in self._incidents if not i.resolved]
        return [i.to_dict() for i in reversed(active[-20:])]

    def get_stats(self) -> dict:
        with self._lock:
            total    = len(self._incidents)
            active   = sum(1 for i in self._incidents if not i.resolved)
            by_pat   = defaultdict(int)
            by_sev   = defaultdict(int)
            for i in self._incidents:
                by_pat[i.pattern]  += 1
                by_sev[i.severity] += 1
            total_events = len(self._all_events)
        return {
            'total_incidents':  total,
            'active_incidents': active,
            'total_events':     total_events,
            'by_pattern':       dict(by_pat),
            'by_severity':      dict(by_sev),
        }

    def resolve_incident(self, incident_id: str) -> bool:
        with self._lock:
            for i in self._incidents:
                if i.incident_id == incident_id:
                    i.resolved = True
                    return True
        return False

    def ingest_external_event(self, source: str, event_type: str,
                              ip: str, severity: str, data: dict = None):
        """
        API para que plugins externos inyecten eventos al correlador.
        Útil para DNSMonitor, MalwareTraffic, etc.
        """
        event = CorrelationEvent(
            source=source, event_type=event_type, ip=ip,
            severity=severity, data=data or {}
        )
        self._add_event(event)
