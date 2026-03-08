"""
modules/database.py
FASE 3 — Historial SQLite para Neural Network Map
Tablas:
  - devices       : todos los dispositivos vistos
  - alerts        : historial de alertas IDS
  - traffic_stats : estadisticas de trafico cada 60s
  - port_scans    : puertos encontrados por dispositivo
"""

import sqlite3
import threading
import time
import logging
import os
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

DB_PATH = "logs/nnm_history.db"


class Database:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self._lock   = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()
        logger.info(f"Database iniciada: {db_path}")
        print(f"\033[32m[+] Database SQLite: {db_path}\033[0m")

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")   # Write-Ahead Logging — mejor para multithreading
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        """Crea las tablas si no existen."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS devices (
                        ip              TEXT PRIMARY KEY,
                        mac             TEXT,
                        hostname        TEXT,
                        vendor          TEXT,
                        device_type     TEXT,
                        os_info         TEXT,
                        is_gateway      INTEGER DEFAULT 0,
                        open_ports      TEXT,          -- JSON list
                        first_seen      REAL,          -- unix timestamp
                        last_seen       REAL,
                        times_seen      INTEGER DEFAULT 1,
                        status          TEXT DEFAULT 'active'  -- active/offline
                    );

                    CREATE TABLE IF NOT EXISTS alerts (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp       REAL,
                        severity        TEXT,
                        category        TEXT,
                        message         TEXT,
                        ip              TEXT,
                        acknowledged    INTEGER DEFAULT 0
                    );

                    CREATE TABLE IF NOT EXISTS traffic_stats (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp       REAL,
                        tx_kbps         REAL,
                        rx_kbps         REAL,
                        active_devices  INTEGER
                    );

                    CREATE TABLE IF NOT EXISTS port_scans (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip              TEXT,
                        timestamp       REAL,
                        port            INTEGER,
                        service         TEXT,
                        UNIQUE(ip, port)
                    );

                    CREATE INDEX IF NOT EXISTS idx_devices_last_seen  ON devices(last_seen);
                    CREATE INDEX IF NOT EXISTS idx_alerts_timestamp    ON alerts(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_alerts_ip           ON alerts(ip);
                    CREATE INDEX IF NOT EXISTS idx_traffic_timestamp   ON traffic_stats(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_portscans_ip        ON port_scans(ip);

                    -- FASE 9: Perfiles baseline por dispositivo
                    CREATE TABLE IF NOT EXISTS device_profiles (
                        ip                      TEXT PRIMARY KEY,
                        sample_count            INTEGER DEFAULT 0,
                        baseline_bytes_mean     REAL DEFAULT 0,
                        baseline_bytes_std      REAL DEFAULT 1,
                        baseline_packets_mean   REAL DEFAULT 0,
                        baseline_packets_std    REAL DEFAULT 1,
                        baseline_ports_mean     REAL DEFAULT 0,
                        hour_distribution       TEXT,   -- JSON dict hora->frecuencia
                        last_updated            REAL,
                        created_at              REAL
                    );

                    -- FASE 9: Eventos de detección especializada (port scan, exfiltración)
                    CREATE TABLE IF NOT EXISTS detection_events (
                        id              INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp       REAL,
                        ip              TEXT,
                        event_type      TEXT,   -- PORT_SCAN / EXFILTRATION / UNUSUAL_HOUR
                        description     TEXT,
                        score           REAL,
                        method          TEXT    -- rules / zscore / isolation_forest / dbscan
                    );

                    CREATE INDEX IF NOT EXISTS idx_profiles_ip       ON device_profiles(ip);
                    CREATE INDEX IF NOT EXISTS idx_detections_ip     ON detection_events(ip);
                    CREATE INDEX IF NOT EXISTS idx_detections_ts     ON detection_events(timestamp);
                """)
                conn.commit()
            finally:
                conn.close()

    # ── Dispositivos ──────────────────────────────────────────────────────────

    def upsert_device(self, device_info: dict):
        """Inserta o actualiza un dispositivo. Incrementa times_seen."""
        import json
        now = time.time()
        ip  = device_info.get('ip', '')
        if not ip:
            return

        ports_json = json.dumps(device_info.get('open_ports', []))

        with self._lock:
            conn = self._get_conn()
            try:
                existing = conn.execute(
                    "SELECT first_seen, times_seen FROM devices WHERE ip = ?", (ip,)
                ).fetchone()

                if existing:
                    conn.execute("""
                        UPDATE devices SET
                            mac         = ?,
                            hostname    = ?,
                            vendor      = ?,
                            device_type = ?,
                            os_info     = ?,
                            is_gateway  = ?,
                            open_ports  = ?,
                            last_seen   = ?,
                            times_seen  = times_seen + 1,
                            status      = 'active'
                        WHERE ip = ?
                    """, (
                        device_info.get('mac', ''),
                        device_info.get('hostname', 'Unknown'),
                        device_info.get('vendor', 'Unknown'),
                        device_info.get('device_type', 'unknown'),
                        device_info.get('os_info', ''),
                        1 if device_info.get('is_gateway') else 0,
                        ports_json,
                        now,
                        ip
                    ))
                else:
                    conn.execute("""
                        INSERT INTO devices
                            (ip, mac, hostname, vendor, device_type, os_info,
                             is_gateway, open_ports, first_seen, last_seen, times_seen, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 'active')
                    """, (
                        ip,
                        device_info.get('mac', ''),
                        device_info.get('hostname', 'Unknown'),
                        device_info.get('vendor', 'Unknown'),
                        device_info.get('device_type', 'unknown'),
                        device_info.get('os_info', ''),
                        1 if device_info.get('is_gateway') else 0,
                        ports_json,
                        now,
                        now
                    ))
                conn.commit()
            except Exception as e:
                logger.error(f"Error upsert_device {ip}: {e}")
            finally:
                conn.close()

    def mark_device_offline(self, ip: str):
        """Marca un dispositivo como offline."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE devices SET status = 'offline' WHERE ip = ?", (ip,)
                )
                conn.commit()
            finally:
                conn.close()

    def get_device_history(self, ip: str) -> Optional[dict]:
        """Devuelve el historial completo de un dispositivo."""
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM devices WHERE ip = ?", (ip,)
                ).fetchone()
                if row:
                    return dict(row)
            finally:
                conn.close()
        return None

    def get_all_devices(self) -> List[dict]:
        """Devuelve todos los dispositivos vistos alguna vez."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM devices ORDER BY last_seen DESC"
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_new_devices_today(self) -> List[dict]:
        """Dispositivos vistos por primera vez hoy."""
        today = time.time() - 86400  # 24 horas
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM devices WHERE first_seen > ? ORDER BY first_seen DESC",
                    (today,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ── Alertas ───────────────────────────────────────────────────────────────

    def save_alert(self, alert):
        """Guarda una alerta del IDS en la base de datos."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO alerts (timestamp, severity, category, message, ip)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    alert.timestamp,
                    alert.severity,
                    alert.category,
                    alert.message,
                    alert.ip
                ))
                conn.commit()
            except Exception as e:
                logger.error(f"Error save_alert: {e}")
            finally:
                conn.close()

    def get_recent_alerts(self, limit: int = 50) -> List[dict]:
        """Alertas más recientes."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_alerts_by_ip(self, ip: str) -> List[dict]:
        """Todas las alertas de una IP específica."""
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE ip = ? ORDER BY timestamp DESC",
                    (ip,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_alert_stats(self) -> dict:
        """Estadísticas de alertas."""
        with self._lock:
            conn = self._get_conn()
            try:
                total   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                crit    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='CRITICAL'").fetchone()[0]
                warn    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='WARN'").fetchone()[0]
                info    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='INFO'").fetchone()[0]
                today   = time.time() - 86400
                today_c = conn.execute(
                    "SELECT COUNT(*) FROM alerts WHERE timestamp > ?", (today,)
                ).fetchone()[0]
                return {
                    'total': total, 'critical': crit,
                    'warn': warn, 'info': info, 'today': today_c
                }
            finally:
                conn.close()

    # ── Tráfico ───────────────────────────────────────────────────────────────

    def save_traffic_stat(self, tx_kbps: float, rx_kbps: float, active_devices: int):
        """Guarda una muestra de tráfico."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO traffic_stats (timestamp, tx_kbps, rx_kbps, active_devices)
                    VALUES (?, ?, ?, ?)
                """, (time.time(), tx_kbps, rx_kbps, active_devices))
                conn.commit()
            except Exception as e:
                logger.error(f"Error save_traffic: {e}")
            finally:
                conn.close()

    def get_traffic_history(self, hours: int = 1) -> List[dict]:
        """Historial de tráfico de las últimas N horas."""
        since = time.time() - hours * 3600
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM traffic_stats WHERE timestamp > ? ORDER BY timestamp ASC",
                    (since,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ── Port scans ────────────────────────────────────────────────────────────

    def save_port_scan(self, ip: str, port: int, service: str):
        """Guarda un puerto abierto encontrado."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO port_scans (ip, timestamp, port, service)
                    VALUES (?, ?, ?, ?)
                """, (ip, time.time(), port, service))
                conn.commit()
            except Exception as e:
                logger.error(f"Error save_port_scan: {e}")
            finally:
                conn.close()

    def get_ports_for_ip(self, ip: str) -> List[dict]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM port_scans WHERE ip = ? ORDER BY port ASC", (ip,)
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ── Reportes ──────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """Resumen general de la base de datos."""
        with self._lock:
            conn = self._get_conn()
            try:
                total_devices   = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
                active_devices  = conn.execute("SELECT COUNT(*) FROM devices WHERE status='active'").fetchone()[0]
                offline_devices = conn.execute("SELECT COUNT(*) FROM devices WHERE status='offline'").fetchone()[0]
                total_alerts    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                total_traffic   = conn.execute("SELECT COUNT(*) FROM traffic_stats").fetchone()[0]
                oldest_device   = conn.execute(
                    "SELECT ip, first_seen FROM devices ORDER BY first_seen ASC LIMIT 1"
                ).fetchone()
                return {
                    'total_devices':   total_devices,
                    'active_devices':  active_devices,
                    'offline_devices': offline_devices,
                    'total_alerts':    total_alerts,
                    'traffic_samples': total_traffic,
                    'oldest_device':   dict(oldest_device) if oldest_device else None,
                }
            finally:
                conn.close()

    def cleanup_old_data(self, days: int = 30):
        """Elimina datos más viejos de N días."""
        cutoff = time.time() - days * 86400
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM traffic_stats WHERE timestamp < ?", (cutoff,))
                conn.execute("DELETE FROM alerts WHERE timestamp < ? AND severity = 'INFO'", (cutoff,))
                conn.execute("DELETE FROM detection_events WHERE timestamp < ?", (cutoff,))
                conn.commit()
                logger.info(f"Cleanup: datos mayores a {days} días eliminados")
            finally:
                conn.close()

    # ── Perfiles ML (FASE 9) ──────────────────────────────────────────────────

    def save_device_profile(self, profile_dict: dict):
        """Persiste el perfil baseline de un dispositivo."""
        import json
        ip = profile_dict.get('ip', '')
        if not ip:
            return
        now = time.time()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO device_profiles
                        (ip, sample_count, baseline_bytes_mean, baseline_bytes_std,
                         baseline_packets_mean, baseline_packets_std,
                         baseline_ports_mean, hour_distribution, last_updated, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET
                        sample_count          = excluded.sample_count,
                        baseline_bytes_mean   = excluded.baseline_bytes_mean,
                        baseline_bytes_std    = excluded.baseline_bytes_std,
                        baseline_packets_mean = excluded.baseline_packets_mean,
                        baseline_packets_std  = excluded.baseline_packets_std,
                        baseline_ports_mean   = excluded.baseline_ports_mean,
                        hour_distribution     = excluded.hour_distribution,
                        last_updated          = excluded.last_updated
                """, (
                    ip,
                    profile_dict.get('sample_count', 0),
                    profile_dict.get('baseline_bytes_mean', 0.0),
                    profile_dict.get('baseline_bytes_std', 1.0),
                    profile_dict.get('baseline_packets_mean', 0.0),
                    profile_dict.get('baseline_packets_std', 1.0),
                    profile_dict.get('baseline_ports_mean', 0.0),
                    json.dumps(profile_dict.get('hour_distribution', {})),
                    now,
                    profile_dict.get('created_at', now),
                ))
                conn.commit()
            except Exception as e:
                logger.error(f"Error save_device_profile {ip}: {e}")
            finally:
                conn.close()

    def get_device_profile(self, ip: str) -> Optional[dict]:
        """Recupera el perfil baseline de un dispositivo."""
        import json
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM device_profiles WHERE ip = ?", (ip,)
                ).fetchone()
                if row:
                    d = dict(row)
                    d['hour_distribution'] = json.loads(d.get('hour_distribution') or '{}')
                    return d
            finally:
                conn.close()
        return None

    def get_all_profiles(self) -> List[dict]:
        """Todos los perfiles guardados."""
        import json
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM device_profiles ORDER BY last_updated DESC"
                ).fetchall()
                result = []
                for row in rows:
                    d = dict(row)
                    d['hour_distribution'] = json.loads(d.get('hour_distribution') or '{}')
                    result.append(d)
                return result
            finally:
                conn.close()

    # ── Eventos de detección (FASE 9) ─────────────────────────────────────────

    def save_detection_event(self, ip: str, event_type: str,
                              description: str, score: float, method: str):
        """Guarda un evento de detección especializada (port scan, exfiltración, etc.)."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO detection_events
                        (timestamp, ip, event_type, description, score, method)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (time.time(), ip, event_type, description, score, method))
                conn.commit()
            except Exception as e:
                logger.error(f"Error save_detection_event: {e}")
            finally:
                conn.close()

    def get_detection_events(self, hours: int = 24, ip: str = None) -> List[dict]:
        """Eventos de detección recientes, opcionalmente filtrado por IP."""
        since = time.time() - hours * 3600
        with self._lock:
            conn = self._get_conn()
            try:
                if ip:
                    rows = conn.execute(
                        "SELECT * FROM detection_events WHERE timestamp > ? AND ip = ? ORDER BY timestamp DESC",
                        (since, ip)
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM detection_events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 100",
                        (since,)
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()
