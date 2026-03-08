#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   NEURAL NETWORK MAP v2.0  —  Cyberpunk Edition                 ║
║   Fase 5: Visual 60fps  ·  Fase 6: API REST                     ║
║   Fase 7: Plugins GeoIP  ·  Fase 8: GeoIP Map + ML Anomaly      ║
╚══════════════════════════════════════════════════════════════════╝
"""

import sys
import threading
import time
import argparse
import os
import logging

os.makedirs("logs",           exist_ok=True)
os.makedirs("logs/reports",   exist_ok=True)
os.makedirs("logs/ml_models", exist_ok=True)
os.makedirs("plugins",        exist_ok=True)
os.makedirs("api",            exist_ok=True)

logging.basicConfig(
    filename='logs/nnm.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

from core.scanner            import NetworkScanner
from core.graph_engine       import GraphEngine
from ui.renderer             import CyberpunkRenderer
from config.settings         import Settings
from modules.traffic_monitor import TrafficMonitor
from modules.ids             import IntrusionDetector
from modules.database        import Database
from modules.dpi             import DPIEngine
from modules.packet_sniffer  import PacketSniffer
from web_dashboard           import WebDashboard

try:
    from plugins.plugin_manager import PluginManager
    PLUGINS_AVAILABLE = True
except ImportError:
    PLUGINS_AVAILABLE = False

try:
    from api.rest_api import create_api_blueprint
    API_AVAILABLE = True
except ImportError:
    API_AVAILABLE = False

try:
    from modules.anomaly_engine import AnomalyEngine
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


def print_banner():
    print("""\033[36m
╔══════════════════════════════════════════════════════════════════╗
║   NEURAL NETWORK MAP  ·  Cyberpunk Edition  ·  v2.0             ║
║   Fase 9: ML Avanzado   ·  Fase 12: Threat Intelligence         ║
║   Fase 14: Motor de Correlación de Eventos                      ║
╚══════════════════════════════════════════════════════════════════╝\033[0m
""")


def parse_args():
    p = argparse.ArgumentParser(description='Neural Network Map v2.0')
    p.add_argument('--subnet',          default=None)
    p.add_argument('--interface',       default=None)
    p.add_argument('--scan-interval',   type=int, default=30)
    p.add_argument('--no-gui',          action='store_true')
    p.add_argument('--no-web',          action='store_true')
    p.add_argument('--no-plugins',      action='store_true')
    p.add_argument('--no-api',          action='store_true')
    p.add_argument('--no-ml',           action='store_true')
    p.add_argument('--web-port',        type=int, default=5000)
    p.add_argument('--theme',           default='cyberpunk',
                   choices=['cyberpunk','matrix','neon','amber'])
    p.add_argument('--telegram-token',  default=None)
    p.add_argument('--telegram-chat',   default=None)
    p.add_argument('--bandwidth-limit', type=int, default=10)
    return p.parse_args()


def main():
    print_banner()
    args     = parse_args()
    settings = Settings(args)

    logger.info("NNM v2.0 iniciando...")
    print(f"\033[32m[*] Subnet: {settings.subnet}  |  Tema: {settings.theme}\033[0m\n")

    # ── Módulos base ──────────────────────────────────────────────────────────
    db              = Database()
    scanner         = NetworkScanner(settings)
    graph_engine    = GraphEngine()
    traffic_monitor = TrafficMonitor(settings)
    ids             = IntrusionDetector(settings)
    dpi             = DPIEngine()
    sniffer         = PacketSniffer(settings)

    sniffer.dpi = dpi
    sniffer.start()
    print(f"\033[32m[+] DPI Engine + Packet Sniffer iniciados\033[0m")

    summary = db.get_summary()
    print(f"\033[36m[DB] {summary['total_devices']} dispositivos  "
          f"{summary['total_alerts']} alertas  "
          f"{summary['traffic_samples']} muestras\033[0m\n")

    # ── Scan inicial ──────────────────────────────────────────────────────────
    print(f"\033[33m[~] Scan inicial...\033[0m")
    devices = scanner.scan()
    graph_engine.build_from_devices(devices)
    print(f"\033[32m[+] {len(devices)} dispositivos encontrados\033[0m\n")

    for dev in devices:
        db.upsert_device(dev.to_dict())
        for port in dev.open_ports:
            svc = dev.port_services.get(port, f"PORT-{port}")
            db.save_port_scan(dev.ip, port, svc)

    ids.register_known_devices(devices)
    print(f"\033[32m[+] IDS baseline: {len(devices)} dispositivos\033[0m")

    # ── Honeypot ──────────────────────────────────────────────────────────────
    honeypot = None
    if getattr(settings, 'honeypot_enabled', True):
        try:
            from modules.honeypot import Honeypot
            honeypot = Honeypot(
                settings = settings,
                ids      = ids,
                ports    = getattr(settings, 'honeypot_ports', None),
            )
            honeypot.start()
            # Agregar nodo honeypot al grafo para visualizarlo
            if honeypot.is_active():
                hp_ip = honeypot.host_ip
                from core.scanner import Device
                hp_device = Device(
                    ip          = f"honeypot.{hp_ip}",
                    hostname    = "🍯 Honeypot",
                    vendor      = "NNM",
                    device_type = "honeypot",
                    open_ports  = honeypot.active_ports,
                )
                graph_engine.add_honeypot_node(hp_device)
        except Exception as e:
            print(f"\033[33m[!] Honeypot no disponible: {e}\033[0m")
            honeypot = None

    # ── Fase 12: Threat Intelligence ─────────────────────────────────────────
    threat_intel = None
    if getattr(settings, 'threat_intel_enabled', True):
        try:
            from modules.threat_intel import ThreatIntelEngine
            threat_intel = ThreatIntelEngine(
                settings=settings,
                ids=ids,
                sniffer=sniffer,
                dpi=dpi,
            )
            threat_intel.start()
        except Exception as e:
            print(f"\033[33m[!] ThreatIntel no disponible: {e}\033[0m")
            threat_intel = None

    # ── Fase 14: Motor de Correlación ────────────────────────────────────────
    correlator = None
    try:
        from modules.correlation_engine import CorrelationEngine
        correlator = CorrelationEngine(
            ids            = ids,
            anomaly_engine = anomaly_engine if 'anomaly_engine' in dir() else None,
            threat_intel   = threat_intel,
            dpi            = dpi,
            db             = db,
            settings       = settings,
        )
        correlator.start()
    except Exception as e:
        print(f"\033[33m[!] CorrelationEngine no disponible: {e}\033[0m")
        correlator = None

    # ── Fase 9: ML Anomaly Engine (Avanzado) ─────────────────────────────────
    anomaly_engine = None
    if not args.no_ml:
        try:
            from modules.anomaly_engine import AnomalyEngine as _AE
            anomaly_engine = _AE(dpi=dpi, ids=ids, sniffer=sniffer)
            anomaly_engine.start()
            print(f"\033[32m[+] ML Anomaly Engine (IF + Z-score + DBSCAN) iniciado\033[0m")
            # Actualizar el correlador con la referencia al ML
            if correlator:
                correlator.anomaly_engine = anomaly_engine
        except Exception as e:
            print(f"\033[33m[!] AnomalyEngine no disponible: {e}\033[0m")
            anomaly_engine = None

    # ── Fase 7: Plugin Manager ────────────────────────────────────────────────
    plugin_manager = None
    if PLUGINS_AVAILABLE and not args.no_plugins:
        plugin_manager = PluginManager(settings, db=db, ids=ids, dpi=dpi, graph=graph_engine)
        plugin_manager.load_all()
        plugin_manager.register_baseline(devices)
        if args.telegram_token and args.telegram_chat:
            plugin_manager.configure_telegram(args.telegram_token, args.telegram_chat)
        elif os.environ.get('TELEGRAM_BOT_TOKEN'):
            plugin_manager.configure_telegram(
                os.environ['TELEGRAM_BOT_TOKEN'],
                os.environ.get('TELEGRAM_CHAT_ID', '')
            )
        plugin_manager.start()
        print(f"\033[32m[+] Plugin Manager iniciado\033[0m\n")

        # Fase 14: conectar EventBus del plugin_manager al correlador
        if correlator:
            def _on_dns_suspicious(data):
                if data:
                    correlator.ingest_external_event(
                        'dns_monitor', 'dns_suspicious',
                        data.get('ip',''), 'WARN', data
                    )
            def _on_beaconing(data):
                if data:
                    correlator.ingest_external_event(
                        'malware_traffic', 'beaconing',
                        data.get('dst_ip',''), 'CRITICAL', data
                    )
            plugin_manager.event_bus.subscribe('dns_suspicious', _on_dns_suspicious)
            plugin_manager.event_bus.subscribe('beaconing_detected', _on_beaconing)

    # ── Fase 4+8: Dashboard Web ───────────────────────────────────────────────
    dashboard = None
    if not args.no_web:
        dashboard = WebDashboard(port=args.web_port)
        dashboard.db             = db
        dashboard.dpi            = dpi
        dashboard.ids            = ids
        dashboard.scanner        = scanner
        dashboard.graph          = graph_engine
        dashboard.settings       = settings
        dashboard.anomaly_engine = anomaly_engine
        dashboard.threat_intel   = threat_intel  # FASE 12
        dashboard.correlator     = correlator    # FASE 14
        if plugin_manager:
            dashboard.geoip_plugin = plugin_manager.geoip
        dashboard.start()

        # Fase 7: API REST
        if API_AVAILABLE and not args.no_api and dashboard._app:
            api_bp = create_api_blueprint(
                db=db, dpi=dpi, ids=ids,
                scanner=scanner, graph=graph_engine,
                sniffer=sniffer, plugin_manager=plugin_manager,
            )
            if api_bp:
                dashboard._app.register_blueprint(api_bp)
                print(f"\033[32m[+] API REST: http://localhost:{args.web_port}/api/v1/status\033[0m")
                print(f"\033[36m    Nuevos: /api/v1/geo  /api/v1/ml  (Fase 8)\033[0m\n")

    # ── Callback IDS ──────────────────────────────────────────────────────────
    def on_alert(alert):
        db.save_alert(alert)
        if dashboard:
            dashboard.emit_new_alert(alert)
        if plugin_manager:
            plugin_manager.on_ids_alert(alert)

    ids.register_callback(on_alert)

    # ── Thread re-scan ────────────────────────────────────────────────────────
    _known_ips = set(d.ip for d in devices)

    def background_scan():
        traffic_counter = 0
        while True:
            time.sleep(settings.scan_interval)
            try:
                new_devices = scanner.scan()
                current_ips = {d.ip for d in new_devices}

                graph_engine.update_devices(new_devices)
                for dev in new_devices:
                    db.upsert_device(dev.to_dict())

                for ip in ({d['ip'] for d in db.get_all_devices()
                            if d.get('status') == 'active'} - current_ips):
                    db.mark_device_offline(ip)
                    if plugin_manager:
                        plugin_manager.on_device_left(ip)

                ids.check_new_devices(new_devices)
                ids.check_devices_left(current_ips)

                if plugin_manager:
                    for dev in new_devices:
                        if dev.ip not in _known_ips:
                            plugin_manager.on_new_device(dev)
                            _known_ips.add(dev.ip)
                    pa = plugin_manager.get_plugin("PortAlert")
                    if pa:
                        for dev in new_devices:
                            pa.check_device(dev.ip, dev.open_ports)

                if dashboard:
                    if plugin_manager and plugin_manager.geoip:
                        if len(plugin_manager.geoip.get_map_data()) > 0:
                            dashboard.emit_geo_update()
                    if anomaly_engine:
                        dashboard.emit_ml_update()
                    try:
                        dashboard._sio.emit('device_update', {})
                    except Exception:
                        pass

                tx, rx = traffic_monitor.get_current_rates()
                ids.check_traffic_anomaly("red_local", (tx + rx) * 1024)

                traffic_counter += 1
                if traffic_counter >= 2:
                    db.save_traffic_stat(tx, rx, len(current_ips))
                    traffic_counter = 0

            except Exception as e:
                logger.error(f"Background scan error: {e}")

    threading.Thread(target=background_scan, daemon=True).start()

    # ── Thread GeoIP activo ───────────────────────────────────────────────────
    def geoip_loop():
        """Geolocaliza IPs externas del trafico en tiempo real."""
        PRIVATE = ("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
                   "172.2", "172.3", "127.", "0.", "169.254.", "224.", "255.", "::1")

        def is_private(ip):
            return any(ip.startswith(p) for p in PRIVATE)

        time.sleep(10)
        while True:
            if not (plugin_manager and plugin_manager.geoip):
                time.sleep(10)
                continue
            try:
                geoip = plugin_manager.geoip
                all_ips = set()

                # Fuente 1: sniffer.device_stats (todas las IPs vistas)
                try:
                    for ip in list(sniffer.device_stats.keys()):
                        if ip and not is_private(ip):
                            all_ips.add(ip)
                except Exception:
                    pass

                # Fuente 2: DPI external_ips
                try:
                    all_ips.update(dpi.get_external_ips())
                except Exception:
                    pass

                # Fuente 3: sniffer top_talkers
                try:
                    for ip, _, _ in sniffer.get_top_talkers(20):
                        if ip and not is_private(ip):
                            all_ips.add(ip)
                except Exception:
                    pass

                if not all_ips:
                    print(f"\033[33m[GeoIP] Sin IPs externas aun...\033[0m")
                    time.sleep(20)
                    continue

                new_n = 0
                for ip in list(all_ips):
                    if ip not in geoip._cache:
                        result = geoip.lookup(ip)
                        if result:
                            new_n += 1
                            print(f"\033[36m[GeoIP] {ip} -> "
                                  f"{result.get('country','')} "
                                  f"{result.get('flag','')}\033[0m")
                        time.sleep(1.4)

                if new_n > 0 and dashboard:
                    dashboard.emit_geo_update()
                    print(f"\033[36m[GeoIP] {new_n} IPs geolocalizadas "
                          f"(cache total: {len(geoip._cache)})\033[0m")

            except Exception as e:
                logger.error(f"GeoIP loop: {e}")
                print(f"\033[31m[GeoIP] Error: {e}\033[0m")
            time.sleep(20)

    threading.Thread(target=geoip_loop, daemon=True).start()

    # ── Thread cleanup ────────────────────────────────────────────────────────
    def cleanup_loop():
        while True:
            time.sleep(3600)
            db.cleanup_old_data(days=30)

    threading.Thread(target=cleanup_loop, daemon=True).start()

    # ── GUI ───────────────────────────────────────────────────────────────────
    if not args.no_gui:
        renderer = CyberpunkRenderer(graph_engine, traffic_monitor, settings)
        renderer.ids     = ids
        renderer.scanner = scanner
        renderer.db      = db
        renderer.dpi     = dpi
        renderer.sniffer = sniffer
        ids.register_callback(renderer.on_ids_alert)

        print(f"\033[32m[+] GUI iniciada — todos los sistemas activos\033[0m")
        print(f"\033[36m[*] [T] Tema  [I] IDS  [H] Historial  [M] Minimap  [R] Reset  [Q] Salir\033[0m")
        if not args.no_web:
            print(f"\033[36m[*] http://localhost:{args.web_port}  —  tabs: Mapa GeoIP | Anomalías ML | Tráfico\033[0m")
            if API_AVAILABLE and not args.no_api:
                print(f"\033[36m[*] API: http://localhost:{args.web_port}/api/v1/status\033[0m")
        print()
        renderer.run()

    else:
        print(f"\033[36m[*] Headless. Dashboard: http://localhost:{args.web_port}\033[0m")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n\033[31m[!] Shutdown.\033[0m")
            if plugin_manager:
                rp = plugin_manager.get_plugin("AutoReport")
                if rp:
                    try:
                        rp.generate_report()
                    except Exception:
                        pass


if __name__ == "__main__":
    main()
