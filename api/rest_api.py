"""
api/rest_api.py
FASE 7 — API REST completa para Neural Network Map v2.0

Endpoints:
  GET  /api/v1/status           → estado general del sistema
  GET  /api/v1/devices          → todos los dispositivos
  GET  /api/v1/devices/<ip>     → detalle completo de un dispositivo
  GET  /api/v1/alerts           → alertas IDS recientes
  GET  /api/v1/activity         → actividad DPI en vivo
  GET  /api/v1/traffic          → estadísticas de tráfico
  GET  /api/v1/top-talkers      → dispositivos con más tráfico
  GET  /api/v1/top-services     → servicios más usados
  POST /api/v1/scan/<ip>        → lanza Nmap scan on-demand
  GET  /api/v1/history          → historial completo de sesiones
  GET  /api/v1/plugins          → plugins activos y su estado
  GET  /api/v1/export/json      → exportar todo como JSON
"""

import time
import json
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from flask import Blueprint, jsonify, request, Response
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


def _fmt_bytes(b: int) -> str:
    """Formatea bytes en unidad legible."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


def create_api_blueprint(db, dpi, ids, scanner, graph, sniffer=None, plugin_manager=None):
    """
    Crea y retorna el Blueprint Flask de la API REST.
    Se registra en la app Flask del dashboard con:
        app.register_blueprint(create_api_blueprint(...))
    """
    if not FLASK_AVAILABLE:
        return None

    api = Blueprint('api_v1', __name__, url_prefix='/api/v1')

    # ── CORS helper ───────────────────────────────────────────────────────────
    def _cors(response):
        response.headers['Access-Control-Allow-Origin']  = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        return response

    @api.after_request
    def after_request(response):
        return _cors(response)

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/status
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/status')
    def status():
        summary     = db.get_summary()     if db  else {}
        alert_stats = db.get_alert_stats() if db  else {}
        active_ips  = dpi.get_active_devices()  if dpi else []
        top_svcs    = dpi.get_top_services(5)   if dpi else []
        ids_counts  = ids.get_alert_count()     if ids else {}

        plugins_info = []
        if plugin_manager:
            for p in plugin_manager.list_plugins():
                plugins_info.append({'name': p.name, 'enabled': p.enabled, 'status': p.status})

        return jsonify({
            'status':    'running',
            'version':   '2.0',
            'timestamp': time.time(),
            'network': {
                'total_devices':   summary.get('total_devices', 0),
                'active_devices':  summary.get('active_devices', 0),
                'offline_devices': summary.get('offline_devices', 0),
            },
            'alerts': {
                'total':    alert_stats.get('total', 0),
                'critical': ids_counts.get('CRITICAL', 0),
                'warn':     ids_counts.get('WARN', 0),
                'info':     ids_counts.get('INFO', 0),
                'today':    alert_stats.get('today', 0),
                'unread':   ids.get_unread_count() if ids else 0,
            },
            'dpi': {
                'active_devices': len(active_ips),
                'top_services': [{'service': s, 'count': c} for s, c in top_svcs],
            },
            'plugins': plugins_info,
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/devices
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/devices')
    def devices():
        all_devs = db.get_all_devices() if db else []
        result   = []

        for dev in all_devs:
            d = dict(dev)
            # Parsear open_ports de JSON string si viene de DB
            try:
                if isinstance(d.get('open_ports'), str):
                    d['open_ports'] = json.loads(d['open_ports'])
            except Exception:
                d['open_ports'] = []

            # Actividad DPI resumida
            if dpi:
                activity = dpi.get_device_activity(d['ip'], limit=5)
                d['dpi_activity'] = [
                    {'service': a.service, 'icon': a.icon,
                     'category': a.category, 'age': a.age_str}
                    for a in activity
                ]
                d['bytes_total'] = dpi.get_device_bytes(d['ip'])
                d['bytes_human'] = _fmt_bytes(d['bytes_total'])
            else:
                d['dpi_activity'] = []
                d['bytes_total']  = 0
                d['bytes_human']  = '0 B'

            # Info en vivo del grafo
            live = graph.get_device_info(d['ip']) if graph else {}
            d['live'] = {
                'online':      live.get('is_alive', False),
                'is_gateway':  live.get('is_gateway', False),
            }

            result.append(d)

        # Ordenar: activos primero, luego por IP
        result.sort(key=lambda x: (
            x.get('status', 'offline') != 'active',
            list(map(int, x['ip'].split('.')))
        ))

        return jsonify({'count': len(result), 'devices': result})

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/devices/<ip>
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/devices/<ip>')
    def device_detail(ip):
        dev = db.get_device_history(ip) if db else None
        if not dev:
            # Intentar desde el grafo en vivo
            live = graph.get_device_info(ip) if graph else None
            if not live:
                return jsonify({'error': f'Device {ip} not found'}), 404
            dev = live

        dev = dict(dev)
        try:
            if isinstance(dev.get('open_ports'), str):
                dev['open_ports'] = json.loads(dev['open_ports'])
        except Exception:
            dev['open_ports'] = []

        # Puertos detallados de DB
        ports_detail = []
        if db and hasattr(db, 'get_ports_for_ip'):
            try:
                ports_detail = [dict(p) for p in db.get_ports_for_ip(ip)]
            except Exception:
                pass

        # Alertas de este dispositivo
        alerts = []
        if db and hasattr(db, 'get_alerts_by_ip'):
            try:
                alerts = [dict(a) for a in db.get_alerts_by_ip(ip)][:20]
            except Exception:
                pass

        # Actividad DPI completa
        dpi_activity = []
        if dpi:
            try:
                for act in dpi.get_device_activity(ip, limit=50):
                    dpi_activity.append({
                        'service':   act.service,
                        'icon':      act.icon,
                        'category':  act.category,
                        'color':     list(act.color),
                        'age':       act.age_str,
                        'count':     act.count,
                    })
            except Exception:
                pass

        # Info en vivo
        live_info  = graph.get_device_info(ip) if graph else {}
        neighbors  = graph.get_neighbors(ip) if graph else []

        return jsonify({
            'device':       dev,
            'ports':        ports_detail,
            'alerts':       alerts,
            'dpi_activity': dpi_activity,
            'bytes_total':  dpi.get_device_bytes(ip) if dpi else 0,
            'bytes_human':  _fmt_bytes(dpi.get_device_bytes(ip) if dpi else 0),
            'neighbors':    neighbors,
            'live_info':    live_info,
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/alerts
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/alerts')
    def alerts():
        limit    = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity', None)

        if ids:
            raw_alerts = ids.get_recent_alerts(limit)
            result = []
            for a in raw_alerts:
                d = {
                    'ip':        a.ip,
                    'message':   a.message,
                    'severity':  a.severity,
                    'icon':      a.icon,
                    'timestamp': a.timestamp,
                    'time_str':  time.strftime('%H:%M:%S', time.localtime(a.timestamp)),
                    'read':      a.read,
                }
                if not severity or d['severity'] == severity.upper():
                    result.append(d)
        else:
            result = []

        return jsonify({'count': len(result), 'alerts': result})

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/activity
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/activity')
    def activity():
        if not dpi:
            return jsonify({'activity': [], 'active_devices': 0})

        result     = []
        active_ips = dpi.get_active_devices()

        for ip in active_ips:
            acts = dpi.get_device_activity(ip, limit=8)
            for act in acts:
                result.append({
                    'ip':       ip,
                    'service':  act.service,
                    'icon':     act.icon,
                    'category': act.category,
                    'color':    list(act.color),
                    'age':      act.age_str,
                    'count':    act.count,
                })

        return jsonify({'active_devices': len(active_ips), 'activity': result})

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/traffic
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/traffic')
    def traffic():
        hours   = request.args.get('hours', 1, type=int)
        history = db.get_traffic_history(hours) if db else []

        talkers = []
        if dpi:
            for ip, bytes_ in dpi.get_top_talkers(10):
                talkers.append({
                    'ip':    ip,
                    'bytes': bytes_,
                    'human': _fmt_bytes(bytes_),
                })

        return jsonify({
            'history':     [dict(h) for h in history],
            'top_talkers': talkers,
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/top-talkers
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/top-talkers')
    def top_talkers():
        limit   = request.args.get('limit', 10, type=int)
        talkers = []
        if dpi:
            for ip, bytes_ in dpi.get_top_talkers(limit):
                dev_info = graph.get_device_info(ip) if graph else {}
                talkers.append({
                    'ip':       ip,
                    'hostname': dev_info.get('hostname', 'Unknown'),
                    'bytes':    bytes_,
                    'human':    _fmt_bytes(bytes_),
                })
        return jsonify({'count': len(talkers), 'talkers': talkers})

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/top-services
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/top-services')
    def top_services():
        limit    = request.args.get('limit', 10, type=int)
        services = []
        if dpi:
            for svc, count in dpi.get_top_services(limit):
                services.append({'service': svc, 'count': count})
        return jsonify({'count': len(services), 'services': services})

    # ─────────────────────────────────────────────────────────────────────────
    # POST /api/v1/scan/<ip>
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/scan/<ip>', methods=['POST'])
    def scan_device(ip):
        """Lanza un Nmap scan on-demand para el IP especificado."""
        if not scanner:
            return jsonify({'error': 'Scanner no disponible'}), 503

        import threading
        result_holder = {}
        event         = threading.Event()

        def run():
            result_holder['data'] = scanner.nmap_scan_device(ip)
            event.set()

        threading.Thread(target=run, daemon=True).start()

        # Esperar máximo 60s
        finished = event.wait(timeout=60)
        if not finished:
            return jsonify({'error': 'Scan timeout después de 60s', 'ip': ip}), 408

        data = result_holder.get('data', {})
        return jsonify({
            'ip':           ip,
            'os_info':      data.get('os_info', ''),
            'open_ports':   data.get('open_ports', []),
            'port_services': data.get('port_services', {}),
            'scanned_at':   time.time(),
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/history
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/history')
    def history():
        if not db:
            return jsonify({'devices': [], 'alerts': []})

        devices = [dict(d) for d in db.get_all_devices()]
        summary = db.get_summary()
        alerts  = db.get_alert_stats()

        return jsonify({
            'summary': summary,
            'alerts':  alerts,
            'devices': devices,
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/plugins
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/plugins')
    def plugins():
        if not plugin_manager:
            return jsonify({'plugins': [], 'count': 0})

        result = []
        for p in plugin_manager.list_plugins():
            result.append({
                'name':        p.name,
                'description': p.description,
                'enabled':     p.enabled,
                'status':      p.status,
                'version':     getattr(p, 'version', '1.0'),
            })
        return jsonify({'count': len(result), 'plugins': result})

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/export/json
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/export/json')
    def export_json():
        """Exporta todo el estado actual como JSON descargable."""
        devices    = [dict(d) for d in db.get_all_devices()] if db else []
        summary    = db.get_summary() if db else {}
        raw_alerts = ids.get_recent_alerts(200) if ids else []
        alerts     = [{'ip': a.ip, 'message': a.message, 'severity': a.severity,
                        'timestamp': a.timestamp} for a in raw_alerts]

        activity = []
        if dpi:
            for ip in dpi.get_active_devices():
                for act in dpi.get_device_activity(ip, limit=10):
                    activity.append({
                        'ip': ip, 'service': act.service,
                        'category': act.category, 'age': act.age_str,
                    })

        export = {
            'exported_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'version':     '2.0',
            'summary':     summary,
            'devices':     devices,
            'alerts':      alerts,
            'activity':    activity,
        }

        response = Response(
            json.dumps(export, indent=2, default=str),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=nnm_export_{int(time.time())}.json'
            }
        )
        return response

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/geo
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/geo')
    def geo_data():
        """Datos GeoIP de IPs externas detectadas."""
        if not dpi:
            return jsonify({'points': [], 'countries': {}})

        ext_info = dpi.get_external_ip_info()
        points   = []
        countries = {}

        for ip, info in ext_info.items():
            geo = info.get('geo')
            if not geo:
                # Intentar desde plugin_manager si está disponible
                if plugin_manager and plugin_manager.geoip:
                    geo = plugin_manager.geoip._cache.get(ip)
            if geo and geo.get('lat') and geo.get('lon'):
                points.append({
                    'ip':      ip,
                    'lat':     geo['lat'],
                    'lon':     geo['lon'],
                    'country': geo.get('country', 'Unknown'),
                    'city':    geo.get('city', ''),
                    'isp':     geo.get('isp', ''),
                    'count':   info.get('count', 1),
                })
                c = geo.get('country', 'Unknown')
                countries[c] = countries.get(c, 0) + info.get('count', 1)

        # Si plugin_manager tiene cache GeoIP, usarlo también
        if plugin_manager and plugin_manager.geoip:
            cache = plugin_manager.geoip._cache
            for ip, geo in cache.items():
                if not any(p['ip'] == ip for p in points):
                    if geo.get('lat') and geo.get('lon'):
                        points.append({
                            'ip':      ip,
                            'lat':     geo['lat'],
                            'lon':     geo['lon'],
                            'country': geo.get('country', 'Unknown'),
                            'city':    geo.get('city', ''),
                            'isp':     geo.get('isp', ''),
                            'count':   1,
                        })
                        c = geo.get('country', 'Unknown')
                        countries[c] = countries.get(c, 0) + 1

        top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:10]
        return jsonify({
            'points':        points,
            'countries':     dict(top_countries),
            'total_ips':     len(points),
            'total_ext_ips': len(dpi.get_external_ips()),
        })

    # ─────────────────────────────────────────────────────────────────────────
    # GET /api/v1/ml
    # ─────────────────────────────────────────────────────────────────────────
    @api.route('/ml')
    def ml_data():
        """Datos del motor de anomalías ML."""
        if not plugin_manager:
            return jsonify({'scores': [], 'anomalies': [], 'status': 'no_ml'})
        ae = getattr(plugin_manager, 'anomaly_engine', None)
        if not ae:
            return jsonify({'scores': [], 'anomalies': [], 'status': 'no_ml'})
        try:
            scores    = ae.get_scores() if hasattr(ae, 'get_scores') else {}
            anomalies = ae.get_recent_anomalies() if hasattr(ae, 'get_recent_anomalies') else []
            return jsonify({
                'scores':    scores,
                'anomalies': anomalies,
                'status':    'running',
            })
        except Exception as e:
            return jsonify({'scores': [], 'anomalies': [], 'status': f'error: {e}'})

    logger.info("API REST v1 blueprint creado — 14 endpoints")
    return api
