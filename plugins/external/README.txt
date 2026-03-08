PLUGINS EXTERNOS

Crear carpeta: plugins/external/mi_plugin/
Agregar plugin.json: {"name": "MiPlugin", "enabled": true}
Agregar main.py con clase Plugin(BasePlugin)

Hooks disponibles:
  on_packet(pkt), on_ids_alert(alert), on_new_device(dev)
  on_device_left(ip), on_tick(), on_threat_detected(ip, result)
