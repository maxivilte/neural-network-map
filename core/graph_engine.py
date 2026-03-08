"""
core/graph_engine.py
Graph topology engine using NetworkX.
Manages nodes, edges, layout, and network topology.
"""

import networkx as nx
import math
import random
import time
import threading
from typing import Dict, List, Optional, Tuple


class GraphEngine:
    def __init__(self):
        self.graph = nx.Graph()
        self.positions: Dict[str, Tuple[float, float]] = {}
        self.devices: Dict[str, dict] = {}
        self.gateway_ip: Optional[str] = None
        self._lock = threading.Lock()
        self._layout_width = 1400
        self._layout_height = 780
        self._center_x = self._layout_width // 2
        self._center_y = self._layout_height // 2

    def build_from_devices(self, devices: List) -> None:
        """Build graph from discovered devices."""
        with self._lock:
            self.graph.clear()
            self.devices.clear()

            # Find gateway
            for dev in devices:
                if dev.is_gateway:
                    self.gateway_ip = dev.ip
                    break

            if not self.gateway_ip and devices:
                self.gateway_ip = devices[0].ip

            # Add nodes
            for dev in devices:
                self.graph.add_node(dev.ip)
                self.devices[dev.ip] = dev.to_dict()

            # Add edges: all devices connect to gateway
            for dev in devices:
                if dev.ip != self.gateway_ip:
                    self.graph.add_edge(self.gateway_ip, dev.ip)

            self._compute_layout()

    def update_devices(self, new_devices: List) -> None:
        """Update graph with re-scan results."""
        with self._lock:
            new_ips = {d.ip for d in new_devices}
            existing_ips = set(self.devices.keys())

            # Remove stale nodes — preservar honeypot (nunca aparece en ARP scan)
            for ip in existing_ips - new_ips:
                if self.devices.get(ip, {}).get('device_type') == 'honeypot':
                    continue  # nunca eliminar el nodo honeypot
                if ip in self.graph:
                    self.graph.remove_node(ip)
                del self.devices[ip]

            # Add new nodes
            for dev in new_devices:
                if dev.ip not in existing_ips:
                    self.graph.add_node(dev.ip)
                    if self.gateway_ip and dev.ip != self.gateway_ip:
                        self.graph.add_edge(self.gateway_ip, dev.ip)
                self.devices[dev.ip] = dev.to_dict()

            self._compute_layout()

    def _compute_layout(self) -> None:
        """Compute visual positions for nodes."""
        if not self.graph.nodes:
            return

        # Preservar posiciones fijas (honeypot y otros nodos especiales)
        fixed_positions = {
            ip: pos for ip, pos in self.positions.items()
            if self.devices.get(ip, {}).get('device_type') == 'honeypot'
        }

        n = len(self.graph.nodes)

        if n == 1:
            ip = list(self.graph.nodes)[0]
            self.positions[ip] = (self._center_x, self._center_y)
            return

        # Gateway at center, others in orbits
        if self.gateway_ip and self.gateway_ip in self.graph.nodes:
            self.positions[self.gateway_ip] = (self._center_x, self._center_y)
            others = [ip for ip in self.graph.nodes if ip != self.gateway_ip]

            # Group by device type for orbit rings
            type_groups: Dict[str, List[str]] = {}
            for ip in others:
                dtype = self.devices.get(ip, {}).get('device_type', 'unknown')
                type_groups.setdefault(dtype, []).append(ip)

            rings = list(type_groups.values())
            base_radius = 200

            for ring_idx, ring_nodes in enumerate(rings):
                radius = base_radius + ring_idx * 130
                for i, ip in enumerate(ring_nodes):
                    # Add small random offset for organic feel
                    jitter_r = random.uniform(-20, 20)
                    jitter_a = random.uniform(-0.15, 0.15)
                    angle = (2 * math.pi / len(ring_nodes)) * i + jitter_a
                    r = radius + jitter_r
                    x = self._center_x + r * math.cos(angle)
                    y = self._center_y + r * math.sin(angle)
                    # Clamp to screen bounds
                    x = max(60, min(self._layout_width - 60, x))
                    y = max(60, min(self._layout_height - 60, y))
                    self.positions[ip] = (x, y)
        else:
            # Fallback: circular layout
            nodes = list(self.graph.nodes)
            for i, ip in enumerate(nodes):
                angle = (2 * math.pi / len(nodes)) * i
                x = self._center_x + 250 * math.cos(angle)
                y = self._center_y + 250 * math.sin(angle)
                self.positions[ip] = (x, y)

        # Restaurar posiciones fijas (honeypot no se mueve nunca)
        for ip, pos in fixed_positions.items():
            if ip in self.graph.nodes:
                self.positions[ip] = pos

    def get_edges(self) -> List[Tuple[str, str]]:
        return list(self.graph.edges())

    def get_nodes(self) -> List[str]:
        return list(self.graph.nodes())

    def get_position(self, ip: str) -> Tuple[float, float]:
        return self.positions.get(ip, (self._center_x, self._center_y))

    def get_device_info(self, ip: str) -> dict:
        return self.devices.get(ip, {})

    def get_neighbors(self, ip: str) -> List[str]:
        return list(self.graph.neighbors(ip))

    def add_honeypot_node(self, device) -> None:
        """Agrega el nodo honeypot al grafo para visualizarlo."""
        ip = device.ip if hasattr(device, 'ip') else device.get('ip', 'honeypot')
        with self._lock:
            self.graph.add_node(ip)
            self.devices[ip] = {
                'ip':          ip,
                'hostname':    '🍯 Honeypot',
                'vendor':      'NNM',
                'device_type': 'honeypot',
                'os_info':     'Virtual Trap',
                'is_gateway':  False,
                'is_alive':    True,
                'open_ports':  getattr(device, 'open_ports', []),
            }
            # Conectar al gateway si existe
            if self.gateway_ip and self.gateway_ip in self.graph.nodes:
                self.graph.add_edge(self.gateway_ip, ip)
            # Posicion fija: esquina superior derecha del grafo
            self.positions[ip] = (
                self._center_x + 350,
                self._center_y - 280,
            )
        print(f"\033[33m[🍯 Honeypot] Nodo agregado al grafo: {ip}\033[0m")
