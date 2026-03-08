"""
ui/renderer.py
Cyberpunk-style interactive renderer using Pygame.
FASE 5: 
 - Optimización FPS (pre-render de glows, surface caching)
 - Cambio de tema en vivo con tecla [T]
 - Mini-mapa en esquina inferior izquierda
 - Animación de entrada para nodos nuevos
 - Efectos visuales mejorados
"""

import pygame
import pygame.gfxdraw
import math
import random
import time
import threading
from typing import List, Tuple, Dict, Optional


# ─── Servicios por puerto ────────────────────────────────────────────────────
PORT_SERVICES_FALLBACK = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 135: "RPC",
    137: "NetBIOS", 139: "SMB", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 548: "AFP", 554: "RTSP", 631: "IPP/Print",
    1900: "UPnP", 3306: "MySQL", 3389: "RDP", 5000: "UPnP",
    5353: "mDNS", 5357: "WSD", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9100: "Print-RAW", 62078: "iPhone-Sync",
}

def _port_color(port: int, colors: dict) -> tuple:
    if port in (80, 8080, 8888):      return (0, 200, 255)
    if port in (443, 8443):           return (0, 120, 255)
    if port == 22:                    return (255, 80, 80)
    if port == 3389:                  return (255, 150, 0)
    if port in (9100, 631):           return (180, 255, 180)
    if port in (137, 139, 445, 5357): return (180, 180, 255)
    if port in (5353, 548, 62078):    return (200, 160, 255)
    if port == 1900:                  return (255, 220, 80)
    return colors.get('text', (180, 255, 255))


# ─── DataPulse ───────────────────────────────────────────────────────────────

class DataPulse:
    def __init__(self, start, end, color):
        self.start    = start
        self.end      = end
        self.color    = color
        self.progress = random.uniform(0.0, 1.0)
        self.speed    = random.uniform(0.003, 0.012)
        self.size     = random.randint(3, 6)
        self.alive    = True

    def update(self):
        self.progress += self.speed
        if self.progress >= 1.0:
            self.progress = 0.0

    def get_pos(self):
        x = self.start[0] + (self.end[0] - self.start[0]) * self.progress
        y = self.start[1] + (self.end[1] - self.start[1]) * self.progress
        return (int(x), int(y))


# ─── Particle ────────────────────────────────────────────────────────────────

class Particle:
    def __init__(self, width, height, color):
        self.x      = random.uniform(0, width)
        self.y      = random.uniform(0, height)
        self.vx     = random.uniform(-0.3, 0.3)
        self.vy     = random.uniform(-0.3, 0.3)
        self.size   = random.uniform(1, 3)
        self.alpha  = random.randint(40, 140)
        self.color  = color
        self.width  = width
        self.height = height

    def update(self):
        self.x = (self.x + self.vx) % self.width
        self.y = (self.y + self.vy) % self.height


# ─── EdgeParticle — Fase 13: partículas que viajan entre nodos ───────────────

class EdgeParticle:
    """
    Partícula que viaja a lo largo de una arista del grafo.
    Más rápida y brillante que DataPulse — representa tráfico activo DPI.
    """
    def __init__(self, node_a: str, node_b: str, color: tuple, speed_mult: float = 1.0):
        self.node_a    = node_a
        self.node_b    = node_b
        self.color     = color
        self.progress  = random.uniform(0.0, 1.0)
        self.speed     = random.uniform(0.006, 0.018) * speed_mult
        self.size      = random.uniform(2.0, 4.5)
        self.alpha     = random.randint(160, 255)
        self.alive     = True
        self.tail_len  = random.randint(3, 7)  # longitud de la estela

    def update(self):
        self.progress += self.speed
        if self.progress >= 1.0:
            self.progress = 0.0

    def get_pos_and_tail(self, sx1, sy1, sx2, sy2):
        """Devuelve posición actual y puntos de la estela."""
        pos = (
            sx1 + (sx2 - sx1) * self.progress,
            sy1 + (sy2 - sy1) * self.progress,
        )
        tail = []
        for i in range(1, self.tail_len + 1):
            t = max(0.0, self.progress - self.speed * i * 2.5)
            tail.append((
                sx1 + (sx2 - sx1) * t,
                sy1 + (sy2 - sy1) * t,
            ))
        return pos, tail


# ─── AttackRadarBlip — Fase 13: blip en el radar ─────────────────────────────

class AttackRadarBlip:
    """Representa un hit detectado en el radar de ataques."""
    def __init__(self, angle: float, dist_norm: float, color: tuple, label: str):
        self.angle      = angle        # radianes
        self.dist_norm  = dist_norm    # 0..1 desde centro
        self.color      = color
        self.label      = label[:18]
        self.alpha      = 255
        self.born       = 0            # se asigna en tick al crear
        self.ttl        = 420          # ~7 segundos a 60fps

    def is_alive(self, tick: int) -> bool:
        return (tick - self.born) < self.ttl

    def get_alpha(self, tick: int) -> int:
        age = tick - self.born
        return max(0, int(255 * (1 - age / self.ttl)))


# ─── TimelineEvent — Fase 13: evento en la barra de timeline ─────────────────

class TimelineEvent:
    """Evento visual en la barra de timeline de alertas."""
    def __init__(self, tick: int, color: tuple, icon: str, label: str, severity: str):
        self.tick     = tick
        self.color    = color
        self.icon     = icon
        self.label    = label[:22]
        self.severity = severity
        self.alpha    = 255


# ─── NodeSpawnEffect — animación de entrada ──────────────────────────────────

class NodeSpawnEffect:
    """Onda expansiva cuando un nodo nuevo aparece."""
    def __init__(self, sx, sy, color):
        self.sx    = sx
        self.sy    = sy
        self.color = color
        self.r     = 0
        self.max_r = 80
        self.alpha = 255
        self.alive = True

    def update(self):
        self.r     += 4
        self.alpha  = max(0, int(255 * (1 - self.r / self.max_r)))
        if self.r >= self.max_r:
            self.alive = False

    def draw(self, screen):
        if not self.alive or self.r <= 0:
            return
        s = pygame.Surface((self.r * 2 + 4, self.r * 2 + 4), pygame.SRCALPHA)
        pygame.draw.circle(s, (*self.color, self.alpha), (self.r + 2, self.r + 2), self.r, 2)
        screen.blit(s, (self.sx - self.r - 2, self.sy - self.r - 2))


# ─── GlowCache — pre-renderiza los glows una sola vez ────────────────────────

class GlowCache:
    """
    Pre-renderiza superficies de glow para evitar crearlas en cada frame.
    Clave para pasar de 20 FPS a 60 FPS.
    """
    def __init__(self):
        self._cache: Dict[tuple, pygame.Surface] = {}

    def get(self, color: tuple, radius: int, alpha: int) -> pygame.Surface:
        key = (color, radius, alpha)
        if key not in self._cache:
            size = radius * 2 + 4
            s = pygame.Surface((size, size), pygame.SRCALPHA)
            s = s.convert_alpha()
            pygame.draw.circle(s, (*color, alpha), (radius + 2, radius + 2), radius)
            self._cache[key] = s
        return self._cache[key]

    def get_ring(self, color: tuple, radius: int, alpha: int, width: int = 2) -> pygame.Surface:
        key = (color, radius, alpha, width, 'ring')
        if key not in self._cache:
            size = radius * 2 + 4
            s = pygame.Surface((size, size), pygame.SRCALPHA)
            s = s.convert_alpha()
            pygame.draw.circle(s, (*color, alpha), (radius + 2, radius + 2), radius, width)
            self._cache[key] = s
        return self._cache[key]

    def clear(self):
        self._cache.clear()


# ─── Main Renderer ───────────────────────────────────────────────────────────

class CyberpunkRenderer:

    DEVICE_ICONS = {
        "router":   "⬡", "server":  "▣", "phone":   "◈",
        "laptop":   "◧", "desktop": "⬜", "printer": "⊞",
        "iot":      "⊛", "smart_tv":"⬛", "raspberry":"◉",
        "nas":      "⊟", "camera":  "◎", "unknown": "◇",
    }

    # Todos los temas disponibles — tecla T para ciclar
    THEME_ORDER = ['cyberpunk', 'matrix', 'neon', 'amber']

    def __init__(self, graph_engine, traffic_monitor, settings):
        self.graph    = graph_engine
        self.traffic  = traffic_monitor
        self.settings = settings
        self.colors   = settings.colors

        # Agregar tema amber si no existe
        if 'amber' not in settings.themes:
            settings.themes['amber'] = {
                'bg':           (10, 6, 0),
                'node_default': (255, 160, 0),
                'node_gateway': (255, 80, 0),
                'node_unknown': (180, 100, 0),
                'node_active':  (255, 220, 80),
                'edge':         (120, 60, 0),
                'pulse':        (255, 200, 50),
                'text':         (255, 200, 120),
                'grid':         (30, 15, 0),
                'glow':         (200, 120, 0),
            }

        self._theme_idx = self.THEME_ORDER.index(settings.theme) if settings.theme in self.THEME_ORDER else 0

        pygame.init()
        pygame.display.set_caption("⬡ NEURAL NETWORK MAP ⬡")
        self.screen = pygame.display.set_mode(
            (settings.window_width, settings.window_height),
            pygame.RESIZABLE | pygame.DOUBLEBUF | pygame.HWSURFACE
        )
        self.clock   = pygame.time.Clock()
        self.running = True

        # Camera
        self.offset_x  = 0.0
        self.offset_y  = 0.0
        self.zoom      = 1.0
        self._dragging = False
        self._drag_start = (0, 0)

        # State
        self.pulses: List[DataPulse]         = []
        self.particles: List[Particle]       = []
        self.spawn_effects: List[NodeSpawnEffect] = []
        self.hovered_node: Optional[str]     = None
        self.selected_node: Optional[str]    = None
        self.tick = 0
        self.show_info_panel = True
        self._known_nodes = set()  # para detectar nodos nuevos

        # Fase 5: mini-mapa
        self._show_minimap = True
        self._minimap_rect = pygame.Rect(0, 0, 180, 120)  # se recalcula en draw

        # Fase 5: glow cache
        self._glow_cache = GlowCache()

        # Fase 5: grid surface pre-renderizada
        self._grid_surface = None
        self._grid_tick_last = -999

        # ── Fase 13: partículas entre nodos ──────────────────────────────────
        self._edge_particles: List[EdgeParticle] = []
        self._edge_particle_tick = 0   # para spawn controlado

        # ── Fase 13: radar de ataques ─────────────────────────────────────────
        self._radar_angle   = 0.0      # ángulo del barrido actual (radianes)
        self._radar_blips: List[AttackRadarBlip] = []
        self._radar_trail: List[float] = []  # trail del barrido

        # ── Fase 13: timeline de alertas ──────────────────────────────────────
        self._timeline_events: List[TimelineEvent] = []
        self._timeline_max   = 60      # máx eventos visibles
        self._timeline_hover = -1      # índice bajo el mouse

        # Scan on-demand
        self.scanner = None
        self._scan_states: Dict[str, str] = {}
        self._scan_btn_rect = None

        # IDS
        self.ids = None
        self._visual_alerts: List[dict] = []
        self._show_ids_panel = True
        self._alert_flash    = 0

        # DB
        self.db = None
        self._show_history_panel = False

        # DPI
        self.dpi = None

        # Fonts
        try:
            self.font_sm    = pygame.font.SysFont("monospace", 11)
            self.font_md    = pygame.font.SysFont("monospace", 14, bold=True)
            self.font_lg    = pygame.font.SysFont("monospace", 18, bold=True)
            self.font_title = pygame.font.SysFont("monospace", 22, bold=True)
        except Exception:
            self.font_sm    = pygame.font.Font(None, 16)
            self.font_md    = pygame.font.Font(None, 20)
            self.font_lg    = pygame.font.Font(None, 24)
            self.font_title = pygame.font.Font(None, 28)

        self.w = settings.window_width
        self.h = settings.window_height

        # Init particles
        self._reinit_particles()
        self._init_pulses()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _reinit_particles(self):
        self.particles.clear()
        for _ in range(60):  # reducido de 80 a 60 para FPS
            self.particles.append(Particle(self.w, self.h, self.colors['glow']))

    def _init_pulses(self):
        self.pulses.clear()
        for (a, b) in self.graph.get_edges():
            pa = self.graph.get_position(a)
            pb = self.graph.get_position(b)
            for _ in range(random.randint(1, 2)):  # reducido a 2 por borde
                self.pulses.append(DataPulse(pa, pb, self.colors['pulse']))
                self.pulses.append(DataPulse(pb, pa, self.colors['pulse']))

    def _cycle_theme(self):
        """Cambia al siguiente tema — tecla T."""
        self._theme_idx = (self._theme_idx + 1) % len(self.THEME_ORDER)
        theme_name = self.THEME_ORDER[self._theme_idx]
        self.settings.theme  = theme_name
        self.settings.colors = self.settings.themes[theme_name]
        self.colors = self.settings.colors
        self._glow_cache.clear()
        self._grid_surface = None
        self._reinit_particles()
        self._init_pulses()
        print(f"\033[36m[~] Tema cambiado a: {theme_name}\033[0m")

    def _world_to_screen(self, wx, wy) -> Tuple[int, int]:
        sx = int((wx + self.offset_x) * self.zoom)
        sy = int((wy + self.offset_y) * self.zoom)
        return sx, sy

    def _screen_to_world(self, sx, sy) -> Tuple[float, float]:
        wx = sx / self.zoom - self.offset_x
        wy = sy / self.zoom - self.offset_y
        return wx, wy

    # ── Grid (optimizada) ─────────────────────────────────────────────────────

    def _draw_grid(self):
        """Grid optimizada: solo re-renderiza cada 4 ticks o si el offset cambia."""
        grid_color = self.colors['grid']
        spacing    = int(50 * self.zoom)
        if spacing < 10:
            return

        # Re-dibujar solo si cambió algo relevante
        needs_redraw = (
            self._grid_surface is None or
            abs(self.tick - self._grid_tick_last) >= 4
        )
        if not needs_redraw:
            self.screen.blit(self._grid_surface, (0, 0))
            return

        surf = pygame.Surface((self.w, self.h))
        surf.fill(self.colors['bg'])

        ox = int(self.offset_x * self.zoom) % spacing
        oy = int(self.offset_y * self.zoom) % spacing

        base_alpha = 40
        for x in range(-spacing + ox, self.w + spacing, spacing):
            a = base_alpha + int(15 * math.sin(self.tick * 0.02 + x * 0.01))
            color = tuple(min(255, int(c * a / 80)) for c in grid_color)
            pygame.draw.line(surf, color, (x, 0), (x, self.h), 1)

        for y in range(-spacing + oy, self.h + spacing, spacing):
            a = base_alpha + int(15 * math.sin(self.tick * 0.02 + y * 0.01))
            color = tuple(min(255, int(c * a / 80)) for c in grid_color)
            pygame.draw.line(surf, color, (0, y), (self.w, y), 1)

        self._grid_surface = surf
        self._grid_tick_last = self.tick
        self.screen.blit(surf, (0, 0))

    # ── Edges (optimizadas) ───────────────────────────────────────────────────

    def _draw_edge(self, a: str, b: str):
        """Edge con glow simplificado — 2 capas en vez de 3."""
        pa = self._world_to_screen(*self.graph.get_position(a))
        pb = self._world_to_screen(*self.graph.get_position(b))
        ec = self.colors['edge']
        # Capa glow
        pygame.draw.line(self.screen, tuple(c // 4 for c in ec), pa, pb, 4)
        # Capa principal
        pygame.draw.line(self.screen, tuple(min(255, c * 2) for c in ec), pa, pb, 1)

    # ── Pulses ────────────────────────────────────────────────────────────────

    def _draw_pulse(self, pulse: DataPulse):
        sx1, sy1 = self._world_to_screen(*pulse.start)
        sx2, sy2 = self._world_to_screen(*pulse.end)
        px = int(sx1 + (sx2 - sx1) * pulse.progress)
        py = int(sy1 + (sy2 - sy1) * pulse.progress)
        c    = pulse.color
        size = max(2, int(pulse.size * self.zoom))

        # Glow usando cache
        glow = self._glow_cache.get(c, size * 2, 40)
        self.screen.blit(glow, (px - size * 2 - 2, py - size * 2 - 2))
        core = self._glow_cache.get(c, size, 200)
        self.screen.blit(core, (px - size - 2, py - size - 2))

    # ── Nodes ─────────────────────────────────────────────────────────────────

    def _get_node_color(self, ip: str) -> Tuple:
        info  = self.graph.get_device_info(ip)
        if info.get('is_gateway'):
            return self.colors['node_gateway']
        # Nodo honeypot — amarillo/naranja pulsante
        if info.get('device_type') == 'honeypot':
            return (255, 180, 0)
        dtype = info.get('device_type', 'unknown')
        if dtype in ('server', 'nas', 'raspberry'):
            return self.colors['node_active']
        if dtype == 'unknown':
            return self.colors['node_unknown']
        return self.colors['node_default']

    def _draw_node(self, ip: str):
        wx, wy     = self.graph.get_position(ip)
        sx, sy     = self._world_to_screen(wx, wy)
        info       = self.graph.get_device_info(ip)
        color      = self._get_node_color(ip)
        r          = int(self.settings.node_radius * self.zoom)
        is_hovered  = (ip == self.hovered_node)
        is_selected = (ip == self.selected_node)
        is_gateway  = info.get('is_gateway', False)

        # Detectar nodo nuevo → spawn effect
        if ip not in self._known_nodes:
            self._known_nodes.add(ip)
            self.spawn_effects.append(NodeSpawnEffect(sx, sy, color))

        # Gateway pulse rings — usando cache
        if is_gateway:
            pulse_r = r + int(10 * (0.5 + 0.5 * math.sin(self.tick * 0.05)))
            for pr, pa in [(pulse_r + 8, 15), (pulse_r + 4, 30), (pulse_r, 70)]:
                ring = self._glow_cache.get_ring(color, pr, pa, 2)
                self.screen.blit(ring, (sx - pr - 2, sy - pr - 2))

        # Honeypot — anillo pulsante naranja + label "🍯"
        if info.get('device_type') == 'honeypot':
            hp_color = (255, 140, 0)
            pulse_r  = r + int(14 * (0.5 + 0.5 * math.sin(self.tick * 0.08)))
            for pr, pa in [(pulse_r + 10, 10), (pulse_r + 5, 25), (pulse_r, 60)]:
                ring = self._glow_cache.get_ring(hp_color, pr, pa, 2)
                self.screen.blit(ring, (sx - pr - 2, sy - pr - 2))
            # Label "HONEYPOT"
            hp_label = self.font_sm.render("🍯 HONEYPOT", True, (255, 200, 0))
            self.screen.blit(hp_label, (sx - hp_label.get_width() // 2, sy - r - 22))

        # Hover/selected ring
        if is_hovered or is_selected:
            hr   = r + 8
            ring = self._glow_cache.get_ring(color, hr, 100, 3)
            self.screen.blit(ring, (sx - hr - 2, sy - hr - 2))

        # Glow layers usando cache — OPTIMIZADO
        for gr, ga in [(r * 3, 10), (r * 2, 28), (r + 4, 55)]:
            glow = self._glow_cache.get(color, gr, ga)
            self.screen.blit(glow, (sx - gr - 2, sy - gr - 2))

        # Core
        pygame.draw.circle(self.screen, color, (sx, sy), r)
        pygame.draw.circle(self.screen, (255, 255, 255), (sx, sy), max(1, r // 3))
        pygame.draw.circle(self.screen, color, (sx, sy), r, 2)

        # Label
        if self.settings.show_labels and r > 8:
            hostname = info.get('hostname', ip)
            if hostname == 'Unknown':
                hostname = ip
            label = self.font_sm.render(hostname, True, self.colors['text'])
            self.screen.blit(label, (sx - label.get_width() // 2, sy + r + 4))
            dtype = info.get('device_type', '')
            if dtype:
                dt = self.font_sm.render(f"[{dtype}]", True,
                                          tuple(max(0, c - 60) for c in self.colors['text']))
                self.screen.blit(dt, (sx - dt.get_width() // 2, sy + r + 18))

    def _get_node_at(self, sx, sy) -> Optional[str]:
        threshold = self.settings.node_radius * self.zoom * 1.5
        for ip in self.graph.get_nodes():
            wx, wy = self.graph.get_position(ip)
            nsx, nsy = self._world_to_screen(wx, wy)
            if math.hypot(sx - nsx, sy - nsy) < threshold:
                return ip
        return None

    # ── Tooltip ───────────────────────────────────────────────────────────────

    def _draw_tooltip(self, ip: str):
        info  = self.graph.get_device_info(ip)
        lines = [
            f"IP:       {info.get('ip', ip)}",
            f"Hostname: {info.get('hostname', 'Unknown')}",
            f"MAC:      {info.get('mac', '??:??:??:??:??:??')}",
            f"Vendor:   {info.get('vendor', 'Unknown')}",
            f"Type:     {info.get('device_type', 'unknown')}",
            f"Ports:    {info.get('open_ports', [])}",
        ]
        pad    = 12
        line_h = 18
        w      = max(self.font_sm.size(l)[0] for l in lines) + pad * 2
        h      = len(lines) * line_h + pad * 2
        wx, wy = self.graph.get_position(ip)
        sx, sy = self._world_to_screen(wx, wy)
        tx = min(sx + 25, self.w - w - 10)
        ty = min(sy - 10, self.h - h - 10)
        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((5, 10, 25, 220))
        pygame.draw.rect(surf, self.colors['node_default'], (0, 0, w, h), 1)
        self.screen.blit(surf, (tx, ty))
        header = self.font_md.render(f"◉ {info.get('hostname', ip)}", True, self.colors['node_default'])
        self.screen.blit(header, (tx + pad, ty + 4))
        for i, line in enumerate(lines[1:], 1):
            txt = self.font_sm.render(line, True, self.colors['text'])
            self.screen.blit(txt, (tx + pad, ty + pad + i * line_h - 2))

    # ── HUD ───────────────────────────────────────────────────────────────────

    def _draw_hud(self):
        title = self.font_title.render("⬡ NEURAL NETWORK MAP", True, self.colors['node_gateway'])
        self.screen.blit(title, (16, 10))

        n_devices = len(self.graph.get_nodes())
        n_edges   = len(self.graph.get_edges())
        theme_name = self.THEME_ORDER[self._theme_idx].upper()
        stats = [
            f"NODES: {n_devices}",
            f"EDGES: {n_edges}",
            f"SUBNET: {self.settings.subnet}",
            f"ZOOM: {self.zoom:.1f}x",
            f"TEMA: {theme_name}",
        ]
        for i, s in enumerate(stats):
            surf = self.font_sm.render(s, True, self.colors['text'])
            self.screen.blit(surf, (16, 38 + i * 16))

        # IDS counters
        if self.ids:
            counts = self.ids.get_alert_count()
            unread = self.ids.get_unread_count()
            y_ids  = 38 + len(stats) * 16 + 6
            if unread > 0 and self.tick % 60 < 30:
                flash = pygame.Surface((170, 16), pygame.SRCALPHA)
                flash.fill((255, 50, 50, 40))
                self.screen.blit(flash, (12, y_ids - 2))
            ids_color = (
                (255, 80, 80)   if counts['CRITICAL'] > 0 else
                (255, 200, 0)   if counts['WARN']     > 0 else
                self.colors['text']
            )
            ids_text = (f"IDS  CRIT:{counts['CRITICAL']}  WARN:{counts['WARN']}  INFO:{counts['INFO']}"
                        + (f"  [{unread} NUEVAS]" if unread > 0 else ""))
            self.screen.blit(self.font_sm.render(ids_text, True, ids_color), (16, y_ids))
            self.screen.blit(self.font_sm.render("[I] Panel IDS",
                             True, tuple(max(0,c-80) for c in self.colors['text'])), (16, y_ids + 14))

        # Controls hint
        hints = "[SCROLL] Zoom  [DRAG] Pan  [CLICK] Select  [T] Tema  [R] Reset  [L] Labels  [I] IDS  [H] Historial  [M] Mapa  [Q] Quit"
        hint_surf = self.font_sm.render(hints, True, tuple(max(0, c - 80) for c in self.colors['text']))
        self.screen.blit(hint_surf, (16, self.h - 20))

        # FPS top right — con color por rendimiento
        fps_val = self.clock.get_fps()
        fps_str = f"{fps_val:.0f}" if fps_val > 0 else "..."
        fps_col = (
            self.colors['node_active'] if fps_val >= 50 else
            (255, 200, 0)              if fps_val >= 25 else
            (255, 80, 80)
        )
        self.screen.blit(self.font_sm.render(f"FPS {fps_str}", True, fps_col),
                         (self.w - 70, 10))

        # Reloj
        ts_surf = self.font_md.render(time.strftime("%H:%M:%S"), True, self.colors['node_default'])
        self.screen.blit(ts_surf, (self.w - ts_surf.get_width() - 16, 24))

        # Indicador de tema (arriba derecha)
        theme_surf = self.font_sm.render(f"[ {self.THEME_ORDER[self._theme_idx].upper()} ]",
                                          True, self.colors['node_gateway'])
        self.screen.blit(theme_surf, (self.w - theme_surf.get_width() - 16, 42))

    # ── Mini-mapa ─────────────────────────────────────────────────────────────

    def _draw_minimap(self):
        """Mini-mapa en esquina inferior izquierda — tecla M."""
        if not self._show_minimap:
            return

        nodes = list(self.graph.get_nodes())
        if not nodes:
            return

        mm_w, mm_h = 180, 120
        mm_x = 10
        mm_y = self.h - mm_h - 30

        # Fondo
        surf = pygame.Surface((mm_w, mm_h), pygame.SRCALPHA)
        surf.fill((5, 8, 20, 200))
        pygame.draw.rect(surf, tuple(c // 2 for c in self.colors['node_default']),
                         (0, 0, mm_w, mm_h), 1)
        self.screen.blit(surf, (mm_x, mm_y))

        # Título
        title = self.font_sm.render("MINIMAP", True,
                                     tuple(c // 2 for c in self.colors['node_default']))
        self.screen.blit(title, (mm_x + 4, mm_y + 2))

        # Calcular bounds del mundo
        positions = [self.graph.get_position(ip) for ip in nodes]
        if not positions:
            return
        xs = [p[0] for p in positions]
        ys = [p[1] for p in positions]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        world_w = max(max_x - min_x, 1)
        world_h = max(max_y - min_y, 1)

        pad = 12

        def world_to_mini(wx, wy):
            nx = mm_x + pad + int((wx - min_x) / world_w * (mm_w - pad * 2))
            ny = mm_y + pad + int((wy - min_y) / world_h * (mm_h - pad * 2))
            return nx, ny

        # Edges en mini-mapa
        for (a, b) in self.graph.get_edges():
            pa = world_to_mini(*self.graph.get_position(a))
            pb = world_to_mini(*self.graph.get_position(b))
            pygame.draw.line(self.screen,
                             tuple(c // 3 for c in self.colors['edge']), pa, pb, 1)

        # Nodos en mini-mapa
        for ip in nodes:
            nx, ny = world_to_mini(*self.graph.get_position(ip))
            color  = self._get_node_color(ip)
            r      = 4 if self.graph.get_device_info(ip).get('is_gateway') else 2
            pygame.draw.circle(self.screen, color, (nx, ny), r)

        # Viewport indicator — rectángulo que muestra la vista actual
        vp_w = int(mm_w * (self.w / max(world_w * self.zoom, 1)) * 0.5)
        vp_h = int(mm_h * (self.h / max(world_h * self.zoom, 1)) * 0.5)
        vp_x = mm_x + pad + int((-self.offset_x - min_x / 1) / max(world_w, 1) * (mm_w - pad * 2))
        vp_y = mm_y + pad + int((-self.offset_y - min_y / 1) / max(world_h, 1) * (mm_h - pad * 2))
        pygame.draw.rect(self.screen, self.colors['node_gateway'],
                         (vp_x, vp_y, max(vp_w, 8), max(vp_h, 8)), 1)

        self._minimap_rect = pygame.Rect(mm_x, mm_y, mm_w, mm_h)

    # ── Panel lateral derecho ─────────────────────────────────────────────────

    def _draw_selected_panel(self):
        if not self.selected_node:
            return
        ip        = self.selected_node
        info      = self.graph.get_device_info(ip)
        neighbors = self.graph.get_neighbors(ip)
        c         = self.colors

        ports         = info.get('open_ports', [])
        port_services = info.get('port_services', {})
        os_info       = info.get('os_info', '')
        n_ports       = len(ports)
        dpi_activity  = self.dpi.get_device_activity(ip) if self.dpi else []
        n_activity    = len(dpi_activity)

        ph = 280 + max(0, n_ports - 3) * 16 + (16 if os_info else 0) + len(neighbors[:6]) * 16 + (24 + n_activity * 16 if n_activity else 0)
        ph = min(ph, self.h - 60)
        pw = 280
        px = self.w - pw - 10
        py = 40

        surf = pygame.Surface((pw, ph), pygame.SRCALPHA)
        surf.fill((5, 8, 20, 235))
        dtype = info.get('device_type', 'unknown')
        border_colors = {
            'router': c['node_gateway'], 'phone': c['node_active'],
            'printer': (0, 180, 255), 'windows_pc': (100, 180, 255),
            'server': (255, 200, 0), 'unknown': c['node_unknown'],
        }
        border_col = border_colors.get(dtype, c['node_default'])
        pygame.draw.rect(surf, border_col, (0, 0, pw, ph), 1)
        self.screen.blit(surf, (px, py))

        pad = 10
        y   = py + pad

        def draw_line(text, color, bold=False, indent=0):
            nonlocal y
            font = self.font_md if bold else self.font_sm
            s    = font.render(text, True, color)
            self.screen.blit(s, (px + pad + indent, y))
            y   += 18 if bold else 15

        def draw_separator():
            nonlocal y
            pygame.draw.line(self.screen, tuple(max(0, v - 120) for v in c['node_default']),
                             (px + 6, y + 2), (px + pw - 6, y + 2), 1)
            y += 8

        hostname = info.get('hostname', ip)
        draw_line("◈ DISPOSITIVO", c['node_gateway'], bold=True)
        draw_line(f"  {hostname}", c['node_default'])
        draw_separator()

        draw_line(f"IP      {info.get('ip', ip)}", c['text'])
        draw_line(f"MAC     {info.get('mac', '??')}", c['text'])
        vendor = info.get('vendor', 'Unknown')
        draw_line(f"Vendor  {vendor}", c['node_active'] if vendor != 'Unknown' else c['text'])
        draw_line(f"Tipo    {dtype}", border_col)
        if os_info:
            draw_line(f"OS      {os_info[:32]}", (255, 200, 100))
        ttl = info.get('ttl', 0)
        if ttl:
            draw_line(f"TTL     {ttl}", tuple(max(0, v - 60) for v in c['text']))
        draw_separator()

        scan_state = self._scan_states.get(ip, 'idle')
        if scan_state == 'scanning':
            dots = '.' * (1 + (self.tick // 20) % 3)
            draw_line(f"⬡ SCANNING{dots}", (255, 200, 0), bold=True)
        elif n_ports > 0:
            draw_line(f"PUERTOS ABIERTOS ({n_ports})", c['node_gateway'], bold=True)
            for port in ports[:12]:
                svc  = port_services.get(port, PORT_SERVICES_FALLBACK.get(port, f'PORT-{port}'))
                draw_line(f"  {port:5d}  {svc[:28]}", _port_color(port, c), indent=4)
        else:
            draw_line("PUERTOS  (ninguno)", tuple(max(0, v - 80) for v in c['text']))
        draw_separator()

        # Botón scan
        btn_y = y
        btn_w = pw - 20
        btn_h = 22
        btn_x = px + 10
        if scan_state == 'idle':
            btn_col, btn_txt = c['node_active'], "[ SCAN PUERTOS (Nmap) ]"
        elif scan_state == 'scanning':
            btn_col, btn_txt = (255, 200, 0), "[ ESCANEANDO... ]"
        else:
            btn_col, btn_txt = tuple(max(0, v - 80) for v in c['node_active']), "[ RE-SCAN ]"

        pygame.draw.rect(self.screen, tuple(v // 6 for v in btn_col), (btn_x, btn_y, btn_w, btn_h))
        pygame.draw.rect(self.screen, btn_col, (btn_x, btn_y, btn_w, btn_h), 1)
        ts = self.font_sm.render(btn_txt, True, btn_col)
        self.screen.blit(ts, (btn_x + btn_w // 2 - ts.get_width() // 2, btn_y + 5))
        self._scan_btn_rect = pygame.Rect(btn_x, btn_y, btn_w, btn_h)
        y += btn_h + 8
        draw_separator()

        # DPI
        if self.dpi and dpi_activity:
            draw_line("ACTIVIDAD DETECTADA", c['node_gateway'], bold=True)
            for act in dpi_activity:
                draw_line(f"  {act.icon} {act.service[:18]}  {act.age_str}", act.color, indent=2)
            draw_separator()
        elif self.dpi:
            draw_line("ACTIVIDAD  (sin datos aun)", tuple(max(0, v - 100) for v in c['text']))
            draw_separator()

        # Conexiones
        draw_line(f"CONEXIONES ({len(neighbors)})", c['node_gateway'], bold=True)
        for n in neighbors[:6]:
            ninfo  = self.graph.get_device_info(n)
            nlabel = ninfo.get('hostname', n) if ninfo else n
            draw_line(f"  → {n} ({nlabel})", c['node_active'], indent=2)

    # ── Traffic panel ─────────────────────────────────────────────────────────

    def _draw_traffic_panel(self):
        if not hasattr(self, 'sniffer'):
            return
        events = self.sniffer.get_recent_events(12)
        if not events:
            return
        pw, ph = 420, 260
        px, py = self.w - pw - 10, self.h - ph - 30
        surf = pygame.Surface((pw, ph), pygame.SRCALPHA)
        surf.fill((5, 8, 20, 220))
        pygame.draw.rect(surf, self.colors['node_active'], (0, 0, pw, ph), 1)
        self.screen.blit(surf, (px, py))
        header = self.font_md.render("◉ LIVE TRAFFIC", True, self.colors['node_active'])
        self.screen.blit(header, (px + 10, py + 8))
        proto_colors = {
            'DNS': (0, 255, 180), 'HTTP': (0, 180, 255),
            'HTTPS': (0, 120, 255), 'ARP': (255, 200, 0),
            'ICMP': (255, 100, 0), 'TCP': (180, 180, 255),
            'UDP': (200, 255, 200), 'SSH': (255, 50, 50),
        }
        for i, ev in enumerate(reversed(events)):
            ey = py + 30 + i * 19
            color = proto_colors.get(ev.protocol, self.colors['text'])
            self.screen.blit(self.font_sm.render(f"{ev.protocol:6s}", True, color), (px + 10, ey))
            self.screen.blit(self.font_sm.render(f"{ev.src_ip:15s}", True, self.colors['text']), (px + 70, ey))
            self.screen.blit(self.font_sm.render(ev.info[:22], True,
                             tuple(max(0, c - 60) for c in self.colors['text'])), (px + 210, ey))

    # ── Nmap on-demand ────────────────────────────────────────────────────────

    def _trigger_nmap_scan(self, ip: str):
        if not self.scanner:
            return
        self._scan_states[ip] = 'scanning'
        print(f"\033[36m[~] Iniciando Nmap scan para {ip}...\033[0m")

        def run_scan():
            result  = self.scanner.nmap_scan_device(ip)
            dev_info = self.graph.get_device_info(ip)
            if dev_info:
                if result.get('os_info'):
                    dev_info['os_info'] = result['os_info']
                if result.get('open_ports'):
                    dev_info['open_ports']    = result['open_ports']
                    dev_info['port_services'] = result['port_services']
                with self.graph._lock:
                    self.graph.devices[ip] = dev_info
            self._scan_states[ip] = 'done'
            print(f"\033[32m[+] Scan {ip} completo: {len(result.get('open_ports',[]))} puertos | OS: {result.get('os_info','')}\033[0m")

        threading.Thread(target=run_scan, daemon=True).start()

    # ── IDS Visual ────────────────────────────────────────────────────────────

    def on_ids_alert(self, alert):
        self._visual_alerts.append({
            'ip':      alert.ip,
            'color':   alert.color,
            'message': f"{alert.icon} {alert.message}",
            'born':    self.tick,
            'ttl':     300,
        })
        self._alert_flash = 120

        # ── Fase 13: alimentar radar y timeline ───────────────────────────────
        self._add_radar_blip(alert)
        self._add_timeline_event(alert)

    def _draw_ids_alerts(self):
        now   = self.tick
        alive = []
        for va in self._visual_alerts:
            age = now - va['born']
            if age > va['ttl']:
                continue
            alive.append(va)
            ip = va['ip']
            if ip not in self.graph.get_nodes():
                continue
            sx, sy = self._world_to_screen(*self.graph.get_position(ip))
            if (now // 15) % 2 == 0:
                r     = 28 + int(6 * abs(math.sin(now * 0.08)))
                alpha = max(40, 180 - int(180 * age / va['ttl']))
                ring  = self._glow_cache.get_ring(va['color'], r, alpha, 2)
                self.screen.blit(ring, (sx - r - 2, sy - r - 2))
            float_y   = sy - 36 - int(age * 0.04)
            alpha_txt = max(0, 255 - int(255 * age / va['ttl']))
            txt = self.font_sm.render(va['message'][:40], True, va['color'])
            txt.set_alpha(alpha_txt)
            self.screen.blit(txt, (sx - txt.get_width() // 2, float_y))
        self._visual_alerts = alive

    def _draw_ids_panel(self):
        if not self._show_ids_panel or not self.ids:
            return
        alerts = self.ids.get_recent_alerts(12)
        if not alerts:
            return
        pw, ph       = 380, min(30 + len(alerts) * 22 + 10, 310)
        px, py       = 10, self.h // 2 - ph // 2
        surf         = pygame.Surface((pw, ph), pygame.SRCALPHA)
        surf.fill((5, 8, 20, 210))
        border_color = self.colors['text']
        for a in alerts:
            if a.severity == "CRITICAL":
                border_color = (255, 50, 50); break
            elif a.severity == "WARN":
                border_color = (255, 200, 0)
        pygame.draw.rect(surf, border_color, (0, 0, pw, ph), 1)
        self.screen.blit(surf, (px, py))
        unread      = self.ids.get_unread_count()
        header_text = "⬡ IDS ALERTS" + (f"  [{unread} NEW]" if unread > 0 else "")
        self.screen.blit(self.font_md.render(header_text, True, border_color), (px + 10, py + 8))
        pygame.draw.line(self.screen, border_color, (px + 8, py + 26), (px + pw - 8, py + 26), 1)
        for i, alert in enumerate(alerts):
            ay = py + 32 + i * 22
            if ay + 20 > py + ph:
                break
            ts    = time.strftime("%H:%M:%S", time.localtime(alert.timestamp))
            color = alert.color
            if not alert.read:
                bg = pygame.Surface((pw - 4, 20), pygame.SRCALPHA)
                bg.fill((*color, 20))
                self.screen.blit(bg, (px + 2, ay))
            self.screen.blit(self.font_sm.render(f"{alert.icon}", True, color), (px + 8,  ay + 4))
            self.screen.blit(self.font_sm.render(ts, True, tuple(max(0, c - 60) for c in self.colors['text'])), (px + 22, ay + 4))
            self.screen.blit(self.font_sm.render(alert.message[:38], True, color), (px + 80, ay + 4))
        self.ids.mark_all_read()

    # ── History Panel ─────────────────────────────────────────────────────────

    def _draw_history_panel(self):
        if not self._show_history_panel or not self.db:
            return
        devices = self.db.get_all_devices()
        summary = self.db.get_summary()
        alerts  = self.db.get_alert_stats()
        pw  = 560
        ph  = min(60 + len(devices) * 18 + 80, self.h - 80)
        px  = self.w // 2 - pw // 2
        py  = self.h // 2 - ph // 2
        surf = pygame.Surface((pw, ph), pygame.SRCALPHA)
        surf.fill((3, 5, 18, 245))
        pygame.draw.rect(surf, self.colors['node_gateway'], (0, 0, pw, ph), 1)
        self.screen.blit(surf, (px, py))
        c = self.colors
        y = py + 10
        title = self.font_lg.render("◈ HISTORIAL DE RED — SQLite", True, c['node_gateway'])
        self.screen.blit(title, (px + pw // 2 - title.get_width() // 2, y))
        y += 24
        stats_line = (f"Dispositivos: {summary['total_devices']}  "
                      f"Activos: {summary['active_devices']}  "
                      f"Offline: {summary['offline_devices']}  "
                      f"Alertas: {summary['total_alerts']}  "
                      f"Hoy: {alerts['today']}")
        st = self.font_sm.render(stats_line, True, c['node_active'])
        self.screen.blit(st, (px + pw // 2 - st.get_width() // 2, y))
        y += 16
        pygame.draw.line(self.screen, c['node_gateway'], (px + 8, y), (px + pw - 8, y), 1)
        y += 8
        cols = [(8, "IP"), (115, "HOSTNAME"), (220, "VENDOR"),
                (310, "TIPO"), (380, "1ª VEZ"), (460, "VECES"), (500, "ESTADO")]
        for cx, label in cols:
            self.screen.blit(self.font_sm.render(label, True,
                             tuple(max(0, v - 60) for v in c['node_default'])), (px + cx, y))
        y += 14
        pygame.draw.line(self.screen, tuple(max(0, v - 120) for v in c['node_default']),
                         (px + 8, y), (px + pw - 8, y), 1)
        y += 4
        for dev in devices:
            if y + 14 > py + ph - 20:
                break
            status     = dev.get('status', 'active')
            row_color  = c['node_active'] if status == 'active' else (150, 150, 150)
            first_seen = time.strftime("%d/%m %H:%M", time.localtime(dev.get('first_seen', 0)))
            data = [
                (8,   dev.get('ip', '')[:17]),
                (115, dev.get('hostname', 'Unknown')[:13]),
                (220, dev.get('vendor', 'Unknown')[:11]),
                (310, dev.get('device_type', 'unknown')[:9]),
                (380, first_seen),
                (460, str(dev.get('times_seen', 1))),
                (500, status.upper()),
            ]
            for cx, val in data:
                col = (c['node_active'] if status == 'active' else (100, 100, 100)) if cx == 500 else (c['text'] if status == 'active' else (120, 120, 120))
                self.screen.blit(self.font_sm.render(val, True, col), (px + cx, y))
            y += 16
        pygame.draw.line(self.screen, c['node_gateway'], (px + 8, py + ph - 22), (px + pw - 8, py + ph - 22), 1)
        footer = self.font_sm.render("[H] Cerrar  |  DB: logs/nnm_history.db", True,
                                     tuple(max(0, v - 80) for v in c['text']))
        self.screen.blit(footer, (px + pw // 2 - footer.get_width() // 2, py + ph - 16))

    # ── DPI Bubbles ───────────────────────────────────────────────────────────

    def _draw_dpi_bubbles(self):
        if not self.dpi:
            return
        for ip in self.graph.get_nodes():
            activity = self.dpi.get_device_activity(ip, limit=3)
            if not activity:
                continue
            sx, sy   = self._world_to_screen(*self.graph.get_position(ip))
            bubble_w = min(len(activity) * 52 + 8, 170)
            bubble_h = 22
            bx       = int(sx - bubble_w // 2)
            by       = int(sy - 46)
            bsurf    = pygame.Surface((bubble_w, bubble_h), pygame.SRCALPHA)
            bsurf.fill((5, 8, 20, 180))
            pygame.draw.rect(bsurf, (40, 40, 80, 200), (0, 0, bubble_w, bubble_h), 1)
            self.screen.blit(bsurf, (bx, by))
            x_offset = 4
            for act in activity:
                label = f"{act.icon}{act.service[:6]}"
                txt   = self.font_sm.render(label, True, act.color)
                self.screen.blit(txt, (bx + x_offset, by + 5))
                x_offset += txt.get_width() + 6
                if x_offset > bubble_w - 10:
                    break

    # ── Fase 13: Partículas entre nodos ──────────────────────────────────────

    def _spawn_edge_particles(self):
        """
        Crea EdgeParticles en aristas activas según actividad DPI.
        Solo crea ~2 por arista por llamada para no saturar FPS.
        """
        edges  = list(self.graph.get_edges())
        if not edges:
            return

        dpi_active_ips: set = set()
        if self.dpi:
            for ip in self.graph.get_nodes():
                if self.dpi.get_device_activity(ip, limit=1):
                    dpi_active_ips.add(ip)

        # Paleta por tipo de tráfico
        traffic_colors = {
            'HTTPS': (0, 120, 255),
            'HTTP':  (0, 200, 255),
            'DNS':   (0, 255, 180),
            'SSH':   (255, 50,  50),
            'RDP':   (255, 140,  0),
        }
        default_color = self.colors['pulse']

        for (a, b) in edges:
            # Máx 4 partículas por arista para no saturar
            existing = sum(1 for p in self._edge_particles
                           if (p.node_a == a and p.node_b == b)
                           or (p.node_a == b and p.node_b == a))
            if existing >= 4:
                continue

            speed_mult = 2.0 if (a in dpi_active_ips or b in dpi_active_ips) else 1.0

            # Color según actividad DPI del dispositivo
            color = default_color
            if self.dpi:
                for ip in (a, b):
                    acts = self.dpi.get_device_activity(ip, limit=1)
                    if acts:
                        svc = acts[0].service.upper()
                        for key, col in traffic_colors.items():
                            if key in svc:
                                color = col
                                break
                        break

            # Spawn 1-2 partículas
            for _ in range(random.randint(1, 2)):
                self._edge_particles.append(
                    EdgeParticle(a, b, color, speed_mult)
                )
                # Dirección inversa con menor probabilidad
                if random.random() < 0.4:
                    self._edge_particles.append(
                        EdgeParticle(b, a, color, speed_mult * 0.7)
                    )

        # Limitar total para no reventar FPS
        if len(self._edge_particles) > 200:
            self._edge_particles = self._edge_particles[-180:]

    def _draw_edge_particles(self):
        """Dibuja partículas con estela sobre las aristas."""
        to_remove = []
        for i, ep in enumerate(self._edge_particles):
            try:
                pa = self.graph.get_position(ep.node_a)
                pb = self.graph.get_position(ep.node_b)
            except Exception:
                to_remove.append(i)
                continue

            sx1, sy1 = self._world_to_screen(*pa)
            sx2, sy2 = self._world_to_screen(*pb)

            ep.update()
            pos, tail = ep.get_pos_and_tail(sx1, sy1, sx2, sy2)
            px, py = int(pos[0]), int(pos[1])

            # Estela degradada
            for j, (tx, ty) in enumerate(tail):
                tail_alpha = int(ep.alpha * (1 - j / len(tail)) * 0.5)
                if tail_alpha < 8:
                    continue
                tr = max(1, int((ep.size - j * 0.4) * self.zoom * 0.6))
                if tr < 1:
                    continue
                try:
                    s = pygame.Surface((tr * 2 + 2, tr * 2 + 2), pygame.SRCALPHA)
                    pygame.draw.circle(s, (*ep.color, tail_alpha), (tr + 1, tr + 1), tr)
                    self.screen.blit(s, (int(tx) - tr - 1, int(ty) - tr - 1))
                except Exception:
                    pass

            # Núcleo brillante
            r = max(1, int(ep.size * self.zoom * 0.7))
            glow = self._glow_cache.get(ep.color, r * 2, 60)
            self.screen.blit(glow, (px - r * 2 - 2, py - r * 2 - 2))
            core = self._glow_cache.get(ep.color, r, ep.alpha)
            self.screen.blit(core, (px - r - 2, py - r - 2))

        # Limpiar partículas de nodos ya eliminados
        for i in reversed(to_remove):
            self._edge_particles.pop(i)

    # ── Fase 13: Radar de ataques ─────────────────────────────────────────────

    def _add_radar_blip(self, alert):
        """Agrega un blip al radar cuando llega una alerta IDS."""
        # Ángulo basado en hash de IP para que sea determinístico pero variado
        ip_str = getattr(alert, 'ip', '0.0.0.0') or '0.0.0.0'
        try:
            ip_parts = [int(x) for x in ip_str.split('.')]
            angle = (ip_parts[-1] * 137.5 + ip_parts[-2] * 23.7) % 360
        except Exception:
            angle = random.uniform(0, 360)

        angle_rad  = math.radians(angle)
        dist_norm  = random.uniform(0.25, 0.92)
        color      = getattr(alert, 'color', (255, 80, 80))
        label      = getattr(alert, 'message', '')[:18]

        blip        = AttackRadarBlip(angle_rad, dist_norm, color, label)
        blip.born   = self.tick
        self._radar_blips.append(blip)

        # Máx 20 blips simultáneos
        if len(self._radar_blips) > 20:
            self._radar_blips = self._radar_blips[-20:]

    def _draw_attack_radar(self):
        """
        Radar tipo sonar en esquina superior izquierda (debajo del HUD).
        Muestra de dónde vienen las alertas CRITICAL con barrido animado.
        """
        # Solo mostrar si hay IDS activo
        if not self.ids:
            return

        # Posición y tamaño del radar
        cx     = 75
        cy     = self.h - 220   # arriba del minimap
        radius = 60
        radar_rect = pygame.Rect(cx - radius - 4, cy - radius - 4,
                                  (radius + 4) * 2, (radius + 4) * 2)

        # Fondo circular oscuro
        bg = pygame.Surface((radius * 2 + 8, radius * 2 + 8), pygame.SRCALPHA)
        pygame.draw.circle(bg, (0, 20, 10, 200), (radius + 4, radius + 4), radius)
        self.screen.blit(bg, (cx - radius - 4, cy - radius - 4))

        # Anillos concéntricos
        ring_color = (0, 100, 50)
        for ring_r in [radius // 4, radius // 2, radius * 3 // 4, radius]:
            pygame.draw.circle(self.screen, ring_color, (cx, cy), ring_r, 1)

        # Líneas de cuadrícula (cruz)
        pygame.draw.line(self.screen, ring_color,
                         (cx - radius, cy), (cx + radius, cy), 1)
        pygame.draw.line(self.screen, ring_color,
                         (cx, cy - radius), (cx, cy + radius), 1)

        # Borde exterior
        pygame.draw.circle(self.screen, (0, 200, 80), (cx, cy), radius, 1)

        # ── Barrido del radar ────────────────────────────────────────────────
        self._radar_angle = (self._radar_angle + 0.035) % (math.pi * 2)

        # Estela del barrido (arco degradado)
        sweep_surface = pygame.Surface((radius * 2 + 8, radius * 2 + 8), pygame.SRCALPHA)
        sweep_steps   = 30
        for i in range(sweep_steps):
            a      = self._radar_angle - (i / sweep_steps) * (math.pi * 0.6)
            alpha  = int(90 * (1 - i / sweep_steps))
            green  = int(200 * (1 - i / sweep_steps))
            lx     = cx - (radius - 4) + int(math.cos(a) * (radius - 2))
            ly     = cy - (radius - 4) + int(math.sin(a) * (radius - 2))
            if alpha < 5:
                continue
            pygame.draw.line(sweep_surface,
                             (0, green, 0, alpha),
                             (radius - 4 + 4, radius - 4 + 4),
                             (lx + 4, ly + 4), 2)
        self.screen.blit(sweep_surface, (cx - radius + 4 - 4, cy - radius + 4 - 4))

        # Línea de barrido activa
        lx2 = cx + int(math.cos(self._radar_angle) * radius)
        ly2 = cy + int(math.sin(self._radar_angle) * radius)
        pygame.draw.line(self.screen, (0, 255, 80), (cx, cy), (lx2, ly2), 2)

        # ── Blips ────────────────────────────────────────────────────────────
        self._radar_blips = [b for b in self._radar_blips if b.is_alive(self.tick)]
        for blip in self._radar_blips:
            alpha    = blip.get_alpha(self.tick)
            dist_px  = int(blip.dist_norm * (radius - 6))
            bx       = cx + int(math.cos(blip.angle) * dist_px)
            by_      = cy + int(math.sin(blip.angle) * dist_px)

            # Pulso del blip
            pulse_r = 3 + int(2 * abs(math.sin(self.tick * 0.1 + blip.angle)))
            blip_s  = pygame.Surface((pulse_r * 4, pulse_r * 4), pygame.SRCALPHA)
            pygame.draw.circle(blip_s, (*blip.color, alpha // 3),
                               (pulse_r * 2, pulse_r * 2), pulse_r * 2)
            pygame.draw.circle(blip_s, (*blip.color, alpha),
                               (pulse_r * 2, pulse_r * 2), pulse_r)
            self.screen.blit(blip_s, (bx - pulse_r * 2, by_ - pulse_r * 2))

        # Centro (host NNM)
        pygame.draw.circle(self.screen, (0, 255, 80), (cx, cy), 4)
        pygame.draw.circle(self.screen, (255, 255, 255), (cx, cy), 2)

        # Título y contadores
        title_s = self.font_sm.render("RADAR", True, (0, 200, 80))
        self.screen.blit(title_s, (cx - title_s.get_width() // 2, cy - radius - 14))

        counts = self.ids.get_alert_count() if self.ids else {}
        crit   = counts.get('CRITICAL', 0)
        if crit > 0:
            crit_s = self.font_sm.render(f"CRIT:{crit}", True, (255, 60, 60))
            self.screen.blit(crit_s, (cx - crit_s.get_width() // 2, cy + radius + 4))

    # ── Fase 13: Timeline de alertas ──────────────────────────────────────────

    def _add_timeline_event(self, alert):
        """Registra un evento en el timeline al recibir alerta IDS."""
        color    = getattr(alert, 'color',    (180, 180, 180))
        icon     = getattr(alert, 'icon',     '◉')
        label    = getattr(alert, 'message',  '')[:22]
        severity = getattr(alert, 'severity', 'INFO')
        ev       = TimelineEvent(self.tick, color, icon, label, severity)
        self._timeline_events.append(ev)
        if len(self._timeline_events) > self._timeline_max:
            self._timeline_events = self._timeline_events[-self._timeline_max:]

    def _draw_alert_timeline(self):
        """
        Barra horizontal en la parte baja del GUI con historial visual de eventos.
        Muestra íconos coloreados por severidad, con tooltip al hacer hover.
        """
        if not self._timeline_events:
            return

        bar_h   = 28
        bar_y   = self.h - bar_h - 22   # justo encima del hint de teclas
        bar_x   = 200                    # deja espacio al minimap
        bar_w   = self.w - bar_x - 20

        # Fondo
        bg = pygame.Surface((bar_w, bar_h), pygame.SRCALPHA)
        bg.fill((3, 6, 18, 200))
        pygame.draw.rect(bg, (30, 30, 60, 180), (0, 0, bar_w, bar_h), 1)
        self.screen.blit(bg, (bar_x, bar_y))

        # Etiqueta
        lbl = self.font_sm.render("TIMELINE", True, (60, 60, 100))
        self.screen.blit(lbl, (bar_x + 4, bar_y + 8))
        label_w = lbl.get_width() + 10

        # Área de eventos
        slot_w    = 22
        max_slots = max(1, (bar_w - label_w) // slot_w)
        visible   = self._timeline_events[-max_slots:]

        mouse_x, mouse_y = pygame.mouse.get_pos()
        hover_idx         = -1

        for i, ev in enumerate(visible):
            slot_x = bar_x + label_w + i * slot_w
            slot_cx = slot_x + slot_w // 2
            slot_cy = bar_y + bar_h // 2

            # Edad relativa → opacidad
            age_ticks = self.tick - ev.tick
            age_alpha = max(60, 255 - int(age_ticks * 0.15))

            # Color de fondo por severidad
            sev_bg = {
                'CRITICAL': (80, 0,  0,  100),
                'WARN':     (60, 50, 0,  80),
                'INFO':     (0,  20, 40, 60),
            }.get(ev.severity, (10, 10, 30, 50))

            if abs(mouse_x - slot_cx) < slot_w // 2 and bar_y <= mouse_y <= bar_y + bar_h:
                hover_idx = i
                sev_bg = tuple(min(255, v + 40) for v in sev_bg)

            slot_bg = pygame.Surface((slot_w - 2, bar_h - 4), pygame.SRCALPHA)
            slot_bg.fill(sev_bg)
            self.screen.blit(slot_bg, (slot_x + 1, bar_y + 2))

            # Línea vertical de color en la base
            line_color = (*ev.color, age_alpha)
            line_surf  = pygame.Surface((3, bar_h - 8), pygame.SRCALPHA)
            line_surf.fill(line_color)
            self.screen.blit(line_surf, (slot_cx - 1, bar_y + 4))

            # Ícono del evento
            icon_surf = self.font_sm.render(ev.icon, True, ev.color)
            icon_surf.set_alpha(age_alpha)
            self.screen.blit(icon_surf,
                             (slot_cx - icon_surf.get_width() // 2, bar_y + 3))

        # Tooltip del evento hovereado
        if 0 <= hover_idx < len(visible):
            hev    = visible[hover_idx]
            slot_x = bar_x + label_w + hover_idx * slot_w
            tip_w  = max(180, self.font_sm.size(hev.label)[0] + 20)
            tip_h  = 38
            tip_x  = max(0, min(slot_x - tip_w // 2, self.w - tip_w - 4))
            tip_y  = bar_y - tip_h - 4

            tip = pygame.Surface((tip_w, tip_h), pygame.SRCALPHA)
            tip.fill((5, 8, 22, 230))
            pygame.draw.rect(tip, hev.color, (0, 0, tip_w, tip_h), 1)
            self.screen.blit(tip, (tip_x, tip_y))

            age_s   = f"{int((self.tick - hev.tick) / 60)}s ago"
            hdr_txt = self.font_sm.render(f"{hev.icon} {hev.severity}", True, hev.color)
            msg_txt = self.font_sm.render(hev.label, True, self.colors['text'])
            age_txt = self.font_sm.render(age_s, True,
                                           tuple(max(0, c - 80) for c in self.colors['text']))
            self.screen.blit(hdr_txt, (tip_x + 6,  tip_y + 4))
            self.screen.blit(msg_txt, (tip_x + 6,  tip_y + 18))
            self.screen.blit(age_txt, (tip_x + tip_w - age_txt.get_width() - 6, tip_y + 4))

    # ── Events ────────────────────────────────────────────────────────────────

    def _handle_events(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False

            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_q:
                    self.running = False
                elif event.key == pygame.K_r:
                    self.offset_x = 0.0
                    self.offset_y = 0.0
                    self.zoom     = 1.0
                elif event.key == pygame.K_l:
                    self.settings.show_labels = not self.settings.show_labels
                elif event.key == pygame.K_i:
                    self._show_ids_panel = not self._show_ids_panel
                elif event.key == pygame.K_h:
                    self._show_history_panel = not self._show_history_panel
                elif event.key == pygame.K_m:
                    self._show_minimap = not self._show_minimap
                elif event.key == pygame.K_t:
                    self._cycle_theme()
                elif event.key == pygame.K_ESCAPE:
                    self.selected_node = None

            elif event.type == pygame.MOUSEWHEEL:
                factor    = 1.1 if event.y > 0 else 0.9
                self.zoom = max(0.3, min(4.0, self.zoom * factor))

            elif event.type == pygame.MOUSEBUTTONDOWN:
                if event.button == 1:
                    if (self._scan_btn_rect and self.selected_node
                            and self._scan_btn_rect.collidepoint(event.pos)
                            and self._scan_states.get(self.selected_node) != 'scanning'):
                        self._trigger_nmap_scan(self.selected_node)
                    else:
                        node = self._get_node_at(*event.pos)
                        if node:
                            self.selected_node = node
                        else:
                            self._dragging    = True
                            self._drag_start  = event.pos
                            self.selected_node = None
                elif event.button == 3:
                    self.selected_node = None

            elif event.type == pygame.MOUSEBUTTONUP:
                if event.button == 1:
                    self._dragging = False

            elif event.type == pygame.MOUSEMOTION:
                if self._dragging:
                    dx = event.pos[0] - self._drag_start[0]
                    dy = event.pos[1] - self._drag_start[1]
                    self.offset_x    += dx / self.zoom
                    self.offset_y    += dy / self.zoom
                    self._drag_start  = event.pos
                    self._grid_surface = None  # forzar redraw del grid
                self.hovered_node = self._get_node_at(*event.pos)

            elif event.type == pygame.VIDEORESIZE:
                self.w, self.h = event.size
                self.screen = pygame.display.set_mode(
                    (self.w, self.h),
                    pygame.RESIZABLE | pygame.DOUBLEBUF | pygame.HWSURFACE
                )
                self._grid_surface = None

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self):
        while self.running:
            self._handle_events()
            self.tick += 1

            # Background + grid (optimizado)
            self._draw_grid()

            # Partículas (solo cada 2 ticks para FPS)
            if self.tick % 2 == 0:
                for p in self.particles:
                    p.update()
            for p in self.particles:
                r = max(1, int(p.size))
                dot = self._glow_cache.get(p.color, r, p.alpha)
                self.screen.blit(dot, (int(p.x) - r - 2, int(p.y) - r - 2))

            # Edges
            for (a, b) in self.graph.get_edges():
                self._draw_edge(a, b)

            # ── Fase 13: partículas entre nodos ──────────────────────────────
            # Spawn cada 45 ticks para no saturar
            if self.tick % 45 == 0:
                self._spawn_edge_particles()
            self._draw_edge_particles()

            # Pulses — reinit periódico
            if self.tick % 300 == 0:
                self._init_pulses()
            for pulse in self.pulses:
                pulse.update()
                self._draw_pulse(pulse)

            # Spawn effects (animación de entrada)
            alive_effects = []
            for effect in self.spawn_effects:
                effect.update()
                effect.draw(self.screen)
                if effect.alive:
                    alive_effects.append(effect)
            self.spawn_effects = alive_effects

            # Nodes
            for ip in self.graph.get_nodes():
                self._draw_node(ip)

            # Tooltip
            if self.hovered_node and self.hovered_node != self.selected_node:
                self._draw_tooltip(self.hovered_node)

            # HUD y paneles
            self._draw_hud()
            self._draw_selected_panel()
            self._draw_traffic_panel()
            self._draw_ids_alerts()
            self._draw_dpi_bubbles()
            self._draw_ids_panel()
            self._draw_history_panel()
            self._draw_minimap()

            # ── Fase 13: radar de ataques + timeline ─────────────────────────
            self._draw_attack_radar()
            self._draw_alert_timeline()

            pygame.display.flip()
            self.clock.tick(self.settings.fps)

        pygame.quit()
