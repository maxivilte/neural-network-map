"""
ui/renderer.py
Cyberpunk-style interactive renderer using Pygame.
Features:
 - Animated grid background
 - Glowing nodes with type-based colors
 - Animated data pulses on edges
 - Hover tooltips with device info
 - Zoom + pan
 - Particle effects
"""

import pygame
import pygame.gfxdraw
import math
import random
import time
import threading
from typing import List, Tuple, Dict, Optional


# ─── Pulse / Particle dataclasses ───────────────────────────────────────────

class DataPulse:
    """Animated dot traveling along an edge."""
    def __init__(self, start: Tuple[float, float], end: Tuple[float, float], color: Tuple):
        self.start = start
        self.end = end
        self.color = color
        self.progress = random.uniform(0.0, 1.0)
        self.speed = random.uniform(0.003, 0.012)
        self.size = random.randint(3, 6)
        self.alive = True

    def update(self):
        self.progress += self.speed
        if self.progress >= 1.0:
            self.progress = 0.0

    def get_pos(self) -> Tuple[int, int]:
        x = self.start[0] + (self.end[0] - self.start[0]) * self.progress
        y = self.start[1] + (self.end[1] - self.start[1]) * self.progress
        return (int(x), int(y))


class Particle:
    """Background ambient particle."""
    def __init__(self, width, height, color):
        self.x = random.uniform(0, width)
        self.y = random.uniform(0, height)
        self.vx = random.uniform(-0.3, 0.3)
        self.vy = random.uniform(-0.3, 0.3)
        self.size = random.uniform(1, 3)
        self.alpha = random.randint(40, 140)
        self.color = color
        self.width = width
        self.height = height

    def update(self):
        self.x += self.vx
        self.y += self.vy
        self.x %= self.width
        self.y %= self.height


# ─── Main Renderer ───────────────────────────────────────────────────────────

class CyberpunkRenderer:
    DEVICE_ICONS = {
        "router":     "⬡",
        "server":     "▣",
        "phone":      "◈",
        "laptop":     "◧",
        "desktop":    "⬜",
        "printer":    "⊞",
        "iot":        "⊛",
        "smart_tv":   "⬛",
        "raspberry":  "◉",
        "nas":        "⊟",
        "camera":     "◎",
        "unknown":    "◇",
    }

    def __init__(self, graph_engine, traffic_monitor, settings):
        self.graph = graph_engine
        self.traffic = traffic_monitor
        self.settings = settings
        self.colors = settings.colors

        pygame.init()
        pygame.display.set_caption("⬡ NEURAL NETWORK MAP ⬡")
        self.screen = pygame.display.set_mode(
            (settings.window_width, settings.window_height),
            pygame.RESIZABLE | pygame.DOUBLEBUF
        )
        self.clock = pygame.time.Clock()
        self.running = True

        # Camera
        self.offset_x = 0
        self.offset_y = 0
        self.zoom = 1.0
        self._dragging = False
        self._drag_start = (0, 0)

        # State
        self.pulses: List[DataPulse] = []
        self.particles: List[Particle] = []
        self.hovered_node: Optional[str] = None
        self.selected_node: Optional[str] = None
        self.tick = 0
        self.show_info_panel = True

        # Fonts
        try:
            self.font_sm = pygame.font.SysFont("monospace", 11)
            self.font_md = pygame.font.SysFont("monospace", 14, bold=True)
            self.font_lg = pygame.font.SysFont("monospace", 18, bold=True)
            self.font_title = pygame.font.SysFont("monospace", 22, bold=True)
        except Exception:
            self.font_sm = pygame.font.Font(None, 16)
            self.font_md = pygame.font.Font(None, 20)
            self.font_lg = pygame.font.Font(None, 24)
            self.font_title = pygame.font.Font(None, 28)

        # Surfaces
        self.w = settings.window_width
        self.h = settings.window_height
        self._overlay = pygame.Surface((self.w, self.h), pygame.SRCALPHA)

        # Init particles
        for _ in range(80):
            self.particles.append(Particle(self.w, self.h, self.colors['glow']))

        self._init_pulses()

    def _init_pulses(self):
        """Spawn initial pulses on all edges."""
        self.pulses.clear()
        for (a, b) in self.graph.get_edges():
            pa = self.graph.get_position(a)
            pb = self.graph.get_position(b)
            for _ in range(random.randint(1, 3)):
                self.pulses.append(DataPulse(pa, pb, self.colors['pulse']))
                self.pulses.append(DataPulse(pb, pa, self.colors['pulse']))

    def _world_to_screen(self, wx, wy) -> Tuple[int, int]:
        sx = int((wx + self.offset_x) * self.zoom)
        sy = int((wy + self.offset_y) * self.zoom)
        return sx, sy

    def _screen_to_world(self, sx, sy) -> Tuple[float, float]:
        wx = sx / self.zoom - self.offset_x
        wy = sy / self.zoom - self.offset_y
        return wx, wy

    def _draw_grid(self):
        """Animated cyber grid background."""
        grid_color = self.colors['grid']
        spacing = int(50 * self.zoom)
        if spacing < 10:
            return
        offset_x_mod = int(self.offset_x * self.zoom) % spacing
        offset_y_mod = int(self.offset_y * self.zoom) % spacing

        for x in range(-spacing + offset_x_mod, self.w + spacing, spacing):
            alpha = 60 + int(20 * math.sin(self.tick * 0.02 + x * 0.01))
            s = pygame.Surface((1, self.h), pygame.SRCALPHA)
            s.fill((*grid_color, alpha))
            self.screen.blit(s, (x, 0))

        for y in range(-spacing + offset_y_mod, self.h + spacing, spacing):
            alpha = 60 + int(20 * math.sin(self.tick * 0.02 + y * 0.01))
            s = pygame.Surface((self.w, 1), pygame.SRCALPHA)
            s.fill((*grid_color, alpha))
            self.screen.blit(s, (0, y))

    def _draw_edge(self, a: str, b: str):
        """Draw glowing edge between two nodes."""
        pa = self._world_to_screen(*self.graph.get_position(a))
        pb = self._world_to_screen(*self.graph.get_position(b))
        edge_color = self.colors['edge']

        # Draw multiple layers for glow
        for width, alpha in [(6, 15), (3, 40), (1, 120)]:
            s = pygame.Surface((self.w, self.h), pygame.SRCALPHA)
            pygame.draw.line(s, (*edge_color, alpha), pa, pb, width)
            self.screen.blit(s, (0, 0))

    def _draw_pulse(self, pulse: DataPulse):
        """Draw a data pulse dot with glow."""
        world_start = pulse.start
        world_end = pulse.end
        # Convert to screen
        sx1, sy1 = self._world_to_screen(*world_start)
        sx2, sy2 = self._world_to_screen(*world_end)

        # Interpolate in screen space
        px = int(sx1 + (sx2 - sx1) * pulse.progress)
        py = int(sy1 + (sy2 - sy1) * pulse.progress)

        c = pulse.color
        size = max(2, int(pulse.size * self.zoom))

        # Glow layers
        for r, a in [(size * 3, 25), (size * 2, 60), (size, 180)]:
            s = pygame.Surface((r * 2 + 2, r * 2 + 2), pygame.SRCALPHA)
            pygame.draw.circle(s, (*c, a), (r, r), r)
            self.screen.blit(s, (px - r, py - r))

    def _get_node_color(self, ip: str) -> Tuple:
        info = self.graph.get_device_info(ip)
        if info.get('is_gateway'):
            return self.colors['node_gateway']
        dtype = info.get('device_type', 'unknown')
        if dtype in ('server', 'nas', 'raspberry'):
            return self.colors['node_active']
        if dtype == 'unknown':
            return self.colors['node_unknown']
        return self.colors['node_default']

    def _draw_node(self, ip: str):
        """Draw a glowing node with label."""
        wx, wy = self.graph.get_position(ip)
        sx, sy = self._world_to_screen(wx, wy)
        info = self.graph.get_device_info(ip)

        color = self._get_node_color(ip)
        r = int(self.settings.node_radius * self.zoom)
        is_hovered = (ip == self.hovered_node)
        is_selected = (ip == self.selected_node)
        is_gateway = info.get('is_gateway', False)

        # Pulse ring on gateway
        if is_gateway:
            pulse_r = r + int(10 * (0.5 + 0.5 * math.sin(self.tick * 0.05)))
            for pr, pa in [(pulse_r + 8, 20), (pulse_r + 4, 40), (pulse_r, 80)]:
                s = pygame.Surface((pr * 2 + 4, pr * 2 + 4), pygame.SRCALPHA)
                pygame.draw.circle(s, (*color, pa), (pr + 2, pr + 2), pr, 2)
                self.screen.blit(s, (sx - pr - 2, sy - pr - 2))

        # Hover ring
        if is_hovered or is_selected:
            hr = r + 8
            s = pygame.Surface((hr * 2 + 4, hr * 2 + 4), pygame.SRCALPHA)
            pygame.draw.circle(s, (*color, 100), (hr + 2, hr + 2), hr, 3)
            self.screen.blit(s, (sx - hr - 2, sy - hr - 2))

        # Glow layers
        for gr, ga in [(r * 3, 12), (r * 2, 35), (r + 4, 70)]:
            s = pygame.Surface((gr * 2 + 4, gr * 2 + 4), pygame.SRCALPHA)
            pygame.draw.circle(s, (*color, ga), (gr + 2, gr + 2), gr)
            self.screen.blit(s, (sx - gr - 2, sy - gr - 2))

        # Core circle
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
                dt_surf = self.font_sm.render(f"[{dtype}]", True,
                                               tuple(max(0, c - 60) for c in self.colors['text']))
                self.screen.blit(dt_surf, (sx - dt_surf.get_width() // 2, sy + r + 18))

    def _get_node_at(self, sx, sy) -> Optional[str]:
        """Find node near screen position."""
        threshold = self.settings.node_radius * self.zoom * 1.5
        for ip in self.graph.get_nodes():
            wx, wy = self.graph.get_position(ip)
            nsx, nsy = self._world_to_screen(wx, wy)
            dist = math.hypot(sx - nsx, sy - nsy)
            if dist < threshold:
                return ip
        return None

    def _draw_tooltip(self, ip: str):
        """Draw info tooltip for hovered/selected node."""
        info = self.graph.get_device_info(ip)
        lines = [
            f"IP:       {info.get('ip', ip)}",
            f"Hostname: {info.get('hostname', 'Unknown')}",
            f"MAC:      {info.get('mac', '??:??:??:??:??:??')}",
            f"Vendor:   {info.get('vendor', 'Unknown')}",
            f"Type:     {info.get('device_type', 'unknown')}",
            f"Ports:    {info.get('open_ports', [])}",
        ]
        pad = 12
        line_h = 18
        w = max(self.font_sm.size(l)[0] for l in lines) + pad * 2
        h = len(lines) * line_h + pad * 2

        wx, wy = self.graph.get_position(ip)
        sx, sy = self._world_to_screen(wx, wy)
        tx = min(sx + 25, self.w - w - 10)
        ty = min(sy - 10, self.h - h - 10)

        # Background
        surf = pygame.Surface((w, h), pygame.SRCALPHA)
        surf.fill((5, 10, 25, 220))
        pygame.draw.rect(surf, self.colors['node_default'], (0, 0, w, h), 1)
        self.screen.blit(surf, (tx, ty))

        # Header
        header = self.font_md.render(f"◉ {info.get('hostname', ip)}", True, self.colors['node_default'])
        self.screen.blit(header, (tx + pad, ty + 4))

        for i, line in enumerate(lines[1:], 1):
            txt = self.font_sm.render(line, True, self.colors['text'])
            self.screen.blit(txt, (tx + pad, ty + pad + i * line_h - 2))

    def _draw_hud(self):
        """Draw top HUD overlay."""
        title = self.font_title.render("⬡ NEURAL NETWORK MAP", True, self.colors['node_gateway'])
        self.screen.blit(title, (16, 10))

        n_devices = len(self.graph.get_nodes())
        n_edges = len(self.graph.get_edges())
        stats = [
            f"NODES: {n_devices}",
            f"EDGES: {n_edges}",
            f"SUBNET: {self.settings.subnet}",
            f"ZOOM: {self.zoom:.1f}x",
        ]
        for i, s in enumerate(stats):
            surf = self.font_sm.render(s, True, self.colors['text'])
            self.screen.blit(surf, (16, 38 + i * 16))

        # Controls hint bottom left
        hints = "[SCROLL] Zoom  [DRAG] Pan  [CLICK] Select  [R] Reset  [L] Labels  [Q] Quit"
        hint_surf = self.font_sm.render(hints, True, tuple(max(0, c - 80) for c in self.colors['text']))
        self.screen.blit(hint_surf, (16, self.h - 20))

        # Time top right
        ts = time.strftime("%H:%M:%S")
        ts_surf = self.font_md.render(ts, True, self.colors['node_default'])
        self.screen.blit(ts_surf, (self.w - ts_surf.get_width() - 16, 10))

    def _draw_selected_panel(self):
        """Side panel for selected node."""
        if not self.selected_node:
            return
        ip = self.selected_node
        info = self.graph.get_device_info(ip)
        neighbors = self.graph.get_neighbors(ip)

        pw, ph = 260, 320
        px, py = self.w - pw - 10, 40
        surf = pygame.Surface((pw, ph), pygame.SRCALPHA)
        surf.fill((5, 8, 20, 230))
        pygame.draw.rect(surf, self.colors['node_default'], (0, 0, pw, ph), 1)
        self.screen.blit(surf, (px, py))

        c = self.colors
        pad = 10
        y = py + pad
        lines = [
            ("SELECTED NODE", c['node_gateway']),
            (f"  {info.get('hostname', ip)}", c['node_default']),
            ("", c['text']),
            (f"IP      {info.get('ip', ip)}", c['text']),
            (f"MAC     {info.get('mac', '??')}", c['text']),
            (f"Vendor  {info.get('vendor', 'Unknown')}", c['text']),
            (f"Type    {info.get('device_type', 'unknown')}", c['text']),
            (f"Ports   {info.get('open_ports', [])}", c['text']),
            ("", c['text']),
            (f"CONNECTIONS ({len(neighbors)})", c['node_gateway']),
        ] + [(f"  → {n}", c['node_active']) for n in neighbors[:8]]

        for text, color in lines:
            surf2 = self.font_sm.render(text, True, color)
            self.screen.blit(surf2, (px + pad, y))
            y += 17

    def _handle_events(self):
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                self.running = False

            elif event.type == pygame.KEYDOWN:
                if event.key == pygame.K_q:
                    self.running = False
                elif event.key == pygame.K_r:
                    self.offset_x = 0
                    self.offset_y = 0
                    self.zoom = 1.0
                elif event.key == pygame.K_l:
                    self.settings.show_labels = not self.settings.show_labels
                elif event.key == pygame.K_ESCAPE:
                    self.selected_node = None

            elif event.type == pygame.MOUSEWHEEL:
                factor = 1.1 if event.y > 0 else 0.9
                self.zoom = max(0.3, min(4.0, self.zoom * factor))

            elif event.type == pygame.MOUSEBUTTONDOWN:
                if event.button == 1:
                    node = self._get_node_at(*event.pos)
                    if node:
                        self.selected_node = node
                    else:
                        self._dragging = True
                        self._drag_start = event.pos
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
                    self.offset_x += dx / self.zoom
                    self.offset_y += dy / self.zoom
                    self._drag_start = event.pos
                self.hovered_node = self._get_node_at(*event.pos)

            elif event.type == pygame.VIDEORESIZE:
                self.w, self.h = event.size
                self.screen = pygame.display.set_mode((self.w, self.h), pygame.RESIZABLE | pygame.DOUBLEBUF)

    def run(self):
        """Main render loop."""
        while self.running:
            self._handle_events()
            self.tick += 1

            # Background
            self.screen.fill(self.colors['bg'])
            self._draw_grid()

            # Ambient particles
            for p in self.particles:
                p.update()
                r = max(1, int(p.size))
                s = pygame.Surface((r * 2, r * 2), pygame.SRCALPHA)
                pygame.draw.circle(s, (*p.color, p.alpha), (r, r), r)
                self.screen.blit(s, (int(p.x) - r, int(p.y) - r))

            # Edges
            for (a, b) in self.graph.get_edges():
                self._draw_edge(a, b)

            # Update pulse edge positions (world positions may shift)
            if self.tick % 300 == 0:
                self._init_pulses()

            # Pulses
            for pulse in self.pulses:
                pulse.update()
                self._draw_pulse(pulse)

            # Nodes
            for ip in self.graph.get_nodes():
                self._draw_node(ip)

            # Tooltip
            if self.hovered_node and self.hovered_node != self.selected_node:
                self._draw_tooltip(self.hovered_node)

            # HUD
            self._draw_hud()
            self._draw_selected_panel()

            pygame.display.flip()
            self.clock.tick(self.settings.fps)

        pygame.quit()
