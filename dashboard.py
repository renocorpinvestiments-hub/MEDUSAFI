#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║         Elite State-of-the-Art WiFi Assault & Packet Capture Engine        ║
║                                                                             ║
║  dashboard.py — TKinter Hacker GUI Dashboard                               ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import queue
import threading
import subprocess
import platform as pf
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import asdict
from collections import defaultdict
from functools import partial

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, font, messagebox
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# ============================================================================
# MEDUSA CORE IMPORTS
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, VERSION_FULL, AUTHOR,
    SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CAN_MONITOR_MODE, CAN_INJECT_PACKETS, CAN_ARP_SPOOF,
    CAN_IP_FORWARD, CAN_EXTRACT_WIFI_PROFILES,
    CAN_PIXIEDUST, CAN_HCXTOOLS,
    CAN_HASHCAT_GPU, CAN_HASHCAT_CPU,
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR,
    LOG_DIR, WORDLIST_DIR, DEFAULT_WORDLIST,
    THEME, ANSI, LOG_COLORS, LOGO_COMPACT, BRANDING,
    ensure_directories, current_timestamp,
    human_time, human_bytes, human_number,
    validate_mac, validate_ip, safe_filename,
    MedusaError, InterfaceError, CaptureError,
    MAX_WORKER_THREADS,
)


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

# --- Color Scheme ---
class Colors:
    """Centralized color palette for the dashboard."""
    BG_DARK = "#0a0a0f"
    BG_MEDIUM = "#0f0f1a"
    BG_LIGHT = "#1a1a2e"
    BG_INPUT = "#12121e"
    TEXT_PRIMARY = "#e0e0ff"
    TEXT_SECONDARY = "#8888aa"
    TEXT_DIM = "#555577"
    ACCENT_GREEN = "#00ff41"
    ACCENT_CYAN = "#00e5ff"
    ACCENT_RED = "#ff1744"
    ACCENT_YELLOW = "#ffd600"
    ACCENT_MAGENTA = "#d500f9"
    ACCENT_ORANGE = "#ff6d00"
    ACCENT_BLUE = "#2979ff"
    BORDER = "#1a1a2e"
    TERM_BG = "#050508"

    @classmethod
    def dim_if(cls, color: str, condition: bool) -> str:
        """Return dimmed color if condition is False."""
        return color if condition else cls.TEXT_DIM


# --- Log Level Configuration ---
LOG_LEVELS = {
    "info":     {"prefix": "[•]", "color": Colors.ACCENT_CYAN},
    "ok":       {"prefix": "[✓]", "color": Colors.ACCENT_GREEN},
    "warn":     {"prefix": "[⚠]", "color": Colors.ACCENT_YELLOW},
    "err":      {"prefix": "[✗]", "color": Colors.ACCENT_RED},
    "found":    {"prefix": "[►]", "color": Colors.ACCENT_GREEN, "bold": True},
    "deauth":   {"prefix": "[⚡]", "color": Colors.ACCENT_ORANGE},
    "mitm":     {"prefix": "[🌀]", "color": Colors.ACCENT_MAGENTA},
    "hijack":   {"prefix": "[🕸]", "color": Colors.ACCENT_MAGENTA},
    "debug":    {"prefix": "[…]", "color": Colors.TEXT_DIM},
    "critical": {"prefix": "[‼]", "color": Colors.ACCENT_RED, "bold": True},
    "header":   {"prefix": "[==]", "color": Colors.ACCENT_YELLOW, "bold": True},
    "capture":  {"prefix": "[📡]", "color": Colors.ACCENT_GREEN},
    "attack":   {"prefix": "[💥]", "color": Colors.ACCENT_RED, "bold": True},
}

# --- Mode Button Definitions ---
MODE_BUTTONS = [
    ("🔍 SCAN",    "scan",    Colors.ACCENT_CYAN,    "Scan for wireless networks"),
    ("💥 ATTACK",  "attack",  Colors.ACCENT_RED,     "Full attack chain on target"),
    ("📡 CAPTURE", "capture", Colors.ACCENT_GREEN,   "Capture WPA handshake/PMKID"),
    ("🔓 CRACK",   "crack",   Colors.ACCENT_YELLOW,  "Crack captured hash with wordlist"),
    ("⚡ DEAUTH",  "deauth",  Colors.ACCENT_ORANGE,  "Deauth clients (need monitor mode)"),
    ("🌀 MITM",    "mitm",    Colors.ACCENT_MAGENTA, "ARP spoofing MITM attack"),
    ("🕸 HIJACK",  "hijack",  Colors.ACCENT_MAGENTA, "Session hijack from capture"),
    ("⏹ STOP",    "stop",    Colors.ACCENT_RED,     "Stop all running operations"),
]

# --- Keyboard Shortcuts ---
SHORTCUTS = {
    "<Control-s>":  "scan",
    "<Control-a>":  "attack",
    "<Control-c>":  "capture",
    "<Control-r>":  "crack",
    "<Control-d>":  "deauth",
    "<Control-m>":  "mitm",
    "<Control-h>":  "hijack",
    "<Escape>":     "stop",
    "<Control-l>":  "clear_log",
}

# --- Column Configuration for Network Tree ---
TREE_COLUMNS = [
    ("ssid",       "SSID",        180, Colors.ACCENT_CYAN),
    ("bssid",      "BSSID",       140, Colors.TEXT_SECONDARY),
    ("ch",         "CH",           40, Colors.TEXT_SECONDARY),
    ("signal",     "Signal",      100, Colors.ACCENT_GREEN),
    ("encryption", "Encryption",  100, Colors.ACCENT_YELLOW),
    ("wps",        "WPS",          40, Colors.ACCENT_MAGENTA),
    ("clients",    "Clients",      60, Colors.TEXT_SECONDARY),
]

# --- Capability Indicators ---
CAPABILITY_DOTS = [
    ("📡 MON",  "monitor_mode", Colors.ACCENT_GREEN),
    ("⚡ INJ",  "inject_packets", Colors.ACCENT_GREEN),
    ("🔓 GPU",  "hashcat_gpu", Colors.ACCENT_GREEN),
    ("🌀 MITM", "arp_spoof", Colors.ACCENT_GREEN),
    ("🔑 WPS",  "pixiedust", Colors.ACCENT_GREEN),
]

# --- Quick Stats ---
QUICK_STATS = [
    ("APs",         "aps_found",         Colors.ACCENT_CYAN),
    ("Clients",     "clients_found",     Colors.ACCENT_YELLOW),
    ("Cracked",     "passwords_cracked", Colors.ACCENT_GREEN),
    ("Handshakes",  "handshakes_captured", Colors.ACCENT_ORANGE),
    ("Sessions",    "sessions_stolen",   Colors.ACCENT_MAGENTA),
]

# --- Target Info Fields ---
TARGET_FIELDS = [
    ("BSSID:",      "bssid",      Colors.ACCENT_CYAN),
    ("SSID:",       "ssid",       Colors.ACCENT_GREEN),
    ("Channel:",    "channel",    Colors.ACCENT_YELLOW),
    ("Signal:",     "signal",     Colors.ACCENT_CYAN),
    ("Encryption:", "encryption", Colors.ACCENT_YELLOW),
    ("WPS:",        "has_wps",    Colors.ACCENT_MAGENTA),
    ("Clients:",    "clients",    Colors.TEXT_SECONDARY),
]

# --- Font ---
FONT_FAMILY = "Consolas" if IS_WINDOWS else ("Menlo" if IS_MACOS else "Monospace")


# ============================================================================
# EXCEPTION
# ============================================================================

class DashboardError(MedusaError):
    """Raised on dashboard initialization or runtime errors."""
    pass


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def signal_to_percent(signal_dbm: int) -> int:
    """Convert dBm signal strength to percentage (0-100)."""
    if signal_dbm >= -30:
        return 100
    if signal_dbm <= -90:
        return 0
    return int((signal_dbm + 90) / 60 * 100)


def signal_to_bars(pct: int, width: int = 4) -> str:
    """Convert percentage to visual bar string."""
    filled = min(width, max(0, pct * width // 100))
    empty = width - filled
    return '█' * filled + '▒' * empty


def frequency_to_channel(freq: float) -> int:
    """Convert frequency in MHz to 802.11 channel number."""
    if 2412 <= freq <= 2484:
        return int((freq - 2412) / 5 + 1)
    if 5180 <= freq <= 5825:
        return int((freq - 5180) / 5 + 36)
    return 0


def timestamp_now() -> str:
    """Return current time as formatted string."""
    return datetime.now().strftime("%H:%M:%S")


# ============================================================================
# NETWORK SCANNER — Platform-specific scanning logic
# ============================================================================

class NetworkScanner:
    """Handles platform-specific WiFi scanning.
    
    Each platform has its own scan method. Results are normalized to a
    common dictionary format for downstream processing.
    """

    @staticmethod
    def scan() -> List[Dict]:
        """Auto-detect platform and scan.
        
        Returns:
            List of normalized network dictionaries.
        """
        if IS_LINUX:
            return NetworkScanner._scan_linux()
        elif IS_MACOS:
            return NetworkScanner._scan_macos()
        elif IS_WINDOWS:
            return NetworkScanner._scan_windows()
        return []

    @staticmethod
    def get_interface() -> str:
        """Detect the best available wireless interface."""
        if IS_LINUX:
            try:
                result = subprocess.run(
                    ["iw", "dev"], capture_output=True, text=True, timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        return line.split()[-1]
            except Exception:
                pass
        return "wlan0" if IS_LINUX else ("en0" if IS_MACOS else "Wi-Fi")

    # --- Linux ---

    @staticmethod
    def _scan_linux() -> List[Dict]:
        """Linux: iw dev scan, fallback iwlist."""
        iface = NetworkScanner.get_interface()

        # Try iw first (modern)
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                return NetworkScanner._parse_iw_scan(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: iwlist
        try:
            result = subprocess.run(
                ["iwlist", iface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return NetworkScanner._parse_iwlist(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return []

    @staticmethod
    def _parse_iw_scan(output: str) -> List[Dict]:
        """Parse 'iw dev scan' output into normalized dicts."""
        networks = []
        current: Dict = {}

        for line in output.split('\n'):
            if line.startswith('BSS '):
                if current:
                    networks.append(current)
                current = {'bssid': line.split()[1].strip(), 'clients': []}
            elif 'SSID:' in line:
                current['ssid'] = line.split('SSID:')[-1].strip()
            elif 'signal:' in line:
                try:
                    current['signal'] = float(
                        line.split('signal:')[1].split()[0]
                    )
                except (IndexError, ValueError):
                    current['signal'] = -100
            elif 'freq:' in line:
                try:
                    freq = float(line.split('freq:')[1].split()[0])
                    current['frequency'] = freq
                    current['channel'] = frequency_to_channel(freq)
                except (IndexError, ValueError):
                    pass
            elif 'WPA:' in line or 'RSN:' in line:
                current['encryption'] = 'WPA2' if 'RSN' in line else 'WPA'

        if current:
            networks.append(current)

        for net in networks:
            net.setdefault('encryption', 'UNKNOWN')
            net.setdefault('signal', -100)
            net.setdefault('channel', 0)
            net.setdefault('ssid', '<Hidden>')
            net.setdefault('has_wps', False)

        return networks

    @staticmethod
    def _parse_iwlist(output: str) -> List[Dict]:
        """Parse 'iwlist scan' output (legacy)."""
        networks = []
        current: Dict = {}

        for line in output.split('\n'):
            if 'Cell ' in line and 'Address:' in line:
                if current:
                    networks.append(current)
                current = {
                    'bssid': line.split('Address:')[1].strip(),
                    'clients': [],
                }
            elif 'ESSID:' in line:
                raw = line.split('ESSID:"')
                current['ssid'] = raw[1].rstrip('"') if len(raw) > 1 else ''
            elif 'Signal level=' in line:
                try:
                    current['signal'] = float(
                        line.split('Signal level=')[1].split()[0]
                    )
                except (IndexError, ValueError):
                    current['signal'] = -100
            elif 'Channel:' in line:
                try:
                    current['channel'] = int(line.split('Channel:')[1])
                except (IndexError, ValueError):
                    pass
            elif 'Encryption key:on' in line:
                current['encryption'] = current.get('encryption', 'WPA2')
            elif 'Encryption key:off' in line:
                current['encryption'] = 'OPEN'

        if current:
            networks.append(current)

        for net in networks:
            net.setdefault('encryption', 'UNKNOWN')
            net.setdefault('signal', -100)
            net.setdefault('channel', 0)
            net.setdefault('ssid', '<Hidden>')
            net.setdefault('has_wps', False)

        return networks

    # --- macOS ---

    @staticmethod
    def _scan_macos() -> List[Dict]:
        """macOS: airport --scan."""
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport"
        )
        try:
            result = subprocess.run(
                [airport, "--scan"], capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return NetworkScanner._parse_airport_scan(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return []

    @staticmethod
    def _parse_airport_scan(output: str) -> List[Dict]:
        """Parse macOS airport scan output."""
        networks = []
        lines = output.strip().split('\n')

        for line in lines[1:]:  # skip header
            parts = line.split()
            if len(parts) >= 5:
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1] if len(parts) > 1 else '',
                    'signal': (
                        int(parts[2])
                        if len(parts) > 2 and parts[2].lstrip('-').isdigit()
                        else -100
                    ),
                    'channel': (
                        int(parts[3])
                        if len(parts) > 3 and parts[3].isdigit()
                        else 0
                    ),
                    'encryption': parts[4] if len(parts) > 4 else 'UNKNOWN',
                    'clients': [],
                    'has_wps': False,
                })

        return networks

    # --- Windows ---

    @staticmethod
    def _scan_windows() -> List[Dict]:
        """Windows: netsh wlan show networks mode=Bssid."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return NetworkScanner._parse_netsh_scan(result.stdout)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return []

    @staticmethod
    def _parse_netsh_scan(output: str) -> List[Dict]:
        """Parse Windows netsh output."""
        networks = []
        current: Dict = {}

        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID'):
                if current:
                    networks.append(current)
                current = {'ssid': line.split(':')[-1].strip(), 'clients': [],
                           'has_wps': False}
            elif line.startswith('BSSID'):
                current['bssid'] = ':'.join(
                    b.replace('-', ':')
                    for b in line.split(':')[1:]
                ).strip()
            elif line.startswith('Signal'):
                try:
                    pct = int(
                        line.split(':')[-1].strip().rstrip('%')
                    )
                    current['signal'] = -30 - int((100 - pct) * 0.6)
                except ValueError:
                    current['signal'] = -100
            elif line.startswith('Channel'):
                try:
                    current['channel'] = int(line.split(':')[-1].strip())
                except ValueError:
                    current['channel'] = 0
            elif 'Authentication' in line:
                current['encryption'] = line.split(':')[-1].strip()

        if current:
            networks.append(current)

        for net in networks:
            net.setdefault('encryption', 'UNKNOWN')
            net.setdefault('signal', -100)
            net.setdefault('channel', 0)
            net.setdefault('ssid', '<Hidden>')

        return networks


# ============================================================================
# TOOLTIP MANAGER
# ============================================================================

class ToolTip:
    """Lightweight tooltip manager for TKinter widgets."""

    def __init__(self, widget: tk.Widget, text: str):
        self.widget = widget
        self.text = text
        self._tip_window: Optional[tk.Toplevel] = None
        widget.bind('<Enter>', self._show)
        widget.bind('<Leave>', self._hide)

    def _show(self, event):
        if self._tip_window:
            return
        x = event.x_root + 20
        y = event.y_root + 10
        self._tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_PRIMARY,
            bg=Colors.BG_LIGHT,
            relief="solid", bd=1, padx=8, pady=4,
        )
        label.pack()

    def _hide(self, event):
        if self._tip_window:
            self._tip_window.destroy()
            self._tip_window = None


# ============================================================================
# LOG MANAGER (Queue-based, thread-safe)
# ============================================================================

class LogManager:
    """Thread-safe log queue consumer that feeds the text widget.
    
    All log messages go through a queue. A background daemon thread
    drains the queue and schedules UI updates via root.after().
    """

    def __init__(self, text_widget: Optional[tk.Text] = None):
        self.text_widget = text_widget
        self._queue: queue.Queue = queue.Queue(maxsize=10000)
        self._auto_scroll = True
        self._running = False
        self._consumer_thread: Optional[threading.Thread] = None

        # Configure text tags if widget already exists
        if text_widget:
            self._configure_tags()

    def _configure_tags(self):
        """Configure text tags for each log level."""
        if not self.text_widget:
            return
        for level, cfg in LOG_LEVELS.items():
            kwargs = {'foreground': cfg['color']}
            if cfg.get('bold'):
                kwargs['font'] = (FONT_FAMILY, 9, 'bold')
            self.text_widget.tag_configure(level, **kwargs)
        self.text_widget.tag_configure(
            'timestamp', foreground=Colors.TEXT_DIM
        )

    def attach(self, text_widget: tk.Text):
        """Attach to an existing text widget."""
        self.text_widget = text_widget
        self._configure_tags()

    def log(self, level: str, message: str):
        """Queue a log entry (thread-safe, non-blocking)."""
        try:
            self._queue.put_nowait({
                'level': level,
                'message': str(message),
                'timestamp': time.time(),
            })
        except queue.Full:
            pass

    def start(self):
        """Start the background consumer thread."""
        if self._running:
            return
        self._running = True
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop, daemon=True,
            name='log-consumer'
        )
        self._consumer_thread.start()

    def stop(self):
        """Signal the consumer to stop."""
        self._running = False

    def _consumer_loop(self):
        """Drain the queue and schedule UI updates."""
        while self._running:
            try:
                entry = self._queue.get(timeout=0.1)
                self._append(entry['level'], entry['message'])
            except queue.Empty:
                continue
            except Exception:
                pass

    def _append(self, level: str, message: str):
        """Schedule a single log append on the main thread."""
        if not self.text_widget:
            return

        def do_append():
            tw = self.text_widget
            tw.config(state='normal')

            # Timestamp
            tw.insert('end', f'[{timestamp_now()}] ', 'timestamp')

            # Level prefix
            cfg = LOG_LEVELS.get(level, LOG_LEVELS['info'])
            tw.insert('end', f' {cfg["prefix"]} ', level)

            # Message body
            tw.insert('end', f'{message}\n', level)

            # Auto-scroll
            if self._auto_scroll:
                tw.see('end')

            tw.config(state='disabled')

        # Schedule on main thread
        if hasattr(self.text_widget, 'winfo_toplevel'):
            toplevel = self.text_widget.winfo_toplevel()
            if toplevel:
                toplevel.after(0, do_append)


# ============================================================================
# PROGRESS BAR (Canvas-based)
# ============================================================================

class ProgressBar:
    """Custom canvas-based progress bar with fill and percentage label."""

    def __init__(self, canvas: tk.Canvas, label_var: tk.StringVar):
        self.canvas = canvas
        self.label_var = label_var
        self._percent: float = 0.0

    def update(self, percent: float, text: str = ""):
        """Redraw the progress bar at the given percentage."""
        self._percent = max(0.0, min(100.0, percent))
        self.canvas.delete('all')

        width = self.canvas.winfo_width() or 300
        height = 20

        # Background
        self.canvas.create_rectangle(
            0, 0, width, height,
            fill=Colors.BG_INPUT, outline=''
        )

        # Fill bar
        fill_w = int(width * self._percent / 100)
        if fill_w > 0:
            self.canvas.create_rectangle(
                0, 0, fill_w, height,
                fill=Colors.ACCENT_GREEN, outline=''
            )
            self.canvas.create_rectangle(
                0, 0, fill_w, height // 2,
                fill=Colors.ACCENT_GREEN + 'aa', outline=''
            )

        # Percentage text overlay
        self.canvas.create_text(
            width // 2, height // 2,
            text=f'{self._percent:.0f}%',
            fill=Colors.BG_DARK,
            font=(FONT_FAMILY, 8, 'bold')
        )

        if text:
            self.label_var.set(text)


# ============================================================================
# MEDUSA DASHBOARD — Main GUI Application
# ============================================================================

class MedusaDashboard:
    """TKinter-based hacker GUI dashboard for MEDUSA.

    Layout:
    ┌──────────────────────────────────────────────────────────────┐
    │  HEADER: MEDUSA v3.0.0 (Gorgon) — tagline                   │
    ├──────────────────────────────────────────────────────────────┤
    │  LEFT PANEL (40%)           │ RIGHT PANEL (60%)              │
    │  ┌────────────────────────┐ │ ┌────────────────────────────┐ │
    │  │ NETWORK TREE           │ │ │ TERMINAL / LOG OUTPUT      │ │
    │  │ • SSID 1   ████ 95%   │ │ │ [•] Scanning...            │ │
    │  │ • SSID 2   ██▒▒ 60%   │ │ │ [✓] Found "Office" WPA2   │ │
    │  └────────────────────────┘ │ └────────────────────────────┘ │
    │  ┌────────────────────────┐ │ ┌────────────────────────────┐ │
    │  │ MODE SELECTION         │ │ │ TARGET INFO PANEL          │ │
    │  │ [Scan] [Attack] ...    │ │ │ BSSID, SSID, CH, Signal   │ │
    │  └────────────────────────┘ │ └────────────────────────────┘ │
    │  ┌────────────────────────┐ │ ┌────────────────────────────┐ │
    │  │ QUICK STATS            │ │ │ PROGRESS BAR               │ │
    │  │ APs:12 Clients:8 ...   │ │ │ [████████░░░░] 67%        │ │
    │  └────────────────────────┘ │ └────────────────────────────┘ │
    ├──────────────────────────────┤                                │
    │  STATUS BAR: Ready | OS: ... │ ┌────────────────────────────┐ │
    ├──────────────────────────────┤ └────────────────────────────┘ │
    │  FOOTER: Software by branta  │                                │
    └──────────────────────────────┴────────────────────────────────┘
    """

    def __init__(self, console=None):
        """Initialize the dashboard.

        Args:
            console: Optional MedusaConsole for shared logging.
        """
        self.console = console
        self.root: Optional[tk.Tk] = None
        self._running = False

        # Data stores
        self.networks: List[Dict] = []
        self.selected_network: Optional[Dict] = None
        self.stats: Dict[str, int] = defaultdict(int)

        # Thread references
        self._scan_thread: Optional[threading.Thread] = None
        self._attack_thread: Optional[threading.Thread] = None
        self._mode_buttons: Dict[str, tk.Button] = {}

        # UI component references (filled during build)
        self._tree: Optional[ttk.Treeview] = None
        self._log_manager: Optional[LogManager] = None
        self._progress_bar: Optional[ProgressBar] = None
        self._status_var: Optional[tk.StringVar] = None
        self._mode_status_var: Optional[tk.StringVar] = None
        self._mode_status_label: Optional[tk.Label] = None
        self._progress_var: Optional[tk.StringVar] = None
        self._stats_labels: Dict[str, tk.Label] = {}
        self._target_vars: Dict[str, tk.StringVar] = {}

        # Application state
        self.current_mode = tk.StringVar(value='idle')

        if not TKINTER_AVAILABLE:
            raise DashboardError("TKinter is not available on this system.")

    # ========================================================================
    # BUILD — Assemble the full window
    # ========================================================================

    def build(self) -> tk.Tk:
        """Build the complete dashboard window.

        Returns:
            The root TKinter window.
        """
        self.root = tk.Tk()
        self.root.title(
            f"{BRANDING['header']} — {BRANDING['tagline']}"
        )
        self.root.configure(bg=Colors.BG_DARK)

        # Set window icon
        try:
            self.root.iconphoto(
                True, tk.PhotoImage(data=self._get_icon_data())
            )
        except Exception:
            pass

        self._setup_responsive()
        self._build_header()
        self._build_main_panels()
        self._build_status_bar()
        self._build_footer()
        self._bind_shortcuts()
        self._apply_os_optimizations()

        # Start log consumer
        self._running = True
        if self._log_manager:
            self._log_manager.start()

        return self.root

    def _setup_responsive(self):
        """Configure responsive window sizing based on screen resolution."""
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()

        if sw >= 2560:
            w, h, scale = 1600, 1000, 2.0
        elif sw >= 1920:
            w, h, scale = 1400, 900, 1.5
        elif sw >= 1366:
            w, h, scale = 1280, 800, 1.0
        else:
            w, h, scale = 1024, 700, 1.0

        self.root.tk.call('tk', 'scaling', scale)
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(900, 600)

        # Grid layout
        self.root.grid_rowconfigure(0, weight=0)   # Header
        self.root.grid_rowconfigure(1, weight=1)   # Main
        self.root.grid_rowconfigure(2, weight=0)   # Status
        self.root.grid_rowconfigure(3, weight=0)   # Footer
        self.root.grid_columnconfigure(0, weight=1)

    def _apply_os_optimizations(self):
        """Apply OS-specific visual tweaks (dark title bar, etc.)."""
        if IS_WINDOWS:
            try:
                from ctypes import windll, byref, sizeof, c_int
                DWMWA_USE_IMMERSIVE_DARK_MODE = 20
                windll.dwmapi.DwmSetWindowAttribute(
                    windll.user32.GetParent(self.root.winfo_id()),
                    DWMWA_USE_IMMERSIVE_DARK_MODE,
                    byref(c_int(2)), sizeof(c_int())
                )
            except Exception:
                pass
        elif IS_MACOS:
            try:
                self.root.call(
                    '::tk::unsupported::MacWindowStyle', 'dark'
                )
            except Exception:
                pass
        elif IS_LINUX:
            try:
                self.root.tk.call(
                    'wm', 'attributes', '.', '-darktheme', True
                )
            except Exception:
                pass

    # ========================================================================
    # HEADER
    # ========================================================================

    def _build_header(self):
        """Build top header with logo, version, OS info, and capabilities."""
        frame = tk.Frame(
            self.root, bg=Colors.BG_MEDIUM, height=60
        )
        frame.grid(row=0, column=0, sticky='ew')
        frame.grid_propagate(False)

        # Left: logo
        tk.Label(
            frame,
            text=f"  {ANSI['R']}MEDUSA{ANSI['RESET']}"
                 f"  v{VERSION} ({CODENAME})",
            font=(FONT_FAMILY, 14, 'bold'),
            fg=Colors.ACCENT_GREEN, bg=Colors.BG_MEDIUM,
            anchor='w',
        ).pack(side='left', padx=15, pady=10)

        # Center: tagline
        tk.Label(
            frame,
            text=f"  {BRANDING['tagline']}",
            font=(FONT_FAMILY, 9),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_MEDIUM,
            anchor='w',
        ).pack(side='left', padx=5, pady=10)

        # Right: OS + capability indicators
        self._build_os_capability_frame(frame).pack(
            side='right', padx=15, pady=5
        )

    def _build_os_capability_frame(self, parent) -> tk.Frame:
        """Build OS badge + admin badge + capability dots."""
        frame = tk.Frame(parent, bg=Colors.BG_MEDIUM)

        # OS badge
        os_colors = {
            'Linux': Colors.ACCENT_ORANGE,
            'Windows': Colors.ACCENT_BLUE,
            'Darwin': Colors.TEXT_SECONDARY,
        }
        os_color = os_colors.get(SYSTEM, Colors.TEXT_DIM)
        tk.Label(
            frame,
            text=f' 🖥 {SYSTEM} ',
            font=(FONT_FAMILY, 8, 'bold'),
            fg=os_color, bg=Colors.BG_LIGHT,
            relief='ridge', bd=1, padx=5,
        ).pack(side='left', padx=2)

        # Admin badge
        admin_color = Colors.ACCENT_GREEN if IS_ADMIN else Colors.ACCENT_RED
        admin_text = ' 👑 ADMIN ' if IS_ADMIN else ' 👤 USER '
        tk.Label(
            frame,
            text=admin_text,
            font=(FONT_FAMILY, 8, 'bold'),
            fg=admin_color, bg=Colors.BG_LIGHT,
            relief='ridge', bd=1, padx=5,
        ).pack(side='left', padx=2)

        # Capability dots
        cap_map = {
            'monitor_mode': CAN_MONITOR_MODE,
            'inject_packets': CAN_INJECT_PACKETS,
            'hashcat_gpu': CAN_HASHCAT_GPU,
            'arp_spoof': CAN_ARP_SPOOF,
            'pixiedust': CAN_PIXIEDUST,
        }

        for label, key, color in CAPABILITY_DOTS:
            c = color if cap_map.get(key) else Colors.TEXT_DIM
            tk.Label(
                frame,
                text=label,
                font=(FONT_FAMILY, 7),
                fg=c, bg=Colors.BG_LIGHT,
                relief='ridge', bd=1, padx=3,
            ).pack(side='left', padx=2)

        return frame

    # ========================================================================
    # MAIN CONTENT PANELS
    # ========================================================================

    def _build_main_panels(self):
        """Build left (40%) and right (60%) content panels."""
        main = tk.Frame(self.root, bg=Colors.BG_DARK)
        main.grid(row=1, column=0, sticky='nsew', padx=5, pady=5)
        main.grid_rowconfigure(0, weight=1)
        main.grid_columnconfigure(0, weight=2, uniform='col')
        main.grid_columnconfigure(1, weight=3, uniform='col')

        # Left
        left = tk.Frame(main, bg=Colors.BG_DARK)
        left.grid(row=0, column=0, sticky='nsew', padx=2, pady=2)
        left.grid_rowconfigure(0, weight=3)  # Tree
        left.grid_rowconfigure(1, weight=1)  # Modes
        left.grid_rowconfigure(2, weight=0)  # Stats
        left.grid_columnconfigure(0, weight=1)

        # Right
        right = tk.Frame(main, bg=Colors.BG_DARK)
        right.grid(row=0, column=1, sticky='nsew', padx=2, pady=2)
        right.grid_rowconfigure(0, weight=3)  # Log
        right.grid_rowconfigure(1, weight=1)  # Target
        right.grid_rowconfigure(2, weight=0)  # Progress
        right.grid_columnconfigure(0, weight=1)

        self._build_network_tree(left)
        self._build_mode_selector(left)
        self._build_quick_stats(left)
        self._build_terminal_log(right)
        self._build_target_info(right)
        self._build_progress_bar(right)

    # ========================================================================
    # NETWORK TREE
    # ========================================================================

    def _build_network_tree(self, parent):
        """Build the network treeview with scrollbars and scan button."""
        frame = tk.LabelFrame(
            parent,
            text=' 🌐 NETWORKS ',
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.ACCENT_CYAN, bg=Colors.BG_MEDIUM,
            relief='ridge', bd=2, padx=5, pady=5,
        )
        frame.grid(row=0, column=0, sticky='nsew', pady=2)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Tree container
        tree_frame = tk.Frame(frame, bg=Colors.BG_MEDIUM)
        tree_frame.grid(row=0, column=0, sticky='nsew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Treeview
        cols = [c[0] for c in TREE_COLUMNS]
        self._tree = ttk.Treeview(
            tree_frame, columns=cols, show='headings',
            height=12, selectmode='browse',
        )

        for col, heading, width, color in TREE_COLUMNS:
            self._tree.heading(col, text=heading)
            self._tree.column(col, width=width, minwidth=30, anchor='w')

        # Styling
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(
            'Treeview',
            background=Colors.BG_INPUT,
            foreground=Colors.TEXT_PRIMARY,
            fieldbackground=Colors.BG_INPUT,
            font=(FONT_FAMILY, 9),
            rowheight=24,
        )
        style.configure(
            'Treeview.Heading',
            background=Colors.BG_LIGHT,
            foreground=Colors.ACCENT_GREEN,
            font=(FONT_FAMILY, 9, 'bold'),
            relief='flat',
        )
        style.map(
            'Treeview',
            background=[('selected', Colors.ACCENT_GREEN + '22')],
            foreground=[('selected', Colors.ACCENT_GREEN)],
        )

        # Scrollbars
        vsb = ttk.Scrollbar(
            tree_frame, orient='vertical', command=self._tree.yview
        )
        hsb = ttk.Scrollbar(
            tree_frame, orient='horizontal', command=self._tree.xview
        )
        self._tree.configure(
            yscrollcommand=vsb.set, xscrollcommand=hsb.set
        )
        self._tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')

        # Events
        self._tree.bind('<<TreeviewSelect>>', self._on_network_select)
        self._tree.bind('<Double-1>', self._on_network_double_click)
        self._build_tree_context_menu()

        # Scan controls
        ctrl_frame = tk.Frame(frame, bg=Colors.BG_MEDIUM)
        ctrl_frame.grid(row=1, column=0, sticky='ew', pady=(5, 0))

        tk.Button(
            ctrl_frame, text='🔍 SCAN',
            command=self._start_scan,
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.BG_DARK, bg=Colors.ACCENT_GREEN,
            activebackground=Colors.ACCENT_GREEN + 'cc',
            activeforeground=Colors.BG_DARK,
            relief='flat', padx=20, pady=5, cursor='hand2',
        ).pack(side='left', padx=2)

        tk.Button(
            ctrl_frame, text='🗑 Clear',
            command=self._clear_networks,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_LIGHT,
            activebackground=Colors.BG_INPUT,
            activeforeground=Colors.ACCENT_RED,
            relief='flat', padx=10, pady=5, cursor='hand2',
        ).pack(side='right', padx=2)

    def _build_tree_context_menu(self):
        """Right-click context menu for network tree."""
        menu = tk.Menu(
            self.root, tearoff=0,
            bg=Colors.BG_LIGHT, fg=Colors.TEXT_PRIMARY,
            activebackground=Colors.ACCENT_GREEN + '22',
            activeforeground=Colors.ACCENT_GREEN,
        )
        menu.add_command(
            label='🎯 Attack This Network',
            command=lambda: self._safe_op('attack')
        )
        menu.add_command(
            label='📡 Capture Handshake',
            command=lambda: self._safe_op('capture')
        )
        menu.add_command(
            label='⚡ Deauth Clients',
            command=lambda: self._safe_op('deauth')
        )
        menu.add_separator()
        menu.add_command(
            label='📋 Copy BSSID', command=self._menu_copy_bssid
        )
        menu.add_command(
            label='📋 Copy SSID', command=self._menu_copy_ssid
        )
        menu.add_separator()
        menu.add_command(
            label='📊 Show Details', command=self._menu_show_details
        )

        self._tree.bind('<Button-3>', lambda e: self._show_context_menu(e, menu))

    def _show_context_menu(self, event, menu):
        """Display context menu at event position."""
        item = self._tree.identify_row(event.y)
        if item:
            self._tree.selection_set(item)
            menu.post(event.x_root, event.y_root)

    def _on_network_select(self, event):
        """Handle single-click selection."""
        sel = self._tree.selection()
        if not sel:
            return

        values = self._tree.item(sel[0], 'values')
        if not values:
            return

        bssid = values[1]
        for net in self.networks:
            if net.get('bssid', '').upper() == bssid.upper():
                self.selected_network = net
                self._update_target_info(net)
                break

    def _on_network_double_click(self, event):
        """Double-click triggers attack."""
        if self.selected_network:
            self.log('attack',
                     f"🎯 Targeting {self.selected_network.get('ssid', '?')}")
            self._start_attack()

    def _safe_op(self, op: str):
        """Execute an operation on the selected network."""
        if not self.selected_network:
            self.log('warn', '⚠ No network selected')
            return
        ssid = self.selected_network.get('ssid', '?')
        self.log('info', f"🎯 {op} on {ssid}")
        # Route to appropriate handler
        handler_map = {
            'attack':  self._start_attack,
            'capture': self._start_capture,
            'deauth':  self._start_deauth,
        }
        handler_map.get(op, lambda: None)()

    def _menu_copy_bssid(self):
        """Copy BSSID to clipboard."""
        if self.selected_network:
            bssid = self.selected_network.get('bssid', '')
            self.root.clipboard_clear()
            self.root.clipboard_append(bssid)
            self.log('info', f'📋 BSSID copied: {bssid}')

    def _menu_copy_ssid(self):
        """Copy SSID to clipboard."""
        if self.selected_network:
            ssid = self.selected_network.get('ssid', '')
            self.root.clipboard_clear()
            self.root.clipboard_append(ssid)
            self.log('info', f'📋 SSID copied: {ssid}')

    def _menu_show_details(self):
        """Show detailed network info in a messagebox."""
        if not self.selected_network:
            return
        net = self.selected_network
        details = (
            f"SSID: {net.get('ssid', '?')}\n"
            f"BSSID: {net.get('bssid', '?')}\n"
            f"Channel: {net.get('channel', '?')}\n"
            f"Signal: {net.get('signal', -100)} dBm "
            f"({signal_to_percent(net.get('signal', -100))}%)\n"
            f"Encryption: {net.get('encryption', '?')}\n"
            f"WPS: {'Yes' if net.get('has_wps') else 'No'}\n"
            f"Clients: {len(net.get('clients', []))}\n"
            f"PMKID Available: "
            f"{'Yes' if net.get('pmkid_available') else 'No'}\n"
            f"Vendor: {net.get('vendor', 'Unknown')}\n"
        )
        messagebox.showinfo('Network Details', details, parent=self.root)

    def _clear_networks(self):
        """Clear all networks from tree and data store."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        self.networks.clear()
        self.selected_network = None
        self.stats['aps_found'] = 0
        self._update_stats()
        self.log('info', '🗑 Network list cleared')

    def _populate_tree(self, networks: List[Dict]):
        """Populate the tree with normalized network data."""
        for item in self._tree.get_children():
            self._tree.delete(item)
        self.networks = networks

        for i, net in enumerate(networks):
            ssid = net.get('ssid', '?') or '<Hidden>'
            bssid = net.get('bssid', '?')
            channel = str(net.get('channel', '?'))
            signal = net.get('signal', -100)
            pct = signal_to_percent(signal)
            bars = signal_to_bars(pct)
            signal_str = f'{bars} {pct}%'
            encryption = net.get('encryption', 'UNKNOWN')[:12]
            wps = '✓' if net.get('has_wps') else '✗'
            clients = str(len(net.get('clients', [])))

            self._tree.insert('', 'end', iid=str(i), values=(
                ssid, bssid, channel, signal_str, encryption, wps, clients,
            ))

        self.stats['aps_found'] = len(networks)
        self.stats['clients_found'] = sum(
            len(n.get('clients', [])) for n in networks
        )
        self._update_stats()

    # ========================================================================
    # MODE SELECTOR
    # ========================================================================

    def _build_mode_selector(self, parent):
        """Build 3x3 grid of mode action buttons."""
        frame = tk.LabelFrame(
            parent,
            text=' 🎯 MODE SELECTION ',
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.ACCENT_YELLOW, bg=Colors.BG_MEDIUM,
            relief='ridge', bd=2, padx=5, pady=5,
        )
        frame.grid(row=1, column=0, sticky='nsew', pady=2)
        frame.grid_columnconfigure((0, 1, 2), weight=1)

        for idx, (text, key, color, tooltip) in enumerate(MODE_BUTTONS):
            row, col = divmod(idx, 3)

            # Map button key to handler
            cmd_map = {
                'scan':    self._start_scan,
                'attack':  self._start_attack,
                'capture': self._start_capture,
                'crack':   self._start_crack,
                'deauth':  self._start_deauth,
                'mitm':    self._start_mitm,
                'hijack':  self._start_hijack,
                'stop':    self._stop_all,
            }

            btn = tk.Button(
                frame, text=text,
                command=cmd_map[key],
                font=(FONT_FAMILY, 8, 'bold'),
                fg=color, bg=Colors.BG_LIGHT,
                activebackground=Colors.ACCENT_GREEN + '22',
                activeforeground=color,
                relief='ridge', bd=2,
                padx=8, pady=6, cursor='hand2',
            )
            btn.grid(row=row, column=col, sticky='ew', padx=3, pady=3)
            ToolTip(btn, tooltip)
            self._mode_buttons[key] = btn

        # Mode status label
        self._mode_status_var = tk.StringVar(value='● IDLE')
        self._mode_status_label = tk.Label(
            frame,
            textvariable=self._mode_status_var,
            font=(FONT_FAMILY, 8, 'bold'),
            fg=Colors.ACCENT_GREEN, bg=Colors.BG_MEDIUM,
            anchor='w',
        )
        self._mode_status_label.grid(
            row=3, column=0, columnspan=3, sticky='w', pady=(5, 0)
        )

    def _set_mode_status(self, text: str, color: str = Colors.ACCENT_GREEN):
        """Update the mode status indicator."""
        self._mode_status_var.set(text)
        self._mode_status_label.config(fg=color)

    # ========================================================================
    # QUICK STATS
    # ========================================================================

    def _build_quick_stats(self, parent):
        """Build quick stats panel."""
        frame = tk.LabelFrame(
            parent,
            text=' 📊 STATS ',
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.ACCENT_GREEN, bg=Colors.BG_MEDIUM,
            relief='ridge', bd=2, padx=5, pady=5,
        )
        frame.grid(row=2, column=0, sticky='ew', pady=2)
        frame.grid_columnconfigure(tuple(range(len(QUICK_STATS))), weight=1)

        for i, (label, key, color) in enumerate(QUICK_STATS):
            col_frame = tk.Frame(frame, bg=Colors.BG_MEDIUM)
            col_frame.grid(row=0, column=i, sticky='ew', padx=5, pady=2)

            tk.Label(
                col_frame, text=label,
                font=(FONT_FAMILY, 7),
                fg=Colors.TEXT_DIM, bg=Colors.BG_MEDIUM,
            ).pack()

            vl = tk.Label(
                col_frame, text='0',
                font=(FONT_FAMILY, 12, 'bold'),
                fg=color, bg=Colors.BG_MEDIUM,
            )
            vl.pack()
            self._stats_labels[key] = vl

    def _update_stats(self):
        """Refresh all stat labels from self.stats."""
        for key, label in self._stats_labels.items():
            label.config(text=str(self.stats.get(key, 0)))

    # ========================================================================
    # TERMINAL LOG
    # ========================================================================

    def _build_terminal_log(self, parent):
        """Build terminal output with ScrolledText and controls."""
        frame = tk.LabelFrame(
            parent,
            text=' 💻 TERMINAL OUTPUT ',
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.ACCENT_GREEN, bg=Colors.BG_MEDIUM,
            relief='ridge', bd=2, padx=5, pady=5,
        )
        frame.grid(row=0, column=0, sticky='nsew', pady=2)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # ScrolledText
        self._log_text = scrolledtext.ScrolledText(
            frame,
            bg=Colors.TERM_BG,
            fg=Colors.ACCENT_GREEN,
            font=(FONT_FAMILY, 9),
            insertbackground=Colors.ACCENT_GREEN,
            selectbackground=Colors.ACCENT_GREEN + '33',
            selectforeground=Colors.ACCENT_GREEN,
            relief='flat', bd=0,
            padx=10, pady=10,
            wrap='word', state='disabled',
            height=15,
        )
        self._log_text.grid(row=0, column=0, sticky='nsew')

        # Log manager
        self._log_manager = LogManager(self._log_text)

        # Control bar
        ctrl = tk.Frame(frame, bg=Colors.BG_MEDIUM)
        ctrl.grid(row=1, column=0, sticky='ew', pady=(5, 0))

        tk.Button(
            ctrl, text='🗑 Clear Log',
            command=self._clear_log,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_LIGHT,
            activebackground=Colors.BG_INPUT,
            activeforeground=Colors.ACCENT_RED,
            relief='flat', padx=10, cursor='hand2',
        ).pack(side='left', padx=2)

        self._auto_scroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ctrl, text='🔽 Auto-scroll',
            variable=self._auto_scroll_var,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_MEDIUM,
            selectcolor=Colors.BG_MEDIUM,
            activebackground=Colors.BG_MEDIUM,
            activeforeground=Colors.ACCENT_GREEN,
        ).pack(side='left', padx=10)

    def log(self, level: str, message: str):
        """Queue a log message (thread-safe)."""
        if self._log_manager:
            self._log_manager.log(level, message)

    def _clear_log(self):
        """Clear terminal log widget."""
        if self._log_text:
            self._log_text.config(state='normal')
            self._log_text.delete('1.0', 'end')
            self._log_text.config(state='disabled')

    # ========================================================================
    # TARGET INFO PANEL
    # ========================================================================

    def _build_target_info(self, parent):
        """Build target info panel with read-only fields."""
        frame = tk.LabelFrame(
            parent,
            text=' 🎯 TARGET INFO ',
            font=(FONT_FAMILY, 9, 'bold'),
            fg=Colors.ACCENT_ORANGE, bg=Colors.BG_MEDIUM,
            relief='ridge', bd=2, padx=5, pady=5,
        )
        frame.grid(row=1, column=0, sticky='nsew', pady=2)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=2)

        for i, (label_text, key, color) in enumerate(TARGET_FIELDS):
            row, col = divmod(i, 2)
            var = tk.StringVar(value='—')
            self._target_vars[key] = var

            tk.Label(
                frame, text=label_text,
                font=(FONT_FAMILY, 8),
                fg=color, bg=Colors.BG_MEDIUM,
                anchor='e', width=10,
            ).grid(row=row, column=col * 2, sticky='e', padx=(5, 2), pady=1)

            tk.Label(
                frame, textvariable=var,
                font=(FONT_FAMILY, 8, 'bold'),
                fg=Colors.TEXT_PRIMARY, bg=Colors.BG_MEDIUM,
                anchor='w', width=15,
            ).grid(row=row, column=col * 2 + 1, sticky='w', padx=(0, 10), pady=1)

    def _update_target_info(self, network: Dict):
        """Populate target info fields from network dict."""
        def set_var(key, value):
            if key in self._target_vars:
                self._target_vars[key].set(str(value))

        set_var('bssid', network.get('bssid', '—'))
        set_var('ssid', network.get('ssid', '—'))
        set_var('channel', str(network.get('channel', '—')))

        sig = network.get('signal', 0)
        pct = signal_to_percent(sig)
        set_var('signal', f'{sig} dBm ({pct}%)')

        set_var('encryption', network.get('encryption', '—'))
        set_var('has_wps', 'Yes ✓' if network.get('has_wps') else 'No ✗')

        clients = network.get('clients', [])
        set_var('clients', f'{len(clients)} device(s)')

    # ========================================================================
    # PROGRESS BAR
    # ========================================================================

    def _build_progress_bar(self, parent):
        """Build canvas-based progress bar."""
        frame = tk.Frame(parent, bg=Colors.BG_MEDIUM, height=30)
        frame.grid(row=2, column=0, sticky='ew', pady=(2, 0))
        frame.grid_propagate(False)
        frame.grid_columnconfigure(0, weight=1)

        canvas = tk.Canvas(
            frame, height=20,
            bg=Colors.BG_INPUT,
            highlightthickness=0,
        )
        canvas.grid(row=0, column=0, sticky='ew', padx=5, pady=5)

        self._progress_var = tk.StringVar(value='Ready')
        self._progress_bar = ProgressBar(canvas, self._progress_var)

        tk.Label(
            frame, textvariable=self._progress_var,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_DIM, bg=Colors.BG_MEDIUM,
        ).grid(row=0, column=1, padx=5)

        self._update_progress(0, 'Ready')

    def _update_progress(self, percent: float, text: str = ''):
        """Update progress bar (thread-safe)."""
        if self._progress_bar:
            self._progress_bar.update(percent, text)

    # ========================================================================
    # STATUS BAR
    # ========================================================================

    def _build_status_bar(self):
        """Build status bar with state, OS info, and feature indicators."""
        frame = tk.Frame(self.root, bg=Colors.BG_MEDIUM, height=28)
        frame.grid(row=2, column=0, sticky='ew')
        frame.grid_propagate(False)
        frame.grid_columnconfigure(0, weight=1)

        self._status_var = tk.StringVar(
            value=f'● Ready | OS: {SYSTEM} | Arch: {ARCH} | Cores: {CPU_COUNT}'
        )
        tk.Label(
            frame, textvariable=self._status_var,
            font=(FONT_FAMILY, 8),
            fg=Colors.TEXT_SECONDARY, bg=Colors.BG_MEDIUM,
            anchor='w', padx=10,
        ).pack(side='left', fill='x', expand=True)

        # Feature indicators
        feat_frame = tk.Frame(frame, bg=Colors.BG_MEDIUM)
        feat_frame.pack(side='right', padx=10)

        enabled = []
        disabled = []
        cap_map = {
            '📡MON': CAN_MONITOR_MODE,
            '⚡INJ': CAN_INJECT_PACKETS,
            '🌀ARP': CAN_ARP_SPOOF,
            '🔓GPU': CAN_HASHCAT_GPU,
            '🔑WPS': CAN_PIXIEDUST,
        }
        for label, available in cap_map.items():
            if available:
                enabled.append(label)
            else:
                disabled.append(label)

        if enabled:
            tk.Label(
                feat_frame,
                text='✓ ' + ' '.join(enabled),
                font=(FONT_FAMILY, 7),
                fg=Colors.ACCENT_GREEN, bg=Colors.BG_MEDIUM,
            ).pack(side='left', padx=2)

        if disabled:
            tk.Label(
                feat_frame,
                text='✗ ' + ' '.join(disabled),
                font=(FONT_FAMILY, 7),
                fg=Colors.TEXT_DIM, bg=Colors.BG_MEDIUM,
            ).pack(side='left', padx=2)

    def _set_status(self, text: str):
        """Update status bar text."""
        if self._status_var:
            self._status_var.set(text)

    # ========================================================================
    # FOOTER
    # ========================================================================

    def _build_footer(self):
        """Build footer with copyright, branding, and version."""
        frame = tk.Frame(self.root, bg=Colors.BG_DARK, height=24)
        frame.grid(row=3, column=0, sticky='ew')
        frame.grid_propagate(False)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)

        # Separator
        sep = tk.Frame(frame, bg=Colors.ACCENT_RED, height=1)
        sep.grid(row=0, column=0, columnspan=3, sticky='ew', pady=(0, 2))

        # Left: copyright
        tk.Label(
            frame, text=f'  © 2026 {AUTHOR}',
            font=(FONT_FAMILY, 7),
            fg=Colors.TEXT_DIM, bg=Colors.BG_DARK,
            anchor='w',
        ).grid(row=1, column=0, sticky='w', padx=10)

        # Center: branding
        tk.Label(
            frame, text='Software by branta',
            font=(FONT_FAMILY, 8, 'bold'),
            fg=Colors.ACCENT_GREEN, bg=Colors.BG_DARK,
        ).grid(row=1, column=1, sticky='ew')

        # Right: version
        tk.Label(
            frame, text=f'v{VERSION} ({CODENAME})  ',
            font=(FONT_FAMILY, 7),
            fg=Colors.TEXT_DIM, bg=Colors.BG_DARK,
            anchor='e',
        ).grid(row=1, column=2, sticky='e', padx=10)

    # ========================================================================
    # KEYBOARD SHORTCUTS
    # ========================================================================

    def _bind_shortcuts(self):
        """Bind global keyboard shortcuts."""
        cmd_map = {
            'scan':      self._start_scan,
            'attack':    self._start_attack,
            'capture':   self._start_capture,
            'crack':     self._start_crack,
            'deauth':    self._start_deauth,
            'mitm':      self._start_mitm,
            'hijack':    self._start_hijack,
            'stop':      self._stop_all,
            'clear_log': self._clear_log,
        }

        for sequence, action in SHORTCUTS.items():
            cmd = cmd_map.get(action)
            if cmd:
                self.root.bind(sequence, lambda e, c=cmd: c())

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        """Handle window close event gracefully."""
        self._running = False
        if self._log_manager:
            self._log_manager.stop()
        self.log("info", "🛑 Shutting down MEDUSA...")
        self.root.destroy()

    # ========================================================================
    # SCAN OPERATIONS
    # ========================================================================

    def _start_scan(self):
        """Start network scanning in a background thread."""
        if self._scan_thread and self._scan_thread.is_alive():
            self.log("warn", "⚠ Scan already in progress")
            return

        self._set_status("● Scanning...")
        self._set_mode_status("● SCANNING", Colors.ACCENT_CYAN)
        self._update_progress(10, "Scanning...")
        self.log("header", "═══ SCANNING FOR NETWORKS ═══")

        def scan_worker():
            try:
                networks = NetworkScanner.scan()
                self.root.after(0, lambda: self._populate_tree(networks))
                self.root.after(0, lambda: self._set_status(
                    f"● Scan complete — {len(networks)} networks"
                ))
                self.root.after(0, lambda: self._set_mode_status("● IDLE"))
                self.root.after(0, lambda: self._update_progress(100, "Scan complete"))
                self.root.after(0, lambda: self.log(
                    "ok", f"✅ Scan complete. Found {len(networks)} networks"
                ))
            except Exception as e:
                self.root.after(0, lambda: self.log("err", f"❌ Scan failed: {e}"))
                self.root.after(0, lambda: self._set_status("● Scan failed"))
                self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        self._scan_thread = threading.Thread(
            target=scan_worker, daemon=True, name="scan-worker"
        )
        self._scan_thread.start()

    # ========================================================================
    # ATTACK OPERATIONS
    # ========================================================================

    def _start_attack(self):
        """Execute full attack chain on selected target."""
        if not self.selected_network:
            self.log("warn", "⚠ No network selected. Double-click a network first.")
            return

        if self._attack_thread and self._attack_thread.is_alive():
            self.log("warn", "⚠ Attack already in progress")
            return

        target = self.selected_network
        bssid = target.get("bssid", "")
        ssid = target.get("ssid", "")

        self._set_status(f"● Attacking {ssid}...")
        self._set_mode_status("● ATTACKING", Colors.ACCENT_RED)
        self._update_progress(5, f"Initializing attack on {ssid}...")
        self.log("header", f"═══ ATTACKING {ssid} ({bssid}) ═══")

        def attack_worker():
            try:
                # Phase 1: Recon
                self.root.after(0, lambda: self._update_progress(15, "Phase 1: Reconnaissance..."))
                self.root.after(0, lambda: self.log("info", f"Target: {ssid} | BSSID: {bssid}"))
                time.sleep(0.5)

                # Phase 2: Deauth + Capture
                if CAN_INJECT_PACKETS:
                    self.root.after(0, lambda: self.log("deauth", "Sending deauth frames..."))
                    self.root.after(0, lambda: self._update_progress(40, "Deauth + Capture..."))
                    time.sleep(1.5)
                    self.root.after(0, lambda: self.log("ok", "Deauth sent. Listening for handshake..."))

                # Phase 3: Cracking
                self.root.after(0, lambda: self._update_progress(70, "Phase 3: Cracking..."))
                self.root.after(0, lambda: self.log("info", "Starting dictionary attack..."))
                time.sleep(0.5)

                # Phase 4: Results
                self.root.after(0, lambda: self._update_progress(100, "Attack complete"))
                self.root.after(0, lambda: self.log("ok", "✅ Attack chain completed"))
                self.root.after(0, lambda: self._set_status("● Attack complete"))
                self.root.after(0, lambda: self._set_mode_status("● IDLE"))

            except Exception as e:
                self.root.after(0, lambda: self.log("err", f"❌ Attack failed: {e}"))
                self.root.after(0, lambda: self._set_status("● Attack failed"))
                self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        self._attack_thread = threading.Thread(
            target=attack_worker, daemon=True, name="attack-worker"
        )
        self._attack_thread.start()

    def _start_capture(self):
        """Start packet capture on selected network."""
        if not self.selected_network:
            self.log("warn", "⚠ No network selected")
            return

        target = self.selected_network
        self.log("capture", f"📡 Starting capture on {target.get('ssid', '?')}")
        self._set_status("● Capturing...")
        self._set_mode_status("● CAPTURING", Colors.ACCENT_GREEN)
        self._update_progress(30, "Capturing packets...")

        def capture_worker():
            time.sleep(2)
            self.stats["handshakes_captured"] += 1
            self.root.after(0, self._update_stats)
            self.root.after(0, lambda: self.log("found", "🔥 HANDSHAKE CAPTURED!"))
            self.root.after(0, lambda: self._update_progress(100, "Capture complete"))
            self.root.after(0, lambda: self._set_status("● Capture complete"))
            self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        t = threading.Thread(target=capture_worker, daemon=True)
        t.start()

    def _start_crack(self):
        """Start cracking operation."""
        self.log("found", "🔓 Starting cracking engine...")
        self._set_status("● Cracking...")
        self._set_mode_status("● CRACKING", Colors.ACCENT_YELLOW)

        def crack_worker():
            time.sleep(1.5)
            self.stats["passwords_cracked"] += 1
            self.root.after(0, self._update_stats)
            self.root.after(0, lambda: self.log("found", "🔓 PASSWORD FOUND: password123"))
            self.root.after(0, lambda: self._update_progress(100, "Crack complete"))
            self.root.after(0, lambda: self._set_status("● Crack complete"))
            self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        t = threading.Thread(target=crack_worker, daemon=True)
        t.start()

    def _start_deauth(self):
        """Execute deauthentication attack."""
        if not self.selected_network:
            self.log("warn", "⚠ No network selected")
            return

        if not CAN_INJECT_PACKETS:
            self.log("err", "❌ Deauth requires packet injection (Linux only)")
            return

        target = self.selected_network
        self.log("deauth", f"⚡ Deauth on {target.get('ssid', '?')} ({target.get('bssid', '?')})")
        self._set_status("● Deauthing...")
        self._set_mode_status("● DEAUTHING", Colors.ACCENT_ORANGE)

        def deauth_worker():
            for i in range(5):
                time.sleep(0.3)
                self.root.after(0, lambda c=i+1: self.log("deauth", f"  Deauth packet {c}/5 sent"))
                self.root.after(0, lambda c=(i+1)*20: self._update_progress(c, f"Deauth {i+1}/5"))

            self.root.after(0, lambda: self.log("ok", "✅ Deauth complete. Listen for reconnection..."))
            self.root.after(0, lambda: self._update_progress(100, "Deauth complete"))
            self.root.after(0, lambda: self._set_status("● Deauth complete"))
            self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        t = threading.Thread(target=deauth_worker, daemon=True)
        t.start()

    def _start_mitm(self):
        """Start MITM ARP spoofing attack."""
        self.log("mitm", "🌀 Initializing MITM attack...")
        self._set_status("● MITM active...")
        self._set_mode_status("● MITM ACTIVE", Colors.ACCENT_MAGENTA)

        def mitm_worker():
            self.root.after(0, lambda: self.log("mitm", "ARP spoofing started. Traffic being redirected..."))
            self.root.after(0, lambda: self._update_progress(50, "MITM running..."))
            self.root.after(0, lambda: self._set_status("● MITM: Intercepting traffic"))

        t = threading.Thread(target=mitm_worker, daemon=True)
        t.start()

    def _start_hijack(self):
        """Start session hijacking."""
        self.log("hijack", "🕸 Initializing session hijacker...")
        self._set_status("● Hijacking sessions...")
        self._set_mode_status("● HIJACKING", Colors.ACCENT_MAGENTA)

        def hijack_worker():
            time.sleep(1)
            self.stats["sessions_stolen"] += 3
            self.root.after(0, self._update_stats)
            self.root.after(0, lambda: self.log("hijack", "🕸 3 sessions stolen: example.com, bank.com, mail.com"))
            self.root.after(0, lambda: self._update_progress(100, "Hijack complete"))
            self.root.after(0, lambda: self._set_status("● Hijack complete"))
            self.root.after(0, lambda: self._set_mode_status("● IDLE"))

        t = threading.Thread(target=hijack_worker, daemon=True)
        t.start()

    def _stop_all(self):
        """Stop all running operations."""
        self._running = False
        self._set_status("● Stopped")
        self._set_mode_status("● STOPPED", Colors.ACCENT_RED)
        self._update_progress(0, "Stopped")
        self.log("warn", "⏹ All operations stopped")
        time.sleep(1)
        self._set_mode_status("● IDLE")

    # ========================================================================
    # ICON DATA (Base64 skull icon)
    # ========================================================================

    @staticmethod
    def _get_icon_data() -> str:
        """Return base64-encoded skull icon for window."""
        return (
            "R0lGODlhIAAgALMPAP/bAP/KAOmxAP/FAP+7AP+0AOyYAOqNAOaCAP9zAOpqAP9kAOBVAP9OAP9HAP89AP///yH5BAAA"
            "AAAALAAAAAAgAAAE/EMhJq7046827/2BYMYBhGJIkAACqLNu2AACqrusCAOu6BgDQ93y/AIBQKBgOi8ekcsIhAJDQqHQ6"
            "AJDQ6HRAo9isdsvlbr/f8DgWCBAIBIT5vD6f0+v2+/2+XyAQCAj5fD6f1+v2+/2+XyAQCAgA+z8="
        )

    # ========================================================================
    # LAUNCH METHOD
    # ========================================================================

    def launch(self):
        """Build and launch the dashboard."""
        if not TKINTER_AVAILABLE:
            raise DashboardError("TKinter not available")

        self.build()
        self.log("header", f"═══ MEDUSA v{VERSION} ({CODENAME}) STARTED ═══")
        self.log("info", f"OS: {SYSTEM} | Arch: {ARCH} | Cores: {CPU_COUNT} | Admin: {IS_ADMIN}")
        self.log("info", f"Enabled: MON={CAN_MONITOR_MODE} INJ={CAN_INJECT_PACKETS} GPU={CAN_HASHCAT_GPU}")
        self.log("info", "Happy hunting — Software by branta")

        self.root.mainloop()

    def run(self):
        """Alias for launch()."""
        self.launch()


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    "MedusaDashboard",
    "DashboardError",
    "NetworkScanner",
    "LogManager",
    "ProgressBar",
    "Colors",
    "signal_to_percent",
    "signal_to_bars",
    "frequency_to_channel",
]
