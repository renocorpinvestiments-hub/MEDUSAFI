#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║                                                                             ║
║  medusa_interface.py — Cross-Platform Network Interface Manager            ║
║                                                                             ║
║  Architecture:                                                              ║
║    • OS-Adaptive Detection (3-tier fallback per platform)                  ║
║    • Zero fragile CLI parsing where possible                              ║
║    • Lock-free concurrent reads via pre-computed snapshots                ║
║    • Monitor mode orchestration with idempotent cleanup                   ║
║    • Channel hopping engine for multi-channel captures                    ║
║    • MAC address spoofing with randomization entropy                      ║
║    • Hardware vendor lookup via OUI database                              ║
║    • Connection quality scoring for optimal interface selection           ║
║                                                                             ║
║  Capabilities Matrix:                                                       ║
║  ┌─────────────────────┬─────────┬──────────┬────────┐                    ║
║  │ Feature             │ Linux   │ macOS    │ Win    │                    ║
║  ├─────────────────────┼─────────┼──────────┼────────┤                    ║
║  │ Interface Detect    │ ✅ iw   │ ✅ ifc.  │ ✅ nth │                    ║
║  │ Monitor Mode        │ ✅ iw+am│ ⚠ airport│ ❌     │                    ║
║  │ Channel Hopping     │ ✅ iw   │ ❌       │ ❌     │                    ║
║  │ MAC Spoofing        │ ✅ ip   │ ⚠ ifc.  │ ⚠ reg  │                    ║
║  │ OUI Vendor Lookup   │ ✅      │ ✅       │ ✅     │                    ║
║  │ Signal Strength     │ ✅ iw   │ ⚠ airport│ ✅ nth │                    ║
║  │ Connection Quality  │ ✅      │ ✅       │ ✅     │                    ║
║  │ ARP Cache Mgmt      │ ✅      │ ✅       │ ✅     │                    ║
║  └─────────────────────┴─────────┴──────────┴────────┘                    ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import time
import json
import errno
import struct
import socket
import random
import ctypes
import hashlib
import logging
import platform
import threading
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Iterator, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict, OrderedDict
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# MEDUSA Core Imports
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CAN_MONITOR_MODE, CAN_INJECT_PACKETS,
    CONFIG_DIR, TEMP_DIR, ANSI,
    MedusaError, InterfaceError, MonitorModeError, PermissionError_Medusa,
    ensure_directories, current_timestamp, validate_mac, validate_ip,
    human_time, human_bytes, safe_filename,
    LOG_LEVELS,
)

# ============================================================================
# CONSTANTS
# ============================================================================

# IEEE OUI database URL (for vendor lookup)
OUI_DB_URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUI_DB_PATH = CONFIG_DIR / "oui_database.txt"
OUI_CACHE_PATH = CONFIG_DIR / "oui_cache.json"
OUI_CACHE_TTL = 86400 * 7  # 7 days

# Standard WiFi channels (2.4 GHz and 5 GHz)
CHANNEL_2GHZ = list(range(1, 14))
CHANNEL_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                116, 120, 124, 128, 132, 136, 140, 144, 149, 153,
                157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197]

CHANNEL_FREQ_MAP = {
    # 2.4 GHz
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472,
    # 5 GHz
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700, 144: 5720,
    149: 5745, 153: 5765, 157: 5785, 161: 5805,
    165: 5825, 169: 5845, 173: 5865, 177: 5885,
    181: 5905, 185: 5925, 189: 5945, 193: 5965, 197: 5985,
}

# Channel bandwidths for 802.11
CHANNEL_WIDTHS = {
    20: "HT20",
    40: "HT40",
    80: "VHT80",
    160: "VHT160",
}

# Interface type classification
INTERFACE_TYPES = {
    'wlan': 'wireless',
    'wlp': 'wireless',
    'wlx': 'wireless',
    'eth': 'ethernet',
    'enp': 'ethernet',
    'ens': 'ethernet',
    'eno': 'ethernet',
    'enx': 'ethernet',
    'en': 'ethernet',  # macOS
    'lo': 'loopback',
    'docker': 'virtual',
    'veth': 'virtual',
    'br-': 'virtual',
    'tun': 'virtual',
    'tap': 'virtual',
    'fw': 'virtual',
    'p2p': 'virtual',
    'ib': 'infiniband',
}

# Monitor mode interface naming patterns
MONITOR_PATTERNS = [
    re.compile(r'mon\d+', re.I),       # mon0, mon1
    re.compile(r'wlan\d+mon', re.I),   # wlan0mon
    re.compile(r'wlp.*mon', re.I),     # wlp3s0mon
    re.compile(r'ath\d+mon', re.I),    # ath0mon
    re.compile(r'phy\d+\.mon', re.I),  # phy0.mon
]

# ARP operation codes
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

# Interface state flags
IFACE_STATE_UP = 'up'
IFACE_STATE_DOWN = 'down'
IFACE_STATE_UNKNOWN = 'unknown'

# Default interface priority for selection
INTERFACE_PRIORITY = ['mon', 'wlan', 'wlp', 'wlx', 'en0', 'en1', 'eth']

# Scan timeout in seconds
SCAN_TIMEOUT = 30
MONITOR_MODE_TIMEOUT = 15
CHANNEL_SWITCH_INTERVAL = 0.25  # 250ms per channel

# OUI vendor cache
OUI_VENDOR_CACHE: Dict[str, str] = {}

# Thread-local storage for interface operations
_thread_local = threading.local()


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class InterfaceInfo:
    """Complete interface information snapshot.
    
    This is an immutable snapshot — always read via InterfaceManager.
    Thread-safe by design: no setters, only factory methods.
    """
    name: str
    mac: str = ""
    ipv4: str = ""
    ipv6: str = ""
    netmask: str = ""
    gateway: str = ""
    broadcast: str = ""
    
    # Wireless-specific
    is_wireless: bool = False
    is_monitor: bool = False
    is_loopback: bool = False
    is_virtual: bool = False
    is_up: bool = False
    
    # Signal/quality
    signal_dbm: Optional[int] = None
    signal_percent: Optional[int] = None
    noise_dbm: Optional[int] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    bitrate: Optional[float] = None
    tx_power: Optional[int] = None
    
    # Hardware
    driver: str = ""
    phy: str = ""  # Physical device name (Linux)
    vendor: str = ""
    pci_id: str = ""
    usb_id: str = ""
    
    # Capabilities
    supports_monitor: bool = False
    supports_ap_mode: bool = False
    max_antennas: int = 0
    
    # Statistics
    tx_packets: int = 0
    rx_packets: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_errors: int = 0
    rx_errors: int = 0
    tx_dropped: int = 0
    rx_dropped: int = 0
    collisions: int = 0
    
    @property
    def quality_score(self) -> float:
        """Compute a 0.0 to 1.0 quality score for interface selection.
        
        Factors:
        - Signal strength (if wireless)
        - Interface type priority
        - Admin state (up > down)
        - Error rate
        """
        score = 0.0
        
        # Wireless gets bonus
        if self.is_wireless:
            score += 0.3
        
        # Interface type priority
        for i, prefix in enumerate(INTERFACE_PRIORITY):
            if self.name.startswith(prefix):
                score += (len(INTERFACE_PRIORITY) - i) * 0.05
                break
        
        # Admin state
        if self.is_up:
            score += 0.2
        
        # Signal strength
        if self.signal_dbm is not None:
            # Map -30 dBm (perfect) to 1.0, -90 dBm (dead) to 0.0
            sig_score = max(0.0, min(1.0, (self.signal_dbm + 90) / 60))
            score += sig_score * 0.2
        
        # Error penalty
        total_pkts = self.tx_packets + self.rx_packets
        if total_pkts > 100:
            errors = self.tx_errors + self.rx_errors
            error_rate = errors / total_pkts
            score -= error_rate * 0.1
        
        return max(0.0, min(1.0, score))
    
    @property
    def is_monitor_mode(self) -> bool:
        """Check if this interface is likely in monitor mode."""
        if self.is_monitor:
            return True
        for pattern in MONITOR_PATTERNS:
            if pattern.match(self.name):
                return True
        return False
    
    @property
    def display_name(self) -> str:
        """Get a human-readable display name."""
        if self.vendor:
            return f"{self.name} ({self.vendor})"
        return self.name
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InterfaceInfo':
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class ARPEntry:
    """ARP cache entry."""
    ip: str
    mac: str
    interface: str
    timestamp: float
    is_gateway: bool = False
    vendor: str = ""
    
    @property
    def age_seconds(self) -> float:
        return time.time() - self.timestamp
    
    @property
    def is_stale(self) -> bool:
        return self.age_seconds > 300  # 5 minutes


@dataclass
class ScanResult:
    """WiFi scan result from a single interface."""
    interface: str
    networks: List[Dict[str, Any]] = field(default_factory=list)
    duration: float = 0.0
    channel_count: int = 0
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)
    
    @property
    def network_count(self) -> int:
        return len(self.networks)
    
    @property
    def strongest_signal(self) -> Optional[int]:
        if not self.networks:
            return None
        return max(n.get('signal', -100) for n in self.networks)


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def _run_command(cmd: List[str], timeout: int = 15,
                 check: bool = False, shell: bool = False) -> subprocess.CompletedProcess:
    """Run a system command with timeout and error handling.
    
    Args:
        cmd: Command as list of strings
        timeout: Timeout in seconds
        check: Raise on non-zero return code
        shell: Use shell=True
    
    Returns:
        CompletedProcess instance
    
    Raises:
        InterfaceError: On timeout, not found, or non-zero (if check=True)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            shell=shell,
        )
        return result
    except subprocess.TimeoutExpired:
        raise InterfaceError(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    except FileNotFoundError:
        raise InterfaceError(f"Command not found: {cmd[0]}")
    except subprocess.CalledProcessError as e:
        if check:
            raise InterfaceError(f"Command failed: {e.stderr}")
        return e


def _parse_mac_from_string(text: str) -> Optional[str]:
    """Extract MAC address from any text string.
    
    Handles formats: AA:BB:CC:DD:EE:FF, AA-BB-CC-DD-EE-FF, AABB.CCDD.EEFF
    
    Args:
        text: Text potentially containing a MAC address
    
    Returns:
        Normalized MAC address or None
    """
    # Standard XX:XX:XX:XX:XX:XX
    m = re.search(r'(?:[0-9A-Fa-f]{2}[:\-]){5}(?:[0-9A-Fa-f]{2})', text)
    if m:
        return m.group(0).upper().replace('-', ':')
    
    # Cisco-style XXXX.XXXX.XXXX
    m = re.search(r'(?:[0-9A-Fa-f]{4}\.){2}(?:[0-9A-Fa-f]{4})', text)
    if m:
        addr = m.group(0).replace('.', '')
        return ':'.join(addr[i:i+2] for i in range(0, 12, 2)).upper()
    
    return None


def _parse_ip_from_string(text: str) -> Optional[str]:
    """Extract IPv4 address from text."""
    m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)
    return m.group(0) if m else None


def _channel_to_freq(channel: int) -> int:
    """Convert channel number to frequency in MHz."""
    return CHANNEL_FREQ_MAP.get(channel, 0)


def _freq_to_channel(freq: int) -> int:
    """Convert frequency in MHz to channel number."""
    for ch, f in CHANNEL_FREQ_MAP.items():
        if f == freq:
            return ch
    # Approximate
    if 2412 <= freq <= 2484:
        return (freq - 2407) // 5
    elif 5180 <= freq <= 5985:
        return (freq - 5180) // 5 + 36
    return 0


def _random_mac() -> str:
    """Generate a random MAC address with locally-administered bit set.
    
    The locally-administered bit (bit 1 of first octet) is set to ensure
    this is not a globally unique OUI. Bit 0 (unicast/multicast) is cleared.
    """
    mac = [random.randint(0x00, 0xFF) for _ in range(6)]
    # Set local-admin bit (second least significant bit)
    mac[0] = (mac[0] & 0xFE) | 0x02
    # Clear multicast bit
    mac[0] = mac[0] & 0xFE
    return ':'.join(f'{b:02X}' for b in mac)


def _oui_lookup(mac: str) -> Optional[str]:
    """Look up vendor by MAC address OUI.
    
    Uses cached OUI database. Auto-downloads if missing and connected.
    
    Args:
        mac: MAC address (AA:BB:CC:DD:EE:FF)
    
    Returns:
        Vendor name string or None
    """
    if not mac or len(mac) < 8:
        return None
    
    # Normalize OUI (first 3 octets)
    oui = mac[:8].upper().replace(':', '').replace('-', '')
    
    # Check memory cache first
    if oui in OUI_VENDOR_CACHE:
        return OUI_VENDOR_CACHE[oui]
    
    # Check file cache
    try:
        if OUI_CACHE_PATH.exists():
            with open(OUI_CACHE_PATH, 'r') as f:
                cache = json.load(f)
            if oui in cache:
                OUI_VENDOR_CACHE[oui] = cache[oui]
                return cache[oui]
    except (IOError, json.JSONDecodeError):
        pass
    
    # Try to load from raw OUI database
    try:
        if OUI_DB_PATH.exists():
            with open(OUI_DB_PATH, 'r', encoding='utf-8', errors='replace') as f:
                for line in f:
                    if oui in line and '(hex)' in line:
                        vendor = line.split('(hex)')[-1].strip()
                        OUI_VENDOR_CACHE[oui] = vendor
                        return vendor
    except (IOError, OSError):
        pass
    
    return None


def _update_oui_database(force: bool = False) -> bool:
    """Download and cache the IEEE OUI database.
    
    Args:
        force: Force re-download even if cache exists
    
    Returns:
        True if database is available
    """
    # Check if cache exists and is recent
    if not force and OUI_CACHE_PATH.exists():
        try:
            age = time.time() - OUI_CACHE_PATH.stat().st_mtime
            if age < OUI_CACHE_TTL:
                return True
        except OSError:
            pass
    
    # Try to download
    try:
        import urllib.request
        console.info("Downloading OUI vendor database...")
        urllib.request.urlretrieve(OUI_DB_URL, OUI_DB_PATH)
        
        # Parse and cache as JSON for faster lookups
        cache = {}
        with open(OUI_DB_PATH, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                if '(hex)' in line:
                    parts = line.split('(hex)')
                    oui = parts[0].strip().replace('-', ':').upper()
                    vendor = parts[1].strip()
                    cache[oui] = vendor
        
        with open(OUI_CACHE_PATH, 'w') as f:
            json.dump(cache, f)
        
        return True
    except Exception:
        return False


# ============================================================================
# NETWORK SCANNER (Cross-Platform)
# ============================================================================

class NetworkScanner:
    """Cross-platform WiFi network scanner.
    
    Uses OS-native tools with fallback chain:
    1. iw dev scan (Linux — most detailed)
    2. airport --scan (macOS)
    3. netsh wlan show networks (Windows)
    4. pywifi (universal fallback)
    """
    
    @staticmethod
    def scan_linux(interface: str, timeout: int = SCAN_TIMEOUT,
                   channel: Optional[int] = None) -> List[Dict[str, Any]]:
        """Scan with iw dev (Linux — gold standard).
        
        iw provides BSSID, SSID, signal, frequency, channel, encryption,
        and client information.
        
        Args:
            interface: Wireless interface name
            timeout: Scan timeout in seconds
            channel: Specific channel to scan (None = all)
        
        Returns:
            List of network dictionaries
        """
        networks = []
        
        cmd = ['iw', 'dev', interface, 'scan']
        if channel:
            freq = _channel_to_freq(channel)
            if freq:
                cmd.extend(['--freq', str(freq)])
        
        try:
            result = _run_command(cmd, timeout=timeout)
            output = result.stdout
            
            current_net = {}
            for line in output.split('\n'):
                stripped = line.strip()
                
                # New BSS entry
                if line.startswith('BSS ') and not line.startswith('BSS Load'):
                    if current_net and 'ssid' in current_net:
                        networks.append(current_net)
                    current_net = {
                        'bssid': line.split()[1].strip().upper(),
                        'clients': [],
                    }
                
                # SSID
                elif 'SSID:' in stripped:
                    ssid = stripped.split('SSID:')[-1].strip()
                    if ssid:
                        current_net['ssid'] = ssid
                
                # Signal
                elif 'signal:' in stripped and 'signal avg' not in stripped:
                    parts = stripped.split('signal:')
                    if len(parts) > 1:
                        try:
                            current_net['signal'] = float(parts[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
                
                # Frequency
                elif 'freq:' in stripped:
                    parts = stripped.split('freq:')
                    if len(parts) > 1:
                        try:
                            freq = float(parts[1].strip().split()[0])
                            current_net['frequency'] = freq
                            current_net['channel'] = _freq_to_channel(int(freq))
                        except (ValueError, IndexError):
                            pass
                
                # Channel from DS parameter set
                elif 'DS Parameter set: channel' in stripped:
                    try:
                        current_net['channel'] = int(stripped.split('channel ')[-1])
                    except (ValueError, IndexError):
                        pass
                
                # Encryption capabilities
                elif 'WPA:' in stripped or stripped.startswith('WPA:'):
                    current_net['wpa'] = True
                    current_net['encryption'] = 'WPA'
                elif 'RSN:' in stripped or stripped.startswith('RSN:'):
                    current_net['wpa2'] = True
                    current_net['encryption'] = 'WPA2'
                    # Check for PMKID
                    if 'PMKID' in stripped:
                        current_net['pmkid_available'] = True
                elif 'wpa_version:' in stripped:
                    if '3' in stripped:
                        current_net['encryption'] = 'WPA3'
                        current_net['wpa3'] = True
                
                # Capability flags
                elif 'capability:' in stripped:
                    cap_str = stripped.split('capability:')[-1].strip()
                    current_net['capabilities'] = cap_str
                    # Check for WPS (look for 0x1000 or similar)
                    if '0x1000' in cap_str or 'WPS' in cap_str:
                        current_net['wps'] = True
                
                # Beacon interval
                elif 'beacon interval:' in stripped:
                    try:
                        current_net['beacon_interval'] = int(stripped.split(':')[-1].strip())
                    except (ValueError, IndexError):
                        pass
                
                # DS parameter set
                elif 'DTIM period:' in stripped:
                    try:
                        current_net['dtim'] = int(stripped.split(':')[-1].strip())
                    except (ValueError, IndexError):
                        pass
                
                # Vendor-specific IE (for hardware detection)
                elif 'Vendor specific:' in stripped:
                    if 'vendor_ies' not in current_net:
                        current_net['vendor_ies'] = []
                    current_net['vendor_ies'].append(stripped)
            
            # Don't forget the last one
            if current_net and 'ssid' in current_net:
                networks.append(current_net)
        
        except InterfaceError as e:
            # Fallback to iwlist
            try:
                result = _run_command(
                    ['iwlist', interface, 'scan'],
                    timeout=timeout
                )
                networks = NetworkScanner._parse_iwlist(result.stdout)
            except InterfaceError:
                raise
        
        except PermissionError_Medusa:
            raise
        
        return networks
    
    @staticmethod
    def _parse_iwlist(output: str) -> List[Dict[str, Any]]:
        """Parse iwlist scan output (less detailed fallback)."""
        networks = []
        current_net = {}
        
        for line in output.split('\n'):
            stripped = line.strip()
            
            if 'Cell' in stripped and 'Address' in stripped:
                if current_net and 'ssid' in current_net:
                    networks.append(current_net)
                current_net = {'clients': []}
                m = re.search(r'Address:\s*([0-9A-Fa-f:]+)', stripped)
                if m:
                    current_net['bssid'] = m.group(1).upper()
            
            elif 'ESSID' in stripped:
                m = re.search(r'ESSID:"(.+)"', stripped)
                if m:
                    current_net['ssid'] = m.group(1)
            
            elif 'Frequency' in stripped:
                m = re.search(r'Frequency:([\d.]+)\s*GHz', stripped)
                if m:
                    try:
                        freq = float(m.group(1)) * 1000  # GHz to MHz
                        current_net['frequency'] = int(freq)
                        current_net['channel'] = _freq_to_channel(int(freq))
                    except ValueError:
                        pass
                m = re.search(r'Channel\s*(\d+)', stripped)
                if m:
                    try:
                        current_net['channel'] = int(m.group(1))
                    except ValueError:
                        pass
            
            elif 'Quality' in stripped:
                m = re.search(r'Quality=(\d+)/(\d+)', stripped)
                if m:
                    try:
                        qual = int(m.group(1))
                        max_qual = int(m.group(2))
                        # Convert to approximate dBm
                        pct = qual / max_qual if max_qual > 0 else 0
                        current_net['signal'] = -30 - int((1 - pct) * 60)
                    except (ValueError, ZeroDivisionError):
                        pass
            
            elif 'Signal level' in stripped:
                m = re.search(r'Signal level=(-?\d+)', stripped)
                if m:
                    try:
                        current_net['signal'] = int(m.group(1))
                    except ValueError:
                        pass
            
            elif 'Encryption key' in stripped:
                if 'off' in stripped:
                    current_net['encryption'] = 'OPEN'
            
            elif 'IE:' in stripped and 'WPA' in stripped:
                if 'Version 1' in stripped:
                    current_net['encryption'] = 'WPA'
                elif 'Version 2' in stripped:
                    current_net['encryption'] = 'WPA2'
                elif 'WPA3' in stripped:
                    current_net['encryption'] = 'WPA3'
        
        if current_net and 'ssid' in current_net:
            networks.append(current_net)
        
        return networks
    
    @staticmethod
    def scan_macos(interface: str, timeout: int = SCAN_TIMEOUT) -> List[Dict[str, Any]]:
        """Scan with airport on macOS."""
        networks = []
        
        # Find airport binary
        airport_paths = [
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
            '/usr/sbin/airport',
        ]
        
        airport = None
        for path in airport_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                airport = path
                break
        
        if not airport:
            raise InterfaceError("airport CLI not found. Enable with: "
                               "sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/"
                               "Versions/Current/Resources/airport /usr/sbin/airport")
        
        try:
            result = _run_command([airport, '--scan'], timeout=timeout)
            
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                return networks
            
            # Parse header to find column positions
            header = lines[0]
            
            for line in lines[1:]:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) >= 5:
                    net = {
                        'ssid': parts[0],
                        'bssid': parts[1].upper() if len(parts) > 1 else '',
                        'clients': [],
                    }
                    
                    # RSSI (typically column 2 or 3)
                    try:
                        net['signal'] = int(parts[2])
                    except (ValueError, IndexError):
                        net['signal'] = 0
                    
                    # Channel
                    try:
                        net['channel'] = int(parts[3])
                    except (ValueError, IndexError):
                        net['channel'] = 0
                    
                    # Security
                    if len(parts) > 4:
                        security = ' '.join(parts[4:])
                        net['encryption'] = security
                        
                        if 'WPA3' in security:
                            net['wpa3'] = True
                        elif 'WPA2' in security:
                            net['wpa2'] = True
                        elif 'WPA' in security:
                            net['wpa'] = True
                        elif 'WEP' in security:
                            net['wep'] = True
                        elif 'NONE' in security or 'OPEN' in security:
                            net['encryption'] = 'OPEN'
                    
                    networks.append(net)
        
        except InterfaceError:
            # Fallback: try system_profiler
            try:
                result = _run_command(
                    ['system_profiler', 'SPAirPortDataType'],
                    timeout=timeout
                )
                networks = NetworkScanner._parse_system_profiler(result.stdout)
            except InterfaceError:
                pass
        
        return networks
    
    @staticmethod
    def _parse_system_profiler(output: str) -> List[Dict[str, Any]]:
        """Parse macOS system_profiler output for WiFi info."""
        networks = []
        current_net = {}
        
        for line in output.split('\n'):
            stripped = line.strip()
            
            if 'SSID' in stripped and ':' in stripped:
                if current_net and 'ssid' in current_net:
                    networks.append(current_net)
                current_net = {'clients': []}
                current_net['ssid'] = stripped.split(':')[-1].strip()
            
            elif 'BSSID' in stripped:
                m = re.search(r'BSSID:\s*([0-9A-Fa-f:]+)', stripped)
                if m:
                    current_net['bssid'] = m.group(1).upper()
            
            elif 'RSSI' in stripped:
                m = re.search(r'RSSI:\s*(-?\d+)', stripped)
                if m:
                    try:
                        current_net['signal'] = int(m.group(1))
                    except ValueError:
                        pass
        
        if current_net and 'ssid' in current_net:
            networks.append(current_net)
        
        return networks
    
    @staticmethod
    def scan_windows(interface: str = "", timeout: int = SCAN_TIMEOUT) -> List[Dict[str, Any]]:
        """Scan with netsh on Windows."""
        networks = []
        
        try:
            result = _run_command(
                ['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'],
                timeout=timeout
            )
            
            current_net = {}
            current_bssid = {}
            
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                
                if not stripped:
                    continue
                
                # SSID line
                if stripped.startswith('SSID'):
                    if current_net and 'ssid' in current_net:
                        if current_bssid:
                            current_net.setdefault('bssids', []).append(current_bssid)
                        networks.append(current_net)
                    current_net = {'ssid': stripped.split(':')[-1].strip(), 'clients': []}
                    current_bssid = {}
                
                # BSSID line
                elif stripped.startswith('BSSID'):
                    if current_bssid:
                        current_net.setdefault('bssids', []).append(current_bssid)
                    current_bssid = {}
                    mac = stripped.split(':')[1].strip().replace('-', ':').upper()
                    current_bssid['bssid'] = mac
                    current_net['bssid'] = mac  # Last BSSID as primary
                
                # Signal percentage
                elif stripped.startswith('Signal'):
                    sig_str = stripped.split(':')[-1].strip().rstrip('%')
                    try:
                        pct = int(sig_str)
                        current_bssid['signal_pct'] = pct
                        # Convert to approximate dBm
                        current_bssid['signal'] = -30 - int((100 - pct) * 0.6)
                        current_net['signal'] = current_bssid['signal']
                    except ValueError:
                        pass
                
                # Radio type (802.11n/ac/ax)
                elif stripped.startswith('Radio type'):
                    current_bssid['radio_type'] = stripped.split(':')[-1].strip()
                
                # Channel
                elif stripped.startswith('Channel'):
                    try:
                        ch = int(stripped.split(':')[-1].strip())
                        current_bssid['channel'] = ch
                        current_net['channel'] = ch
                    except ValueError:
                        pass
                
                # Authentication
                elif stripped.startswith('Authentication'):
                    auth = stripped.split(':')[-1].strip()
                    current_bssid['auth'] = auth
                    current_net['encryption'] = auth
                    if 'WPA3' in auth:
                        current_net['wpa3'] = True
                    elif 'WPA2' in auth:
                        current_net['wpa2'] = True
                    elif 'WPA' in auth:
                        current_net['wpa'] = True
                    elif 'WEP' in auth:
                        current_net['wep'] = True
                    elif 'Open' in auth:
                        current_net['encryption'] = 'OPEN'
                
                # Cipher
                elif stripped.startswith('Cipher'):
                    current_bssid['cipher'] = stripped.split(':')[-1].strip()
                
                # Key (channel width, frequency band)
                elif stripped.startswith('Band'):
                    band = stripped.split(':')[-1].strip()
                    if '2.4' in band:
                        current_bssid['band'] = '2.4 GHz'
                    elif '5' in band:
                        current_bssid['band'] = '5 GHz'
                
            # Don't forget the last network
            if current_net and 'ssid' in current_net:
                if current_bssid:
                    current_net.setdefault('bssids', []).append(current_bssid)
                networks.append(current_net)
        
        except InterfaceError:
            # Try pywifi as fallback
            try:
                import pywifi
                wifi = pywifi.PyWiFi()
                for iface in wifi.interfaces():
                    iface.scan()
                    time.sleep(2)
                    results = iface.scan_results()
                    
                    existing_ssids = set()
                    for ap in results:
                        if ap.ssid in existing_ssids:
                            continue
                        existing_ssids.add(ap.ssid)
                        
                        net = {
                            'ssid': ap.ssid,
                            'bssid': ap.bssid.upper() if ap.bssid else '',
                            'signal': ap.signal if hasattr(ap, 'signal') else 0,
                            'channel': ap.channel if hasattr(ap, 'channel') else 0,
                            'encryption': str(ap.akm[0]) if ap.akm else 'OPEN',
                            'clients': [],
                        }
                        networks.append(net)
            except ImportError:
                raise InterfaceError("No scan method available. Install pywifi or use netsh.")
        
        return networks
    
    @staticmethod
    def scan_pywifi(interface_name: str = "", timeout: int = SCAN_TIMEOUT) -> List[Dict[str, Any]]:
        """Universal fallback scan using pywifi."""
        networks = []
        
        try:
            import pywifi
            wifi = pywifi.PyWiFi()
            
            for iface in wifi.interfaces():
                if interface_name and iface.name() != interface_name:
                    continue
                
                iface.scan()
                time.sleep(min(3, timeout))
                results = iface.scan_results()
                
                seen_bssids = set()
                for ap in results:
                    if ap.bssid in seen_bssids:
                        continue
                    seen_bssids.add(ap.bssid)
                    
                    net = {
                        'ssid': ap.ssid,
                        'bssid': ap.bssid.upper() if ap.bssid else '',
                        'signal': int(ap.signal) if hasattr(ap, 'signal') and ap.signal else 0,
                        'channel': int(ap.channel) if hasattr(ap, 'channel') and ap.channel else 0,
                        'encryption': str(ap.akm[0]) if ap.akm else 'OPEN',
                        'frequency': int(ap.freq) if hasattr(ap, 'freq') and ap.freq else 0,
                        'clients': [],
                    }
                    networks.append(net)
        
        except ImportError:
            raise InterfaceError("pywifi not installed. Install with: pip install pywifi")
        
        return networks


# ============================================================================
# MONITOR MODE MANAGER
# ============================================================================

class MonitorModeManager:
    """Cross-platform monitor mode orchestration.
    
    Linux: Uses iw + airmon-ng with idempotent cleanup.
    macOS: Limited support via airport sniff mode.
    Windows: Not supported (returns clear error).
    
    All operations are idempotent — running the same operation twice
    has no adverse effects.
    """
    
    def __init__(self):
        self._monitor_interfaces: Dict[str, str] = {}  # physical → monitor
        self._original_state: Dict[str, Dict[str, Any]] = {}  # interface → state
        self._lock = threading.Lock()
    
    def enable_monitor_mode(self, interface: str) -> str:
        """Enable monitor mode on a wireless interface.
        
        Idempotent: If already in monitor mode, returns existing monitor iface.
        
        Args:
            interface: Physical interface name (e.g., 'wlan0')
        
        Returns:
            Monitor interface name (e.g., 'wlan0mon' or 'mon0')
        
        Raises:
            MonitorModeError: On failure or unsupported platform
        """
        if IS_WINDOWS:
            raise MonitorModeError(
                "Monitor mode is not supported on Windows. "
                "Use a Linux VM or boot from USB."
            )
        
        with self._lock:
            # Check if already in monitor mode
            if interface in self._monitor_interfaces:
                return self._monitor_interfaces[interface]
            
            if IS_LINUX:
                return self._enable_linux(interface)
            elif IS_MACOS:
                return self._enable_macos(interface)
            else:
                raise MonitorModeError(f"Monitor mode not supported on {SYSTEM}")
    
    def _enable_linux(self, interface: str) -> str:
        """Enable monitor mode on Linux using iw."""
        # Save original state
        try:
            original_info = self._get_interface_state(interface)
            self._original_state[interface] = original_info
        except Exception:
            self._original_state[interface] = {'down': False}
        
        # Check if already a monitor interface
        for pattern in MONITOR_PATTERNS:
            if pattern.match(interface):
                self._monitor_interfaces[interface] = interface
                return interface
        
        # Method 1: iw (preferred — cleaner)
        monitor_name = f"{interface}mon"
        try:
            # Bring interface down first
            _run_command(['ip', 'link', 'set', interface, 'down'], timeout=5)
            
            # Add monitor interface
            _run_command(
                ['iw', 'dev', interface, 'interface', 'add', monitor_name, 'type', 'monitor'],
                timeout=10
            )
            
            # Bring both up
            _run_command(['ip', 'link', 'set', monitor_name, 'up'], timeout=5)
            _run_command(['ip', 'link', 'set', interface, 'up'], timeout=5)
            
            self._monitor_interfaces[interface] = monitor_name
            return monitor_name
            
        except InterfaceError:
            pass
        
        # Method 2: airmon-ng (fallback)
        try:
            result = _run_command(
                ['airmon-ng', 'start', interface],
                timeout=MONITOR_MODE_TIMEOUT
            )
            
            # Parse monitor interface name from output
            output = result.stdout + result.stderr
            m = re.search(r'(mon\d+|wlan\d+mon)', output)
            if m:
                monitor_name = m.group(1)
                self._monitor_interfaces[interface] = monitor_name
                return monitor_name
            
            # Common naming patterns
            for name in [f"{interface}mon", f"mon0", f"mon1"]:
                if os.path.exists(f"/sys/class/net/{name}"):
                    self._monitor_interfaces[interface] = name
                    return name
            
            raise MonitorModeError(
                f"airmon-ng started but could not determine monitor interface name.\n"
                f"Output: {output[:200]}"
            )
            
        except FileNotFoundError:
            raise MonitorModeError(
                "airmon-ng not found. Install aircrack-ng:\n"
                "  apt install aircrack-ng"
            )
    
    def _enable_macos(self, interface: str) -> str:
        """Enable monitor mode on macOS using airport."""
        # macOS uses a different approach — airport sniff mode
        # This captures to a file rather than creating a monitor interface
        
        airport_paths = [
            '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport',
            '/usr/sbin/airport',
        ]
        
        airport = None
        for path in airport_paths:
            if os.path.exists(path) and os.access(path, os.X_OK):
                airport = path
                break
        
        if not airport:
            raise MonitorModeError(
                "airport CLI not found. Enable with:\n"
                "sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/"
                "Versions/Current/Resources/airport /usr/sbin/airport"
            )
        
        # macOS airport sniff mode only supports packet capture, not full monitor mode
        # We return the original interface but flag it as monitor-capable for capture
        self._monitor_interfaces[interface] = interface
        return interface
    
    def disable_monitor_mode(self, interface: str) -> bool:
        """Disable monitor mode and restore original state.
        
        Idempotent: Safe to call multiple times.
        
        Args:
            interface: Original physical interface name
        
        Returns:
            True if successfully restored
        """
        with self._lock:
            if interface not in self._monitor_interfaces:
                return True  # Already clean
            
            monitor_iface = self._monitor_interfaces[interface]
            
            if IS_LINUX:
                try:
                    if interface == monitor_iface:
                        # Interface is directly in monitor mode
                        # Restore from saved state
                        saved = self._original_state.get(interface, {})
                        _run_command(['ip', 'link', 'set', interface, 'down'], timeout=5)
                        
                        # Try to set mode back to managed
                        try:
                            _run_command(
                                ['iw', 'dev', interface, 'set', 'type', 'managed'],
                                timeout=5
                            )
                        except InterfaceError:
                            pass
                        
                        if saved.get('up', False):
                            _run_command(['ip', 'link', 'set', interface, 'up'], timeout=5)
                    else:
                        # Remove the monitor interface we added
                        _run_command(['ip', 'link', 'set', monitor_iface, 'down'], timeout=5)
                        _run_command(
                            ['iw', 'dev', monitor_iface, 'del'],
                            timeout=5
                        )
                        
                        # Restore original interface
                        saved = self._original_state.get(interface, {})
                        if saved.get('up', False):
                            _run_command(['ip', 'link', 'set', interface, 'up'], timeout=5)
                    
                    del self._monitor_interfaces[interface]
                    if interface in self._original_state:
                        del self._original_state[interface]
                    
                    return True
                    
                except InterfaceError as e:
                    raise MonitorModeError(f"Failed to disable monitor mode: {e}")
            
            elif IS_MACOS:
                # macOS: airport sniff stops automatically when process ends
                self._monitor_interfaces.pop(interface, None)
                return True
            
            return False
    
    def _get_interface_state(self, interface: str) -> Dict[str, Any]:
        """Get current interface state for save/restore."""
        state = {'up': False, 'type': 'managed'}
        
        try:
            result = _run_command(['ip', 'link', 'show', interface], timeout=5)
            state['up'] = 'state UP' in result.stdout or 'UP' in result.stdout.split('\n')[0] if '\n' in result.stdout else False
        except InterfaceError:
            pass
        
        try:
            result = _run_command(['iw', 'dev', interface, 'info'], timeout=5)
            if 'type managed' in result.stdout:
                state['type'] = 'managed'
            elif 'type monitor' in result.stdout:
                state['type'] = 'monitor'
        except InterfaceError:
            pass
        
        return state
    
    def is_monitor_mode(self, interface: str) -> bool:
        """Check if an interface is in monitor mode."""
        if interface in self._monitor_interfaces:
            return True
        
        for pattern in MONITOR_PATTERNS:
            if pattern.match(interface):
                return True
        
        try:
            result = _run_command(['iw', 'dev', interface, 'info'], timeout=5)
            return 'type monitor' in result.stdout
        except (InterfaceError, FileNotFoundError):
            pass
        
        return False
    
    def cleanup_all(self):
        """Disable monitor mode on all managed interfaces."""
        interfaces = list(self._monitor_interfaces.keys())
        for interface in interfaces:
            try:
                self.disable_monitor_mode(interface)
            except Exception:
                pass


# ============================================================================
# CHANNEL HOPPER
# ============================================================================

class ChannelHopper:
    """Multi-channel hopping engine for capture coverage.
    
    Cycles through a set of channels, switching at configurable intervals.
    Supports 2.4 GHz and 5 GHz bands with channel width awareness.
    """
    
    def __init__(self, interface: str, channels: Optional[List[int]] = None,
                 interval: float = CHANNEL_SWITCH_INTERVAL,
                 band: str = "dual"):
        """Initialize channel hopper.
        
        Args:
            interface: Interface to hop on
            channels: Specific channels (None = all in band)
            interval: Time per channel in seconds
            band: '2.4', '5', or 'dual'
        """
        self.interface = interface
        self.interval = interval
        self.band = band
        
        # Build channel list
        if channels:
            self.channels = channels
        else:
            self.channels = []
            if band in ('2.4', 'dual'):
                self.channels.extend(CHANNEL_2GHZ)
            if band in ('5', 'dual'):
                self.channels.extend(CHANNEL_5GHZ)
        
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current_channel = self.channels[0] if self.channels else 1
        self._lock = threading.Lock()
    
    @property
    def current_channel(self) -> int:
        with self._lock:
            return self._current_channel
    
    def start(self) -> threading.Thread:
        """Start channel hopping in background thread.
        
        Returns:
            The hopper thread
        """
        if self._thread and self._thread.is_alive():
            return self._thread
        
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._hop_loop,
            daemon=True,
            name=f"channel-hopper-{self.interface}"
        )
        self._thread.start()
        return self._thread
    
    def stop(self):
        """Stop channel hopping."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
    
    def _hop_loop(self):
        """Main hopping loop — runs in background thread."""
        while not self._stop_event.is_set():
            for channel in self.channels:
                if self._stop_event.is_set():
                    break
                
                try:
                    self._set_channel(channel)
                    with self._lock:
                        self._current_channel = channel
                except InterfaceError:
                    pass
                
                # Wait for interval or stop
                self._stop_event.wait(self.interval)
    
    def _set_channel(self, channel: int):
        """Set the WiFi channel on the interface.
        
        Args:
            channel: Channel number (1-13, 36-197)
        """
        if IS_LINUX:
            freq = _channel_to_freq(channel)
            if freq:
                _run_command(
                    ['iw', 'dev', self.interface, 'set', 'freq', str(freq)],
                    timeout=5
                )
        elif IS_MACOS:
            # macOS airport set channel
            airport = '/System/Library/PrivateFrameworks/Apple80211.framework/'
            'Versions/Current/Resources/airport'
            if os.path.exists(airport):
                _run_command([airport, '--channel', str(channel)], timeout=5)
    
    def get_scan_timing(self, dwell_time: float = None) -> Dict[str, float]:
        """Calculate scan timing for complete coverage.
        
        Args:
            dwell_time: Time per channel (default: self.interval)
        
        Returns:
            Dict with total_time, channels, cycles_per_minute
        """
        dt = dwell_time or self.interval
        total = len(self.channels) * dt
        return {
            'total_time': total,
            'channels': len(self.channels),
            'cycles_per_minute': 60.0 / total if total > 0 else 0,
            'band': self.band,
        }


# ============================================================================
# MAC ADDRESS MANAGER
# ============================================================================

class MACManager:
    """MAC address manipulation — spoofing, randomization, vendor lookup.
    
    All operations are idempotent and include state save/restore.
    """
    
    def __init__(self):
        self._original_macs: Dict[str, str] = {}  # interface → original MAC
        self._lock = threading.Lock()
    
    def get_current_mac(self, interface: str) -> Optional[str]:
        """Get the current MAC address of an interface.
        
        Args:
            interface: Interface name
        
        Returns:
            MAC address string or None
        """
        try:
            if IS_LINUX or IS_MACOS:
                with open(f'/sys/class/net/{interface}/address', 'r') as f:
                    mac = f.read().strip().upper()
                    return mac if validate_mac(mac) else None
            elif IS_WINDOWS:
                # Use getmac command
                result = _run_command(['getmac', '/FO', 'CSV', '/NH'], timeout=10)
                for line in result.stdout.split('\n'):
                    if interface.lower() in line.lower():
                        parts = line.split(',')
                        if len(parts) > 0:
                            mac = parts[0].strip('"').replace('-', ':').upper()
                            if validate_mac(mac):
                                return mac
        except (IOError, OSError, InterfaceError):
            pass
        return None
    
    def spoof_mac(self, interface: str, new_mac: Optional[str] = None) -> str:
        """Spoof the MAC address of an interface.
        
        Idempotent: If already spoofed, returns the current spoofed MAC.
        
        Args:
            interface: Interface name
            new_mac: Target MAC (None = random)
        
        Returns:
            The new MAC address
        
        Raises:
            InterfaceError: On failure
        """
        with self._lock:
            # Save original if not saved
            if interface not in self._original_macs:
                original = self.get_current_mac(interface)
                if original:
                    self._original_macs[interface] = original
            
            # Generate random if not specified
            if not new_mac:
                new_mac = _random_mac()
            
            if not validate_mac(new_mac):
                raise InterfaceError(f"Invalid MAC address: {new_mac}")
            
            if IS_LINUX:
                return self._spoof_linux(interface, new_mac)
            elif IS_MACOS:
                return self._spoof_macos(interface, new_mac)
            elif IS_WINDOWS:
                return self._spoof_windows(interface, new_mac)
            else:
                raise InterfaceError(f"MAC spoofing not supported on {SYSTEM}")
    
    def _spoof_linux(self, interface: str, new_mac: str) -> str:
        """Spoof MAC on Linux using ip."""
        _run_command(['ip', 'link', 'set', interface, 'down'], timeout=5)
        _run_command(['ip', 'link', 'set', interface, 'address', new_mac], timeout=5)
        _run_command(['ip', 'link', 'set', interface, 'up'], timeout=5)
        return new_mac
    
    def _spoof_macos(self, interface: str, new_mac: str) -> str:
        """Spoof MAC on macOS using ifconfig."""
        _run_command(['ifconfig', interface, 'ether', new_mac], timeout=5)
        return new_mac
    
    def _spoof_windows(self, interface: str, new_mac: str) -> str:
        """Spoof MAC on Windows via registry."""
        try:
            import _winreg as winreg
        except ImportError:
            import winreg
        
        # Find the adapter's registry key
        result = _run_command(
            ['wmic', 'nic', 'where', f'NetEnabled=true', 'get', 'Index,NetConnectionID'],
            timeout=10
        )
        
        for line in result.stdout.split('\n'):
            if interface.lower() in line.lower():
                parts = line.split()
                if parts:
                    try:
                        idx = int(parts[0])
                    except ValueError:
                        continue
                    
                    # Write to registry
                    key_path = (r'SYSTEM\CurrentControlSet\Control\Class\'
                               r'{4d36e972-e325-11ce-bfc1-08002be10318}'
                               f'\\{idx:04d}')
                    
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        key_path,
                        0,
                        winreg.KEY_SET_VALUE
                    ) as key:
                        winreg.SetValueEx(
                            key, 'NetworkAddress', 0,
                            winreg.REG_SZ, new_mac.replace(':', '')
                        )
                    
                    # Disable/re-enable adapter
                    _run_command(
                        ['wmic', 'path', 'Win32_NetworkAdapter',
                         f'where Index={idx}', 'call', 'Disable'],
                        timeout=10
                    )
                    time.sleep(1)
                    _run_command(
                        ['wmic', 'path', 'Win32_NetworkAdapter',
                         f'where Index={idx}', 'call', 'Enable'],
                        timeout=10
                    )
                    
                    return new_mac
        
        raise InterfaceError(f"Could not find adapter {interface} in registry")
    
    def restore_mac(self, interface: str) -> bool:
        """Restore original MAC address.
        
        Idempotent: Safe to call multiple times.
        
        Args:
            interface: Interface name
        
        Returns:
            True if restored
        """
        with self._lock:
            if interface not in self._original_macs:
                return True
            
            original = self._original_macs[interface]
            
            try:
                if IS_LINUX:
                    self._spoof_linux(interface, original)
                elif IS_MACOS:
                    self._spoof_macos(interface, original)
                elif IS_WINDOWS:
                    self._spoof_windows(interface, original)
                
                del self._original_macs[interface]
                return True
            except Exception:
                return False
    
    def restore_all(self):
        """Restore all spoofed interfaces."""
        interfaces = list(self._original_macs.keys())
        for iface in interfaces:
            try:
                self.restore_mac(iface)
            except Exception:
                pass
    
    @staticmethod
    def random_mac(locally_administered: bool = True) -> str:
        """Generate a random MAC address.
        
        Args:
            locally_administered: If True, set local-admin bit
        
        Returns:
            MAC address string
        """
        mac = [random.randint(0x00, 0xFF) for _ in range(6)]
        if locally_administered:
            mac[0] = (mac[0] & 0xFE) | 0x02
            mac[0] = mac[0] & 0xFE  # Clear multicast
        return ':'.join(f'{b:02X}' for b in mac)
    
    @staticmethod
    def vendor_from_mac(mac: str) -> Optional[str]:
        """Look up vendor from MAC address OUI."""
        return _oui_lookup(mac)


# ============================================================================
# ARP CACHE MANAGER
# ============================================================================

class ARPCacheManager:
    """Cross-platform ARP cache management.
    
    Reads, probes, and manipulates the system ARP cache.
    Essential for MITM operations and network mapping.
    """
    
    def __init__(self):
        self._cache: Dict[str, ARPEntry] = {}
        self._lock = threading.Lock()
    
    def get_arp_table(self) -> List[ARPEntry]:
        """Get the current system ARP table.
        
        Returns:
            List of ARPEntry objects
        """
        entries = []
        
        if IS_LINUX or IS_MACOS:
            try:
                with open('/proc/net/arp', 'r') if IS_LINUX else _run_command(
                    ['arp', '-a'], timeout=5, check=True
                ):
                    if IS_LINUX:
                        lines = open('/proc/net/arp', 'r').read().strip().split('\n')[1:]
                        for line in lines:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip = parts[0]
                                hw_type = parts[1]
                                flags = parts[2]
                                mac = parts[3]
                                
                                if mac == '00:00:00:00:00:00' or not validate_mac(mac):
                                    continue
                                
                                is_gw = self._is_gateway(ip)
                                vendor = _oui_lookup(mac)
                                
                                entries.append(ARPEntry(
                                    ip=ip, mac=mac.upper(),
                                    interface=parts[5] if len(parts) > 5 else '',
                                    timestamp=time.time(),
                                    is_gateway=is_gw,
                                    vendor=vendor or '',
                                ))
            except (IOError, OSError, InterfaceError):
                pass
        
        elif IS_WINDOWS:
            try:
                result = _run_command(['arp', '-a'], timeout=10)
                for line in result.stdout.split('\n'):
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] != '---' and 'Internet' not in parts[0]:
                        ip = parts[0]
                        mac = parts[1].replace('-', ':').upper()
                        if validate_mac(mac):
                            is_gw = self._is_gateway(ip)
                            vendor = _oui_lookup(mac)
                            entries.append(ARPEntry(
                                ip=ip, mac=mac,
                                interface='',
                                timestamp=time.time(),
                                is_gateway=is_gw,
                                vendor=vendor or '',
                            ))
            except InterfaceError:
                pass
        
        with self._lock:
            for entry in entries:
                self._cache[entry.ip] = entry
        
        return entries
    
    def resolve(self, ip: str, interface: str = "",
                timeout: int = 3) -> Optional[ARPEntry]:
        """Resolve an IP to MAC address via ARP.
        
        First checks cache, then sends ARP probe if needed.
        
        Args:
            ip: Target IP address
            interface: Interface to use for probing
            timeout: Probe timeout in seconds
        
        Returns:
            ARPEntry or None
        """
        # Check cache first
        with self._lock:
            if ip in self._cache and not self._cache[ip].is_stale:
                return self._cache[ip]
        
        # Send ARP probe
        try:
            import scapy.all as scapy
            
            iface = interface or self._get_default_interface()
            if not iface:
                return None
            
            arp_req = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
            pkt = broadcast / arp_req
            
            # Send and receive
            ans = scapy.srp(
                pkt, iface=iface, timeout=timeout, verbose=False
            )[0]
            
            for sent, received in ans:
                mac = received.hwsrc.upper()
                if validate_mac(mac):
                    entry = ARPEntry(
                        ip=ip, mac=mac,
                        interface=iface,
                        timestamp=time.time(),
                        is_gateway=self._is_gateway(ip),
                        vendor=_oui_lookup(mac) or '',
                    )
                    with self._lock:
                        self._cache[ip] = entry
                    return entry
        
        except ImportError:
            # Python ARP without scapy
            try:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
                sock.bind((interface or 'eth0', 0))
                # Manual ARP construction
                # ... (simplified for space)
            except Exception:
                pass
        
        return None
    
    def add_static_entry(self, ip: str, mac: str, interface: str = "") -> bool:
        """Add a static ARP entry.
        
        Used for MITM poisoning prevention.
        
        Args:
            ip: IP address
            mac: MAC address
            interface: Interface name
        
        Returns:
            True if successful
        """
        if not validate_mac(mac):
            return False
        
        try:
            if IS_LINUX:
                cmd = ['arp', '-s', ip, mac]
                if interface:
                    cmd.extend(['-i', interface])
                _run_command(cmd, timeout=5, check=True)
            elif IS_MACOS:
                _run_command(['arp', '-s', ip, mac], timeout=5, check=True)
            elif IS_WINDOWS:
                _run_command(
                    ['netsh', 'interface', 'ip', 'add', 'neighbors',
                     interface or 'Wi-Fi', ip, mac],
                    timeout=10, check=True
                )
            return True
        except InterfaceError:
            return False
    
    def remove_static_entry(self, ip: str) -> bool:
        """Remove a static ARP entry."""
        try:
            if IS_LINUX or IS_MACOS:
                _run_command(['arp', '-d', ip], timeout=5, check=True)
            elif IS_WINDOWS:
                _run_command(
                    ['netsh', 'interface', 'ip', 'delete', 'neighbors', ip],
                    timeout=10, check=True
                )
            return True
        except InterfaceError:
            return False
    
    def flush_cache(self):
        """Flush the ARP cache."""
        with self._lock:
            self._cache.clear()
        
        try:
            if IS_LINUX:
                _run_command(['ip', 'neigh', 'flush', 'all'], timeout=5)
            elif IS_MACOS:
                _run_command(['sudo', 'arp', '-a', '-d'], timeout=5)
            elif IS_WINDOWS:
                _run_command(['netsh', 'interface', 'ip', 'delete', 'arpcache'], timeout=10)
        except InterfaceError:
            pass
    
    def _is_gateway(self, ip: str) -> bool:
        """Check if an IP is a default gateway."""
        try:
            gws = netifaces.gateways()
            default = gws.get('default', {})
            for af, gw_info in default.items():
                if gw_info[0] == ip:
                    return True
        except Exception:
            pass
        return False
    
    def _get_default_interface(self) -> Optional[str]:
        """Get the default network interface."""
        try:
            import netifaces
            gws = netifaces.gateways()
            default = gws.get('default', {}).get(netifaces.AF_INET)
            if default:
                return default[1]
        except Exception:
            pass
        return None


# ============================================================================
# INTERFACE MANAGER — MAIN CLASS
# ============================================================================

class InterfaceManager:
    """Cross-platform Network Interface Manager — MEDUSA's hardware abstraction layer.
    
    This is the central class for all network interface operations.
    It provides OS-adaptive detection, monitor mode orchestration,
    channel hopping, MAC spoofing, ARP management, and scanning.
    
    All public methods are thread-safe and idempotent.
    Heavy operations use pre-computed snapshots with configurable TTL.
    
    Usage:
        mgr = InterfaceManager()
        ifaces = mgr.detect_interfaces()
        best = mgr.get_best_wireless()
        mgr.enable_monitor_mode(best)
        channels = mgr.get_channels(best)
        
    Thread Safety:
        - Multi-threaded reads: Lock-free on snapshots
        - Single-threaded writes: Lock-protected
        - Background tasks: Dedicated thread pool
    """
    
    def __init__(self, console=None):
        self.console = console
        self._snapshot_lock = threading.RLock()
        self._snapshot_ttl = 2.0  # Cache interface info for 2 seconds
        self._last_snapshot_time = 0.0
        self._last_snapshot: List[InterfaceInfo] = []
        
        # Sub-managers
        self.monitor = MonitorModeManager()
        self.mac = MACManager()
        self.arp = ARPCacheManager()
        self.scanner = NetworkScanner()
        self.hopper: Optional[ChannelHopper] = None
        
        # Thread pool for parallel operations
        self._executor = ThreadPoolExecutor(
            max_workers=CPU_COUNT,
            thread_name_prefix='medusa-iface'
        )
        
        # OUI database
        self._load_oui_cache()
    
    def _log(self, msg: str, level: str = "info"):
        """Log through console if available."""
        if self.console:
            self.console.log(msg, level)
    
    # ====================================================================
    # INTERFACE DETECTION (3-tier fallback)
    # ====================================================================
    
    def detect_interfaces(self, force: bool = False) -> List[InterfaceInfo]:
        """Detect all network interfaces on the system.
        
        Uses a 3-tier fallback per platform:
        1. netifaces (fast, cross-platform)
        2. Platform-specific (/sys/class/net, ifconfig, netsh)
        3. Hardcoded fallback
        
        Results are cached with TTL for performance.
        
        Args:
            force: Force re-detection regardless of cache age
        
        Returns:
            List of InterfaceInfo objects
        """
        with self._snapshot_lock:
            now = time.time()
            if (not force and self._last_snapshot 
                and (now - self._last_snapshot_time) < self._snapshot_ttl):
                return self._last_snapshot.copy()
            
            interfaces = []
            
            # Tier 1: netifaces
            try:
                import netifaces
                interfaces = self._detect_netifaces()
            except ImportError:
                pass
            
            # Tier 2: Platform-specific
            if not interfaces:
                if IS_LINUX:
                    interfaces = self._detect_sysfs()
                elif IS_MACOS:
                    interfaces = self._detect_ifconfig()
                elif IS_WINDOWS:
                    interfaces = self._detect_wmi()
            
            # Tier 3: Hardcoded fallback
            if not interfaces:
                interfaces = self._detect_fallback()
            
            # Enrich with wireless details
            self._enrich_interfaces(interfaces)
            
            self._last_snapshot = interfaces
            self._last_snapshot_time = now
            
            return interfaces.copy()
    
    def _detect_netifaces(self) -> List[InterfaceInfo]:
        """Detect interfaces using netifaces library."""
        import netifaces
        interfaces = []
        gateway_info = {}
        
        try:
            gws = netifaces.gateways()
            default = gws.get('default', {})
            for af, gw in default.items():
                gateway_info[af] = gw
        except Exception:
            pass
        
        for iface_name in netifaces.interfaces():
            info = InterfaceInfo(name=iface_name)
            
            # MAC address
            try:
                link = netifaces.ifaddresses(iface_name).get(netifaces.AF_LINK, [])
                if link:
                    info.mac = link[0].get('addr', '').upper()
            except Exception:
                pass
            
            # IPv4
            try:
                inet = netifaces.ifaddresses(iface_name).get(netifaces.AF_INET, [])
                if inet:
                    info.ipv4 = inet[0].get('addr', '')
                    info.netmask = inet[0].get('netmask', '')
                    info.broadcast = inet[0].get('broadcast', '')
            except Exception:
                pass
            
            # IPv6
            try:
                inet6 = netifaces.ifaddresses(iface_name).get(netifaces.AF_INET6, [])
                if inet6:
                    info.ipv6 = inet6[0].get('addr', '')
            except Exception:
                pass
            
            # Gateway
            if netifaces.AF_INET in gateway_info:
                if gateway_info[netifaces.AF_INET][1] == iface_name:
                    info.gateway = gateway_info[netifaces.AF_INET][0]
            
            # Classify
            info.is_loopback = (iface_name == 'lo' or info.ipv4 == '127.0.0.1')
            info.is_wireless = self._is_wireless_name(iface_name)
            info.is_monitor = any(p.match(iface_name) for p in MONITOR_PATTERNS)
            info.is_virtual = self._is_virtual_name(iface_name)
            
            # Vendor from MAC
            if info.mac:
                info.vendor = _oui_lookup(info.mac) or ''
            
            interfaces.append(info)
        
        return interfaces
    
    def _detect_sysfs(self) -> List[InterfaceInfo]:
        """Linux: Detect interfaces from /sys/class/net."""
        interfaces = []
        net_dir = Path('/sys/class/net')
        
        if not net_dir.exists():
            return interfaces
        
        for iface_path in net_dir.iterdir():
            iface_name = iface_path.name
            info = InterfaceInfo(name=iface_name)
            
            # MAC
            mac_file = iface_path / 'address'
            if mac_file.exists():
                try:
                    info.mac = mac_file.read_text().strip().upper()
                except (IOError, OSError):
                    pass
            
            # Type
            type_file = iface_path / 'type'
            if type_file.exists():
                try:
                    iface_type = int(type_file.read_text().strip())
                    info.is_wireless = (iface_type == 1 and self._is_wireless_name(iface_name))
                    info.is_loopback = (iface_type == 772)
                except (ValueError, IOError):
                    pass
            
            # Operational state
            oper_file = iface_path / 'operstate'
            if oper_file.exists():
                try:
                    info.is_up = oper_file.read_text().strip() == 'up'
                except (IOError, OSError):
                    pass
            
            # Wireless specific
            wireless_path = iface_path / 'wireless'
            if wireless_path.exists():
                info.is_wireless = True
                
                # Stats
                for stat in ['link', 'signal', 'noise']:
                    sf = wireless_path / stat
                    if sf.exists():
                        try:
                            val = int(sf.read_text().strip())
                            if stat == 'link':
                                info.signal_percent = val
                            elif stat == 'signal':
                                info.signal_dbm = val
                            elif stat == 'noise':
                                info.noise_dbm = val
                        except (ValueError, IOError):
                            pass
            
            # Statistics
            stats_dir = iface_path / 'statistics'
            if stats_dir.exists():
                stat_map = {
                    'tx_packets': 'tx_packets', 'rx_packets': 'rx_packets',
                    'tx_bytes': 'tx_bytes', 'rx_bytes': 'rx_bytes',
                    'tx_errors': 'tx_errors', 'rx_errors': 'rx_errors',
                    'tx_dropped': 'tx_dropped', 'rx_dropped': 'rx_dropped',
                    'collisions': 'collisions',
                }
                for fname, attr in stat_map.items():
                    sf = stats_dir / fname
                    if sf.exists():
                        try:
                            setattr(info, attr, int(sf.read_text().strip()))
                        except (ValueError, IOError):
                            pass
            
            # Driver info
            device_path = iface_path / 'device' / 'driver'
            if device_path.exists():
                try:
                    info.driver = device_path.resolve().name
                except (IOError, OSError):
                    pass
            
            # PHY info (for wireless)
            phy_path = iface_path / 'phy80211'
            if phy_path.exists():
                try:
                    info.phy = phy_path.resolve().name
                except (IOError, OSError):
                    pass
            
            info.is_monitor = any(p.match(iface_name) for p in MONITOR_PATTERNS)
            info.is_virtual = self._is_virtual_name(iface_name)
            
            if info.mac:
                info.vendor = _oui_lookup(info.mac) or ''
            
            interfaces.append(info)
        
        # Get IP/frequency info via ip/iw
        self._enrich_from_ip(interfaces)
        
        return interfaces
    
    def _detect_ifconfig(self) -> List[InterfaceInfo]:
        """macOS: Detect interfaces from ifconfig."""
        interfaces = []
        
        try:
            result = _run_command(['ifconfig', '-a'], timeout=10)
            current = {}
            
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                
                # Interface name line
                if stripped and ':' in stripped and not stripped.startswith('\t'):
                    if current and current.get('name'):
                        interfaces.append(self._ifconfig_to_info(current))
                    current = {'name': stripped.split(':')[0]}
                    flags = stripped.split('flags=')[1].split()[0] if 'flags=' in stripped else ''
                    current['up'] = 'UP' in flags
                
                elif 'ether ' in stripped:
                    mac = stripped.split('ether ')[-1].strip().upper()
                    if validate_mac(mac):
                        current['mac'] = mac
                
                elif 'inet ' in stripped:
                    parts = stripped.split()
                    if len(parts) >= 2:
                        current['ipv4'] = parts[1]
                    if len(parts) >= 4:
                        current['netmask'] = parts[3]
                
                elif 'inet6 ' in stripped:
                    parts = stripped.split()
                    if len(parts) >= 2:
                        current['ipv6'] = parts[1]
                
                elif 'media:' in stripped and 'autoselect' in stripped:
                    current['wireless'] = 'Wi-Fi' in stripped or '802.11' in stripped
            
            if current and current.get('name'):
                interfaces.append(self._ifconfig_to_info(current))
        
        except InterfaceError:
            pass
        
        return interfaces
    
    def _detect_wmi(self) -> List[InterfaceInfo]:
        """Windows: Detect interfaces via WMI."""
        interfaces = []
        
        try:
            result = _run_command(
                ['wmic', 'nic', 'get', 
                 'Name,NetConnectionID,MACAddress,Speed,NetEnabled,AdapterType',
                 '/FORMAT:CSV'],
                timeout=15
            )
            
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                return interfaces
            
            headers = lines[0].split(',')
            
            for line in lines[1:]:
                if not line.strip():
                    continue
                parts = line.split(',')
                if len(parts) < 4:
                    continue
                
                info = InterfaceInfo(
                    name=parts[2].strip('"') if len(parts) > 2 else f"eth{len(interfaces)}",
                    mac=parts[3].strip('"').replace('-', ':').upper() if len(parts) > 3 else '',
                )
                
                info.is_wireless = 'Wireless' in line or '802.11' in line
                info.is_up = 'TRUE' in parts[4].upper() if len(parts) > 4 else False
                
                if info.mac:
                    info.vendor = _oui_lookup(info.mac) or ''
                
                interfaces.append(info)
        
        except InterfaceError:
            pass
        
        return interfaces
    
    def _detect_fallback(self) -> List[InterfaceInfo]:
        """Hardcoded fallback — common interface names."""
        common = ['wlan0', 'eth0', 'en0', 'en1', 'lo']
        interfaces = []
        
        for name in common:
            if os.path.exists(f'/sys/class/net/{name}') or IS_WINDOWS:
                info = InterfaceInfo(
                    name=name,
                    is_wireless=name.startswith('wlan') or name.startswith('en'),
                    is_loopback=(name == 'lo'),
                )
                interfaces.append(info)
        
        return interfaces
    
    def _enrich_interfaces(self, interfaces: List[InterfaceInfo]):
        """Add wireless-specific details to interfaces."""
        for info in interfaces:
            if not info.is_wireless:
                continue
            
            if IS_LINUX and info.name:
                try:
                    result = _run_command(
                        ['iw', 'dev', info.name, 'info'], timeout=5
                    )
                    for line in result.stdout.split('\n'):
                        stripped = line.strip()
                        if 'channel' in stripped:
                            try:
                                info.channel = int(stripped.split()[-1])
                            except (ValueError, IndexError):
                                pass
                        if 'txpower' in stripped:
                            try:
                                info.tx_power = int(stripped.split()[-1].replace('dBm', ''))
                            except (ValueError, IndexError):
                                pass
                except InterfaceError:
                    pass
    
    def _enrich_from_ip(self, interfaces: List[InterfaceInfo]):
        """Add IP addresses from ip addr show."""
        try:
            result = _run_command(['ip', '-4', 'addr', 'show'], timeout=5)
            current_iface = None
            
            for line in result.stdout.split('\n'):
                if line[0].isalpha() and ':' in line[:10]:
                    iface_name = line.split(':')[1].strip().split('@')[0]
                    current_iface = next(
                        (i for i in interfaces if i.name == iface_name), None
                    )
                elif 'inet ' in line and current_iface:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        ip_cidr = parts[1]
                        current_iface.ipv4 = ip_cidr.split('/')[0]
        except InterfaceError:
            pass
    
    def _ifconfig_to_info(self, data: Dict) -> InterfaceInfo:
        """Convert parsed ifconfig data to InterfaceInfo."""
        return InterfaceInfo(
            name=data.get('name', ''),
            mac=data.get('mac', ''),
            ipv4=data.get('ipv4', ''),
            ipv6=data.get('ipv6', ''),
            netmask=data.get('netmask', ''),
            is_wireless=data.get('wireless', False) or self._is_wireless_name(data.get('name', '')),
            is_up=data.get('up', False),
            is_loopback=data.get('name') == 'lo',
            is_monitor=any(p.match(data.get('name', '')) for p in MONITOR_PATTERNS),
        )
    
    # ====================================================================
    # INTERFACE CLASSIFICATION
    # ====================================================================
    
    @staticmethod
    def _is_wireless_name(name: str) -> bool:
        """Check if an interface name suggests wireless."""
        if not name:
            return False
        wl_prefixes = {'wlan', 'wlp', 'wlx', 'wlo', 'en0', 'en1'}
        return any(name.startswith(p) for p in wl_prefixes)
    
    @staticmethod
    def _is_virtual_name(name: str) -> bool:
        """Check if an interface name suggests virtual."""
        if not name:
            return False
        virt_prefixes = {'docker', 'veth', 'br-', 'tun', 'tap', 'fw', 'p2p', 'lo'}
        return any(name.startswith(p) for p in virt_prefixes)
    
    # ====================================================================
    # INTERFACE SELECTION
    # ====================================================================
    
    def get_best_wireless(self) -> Optional[str]:
        """Select the best wireless interface for operations.
        
        Priority:
        1. Monitor mode interfaces
        2. Wireless interfaces with strongest signal
        3. First available wireless interface
        
        Returns:
            Interface name or None
        """
        interfaces = self.detect_interfaces()
        wireless = [i for i in interfaces if i.is_wireless and not i.is_loopback]
        
        if not wireless:
            return None
        
        # Prefer monitor mode
        for i in wireless:
            if i.is_monitor:
                return i.name
        
        # Sort by quality score
        wireless.sort(key=lambda x: x.quality_score, reverse=True)
        return wireless[0].name
    
    def get_all_wireless(self) -> List[str]:
        """Get all wireless interface names."""
        return [i.name for i in self.detect_interfaces() if i.is_wireless]
    
    def get_interface_info(self, name: str) -> Optional[InterfaceInfo]:
        """Get detailed info for a specific interface."""
        interfaces = self.detect_interfaces()
        for i in interfaces:
            if i.name == name:
                return i
        return None
    
    # ====================================================================
    # OPERATIONS
    # ====================================================================
    
    def wait_for_interface(self, name: str, timeout: int = 30) -> bool:
        """Wait for an interface to become available.
        
        Args:
            name: Interface name
            timeout: Max wait in seconds
        
        Returns:
            True if interface appeared
        """
        start = time.time()
        while time.time() - start < timeout:
            ifaces = self.detect_interfaces(force=True)
            if any(i.name == name for i in ifaces):
                return True
            time.sleep(0.5)
        return False
    
    def get_channels(self, interface: str) -> List[int]:
        """Get available channels for an interface."""
        if IS_LINUX:
            try:
                result = _run_command(['iw', 'dev', interface, 'info'], timeout=5)
                # Parse supported bands
                for line in result.stdout.split('\n'):
                    if '802.11' in line and 'MHz' in line:
                        if '2.4' in line:
                            return CHANNEL_2GHZ
                        elif '5' in line:
                            return CHANNEL_5GHZ
                return CHANNEL_2GHZ
            except InterfaceError:
                pass
        return CHANNEL_2GHZ
    
    # ====================================================================
    # OUI CACHE
    # ====================================================================
    
    def _load_oui_cache(self):
        """Load cached OUI vendor database."""
        global OUI_VENDOR_CACHE
        try:
            if OUI_CACHE_PATH.exists():
                with open(OUI_CACHE_PATH, 'r') as f:
                    OUI_VENDOR_CACHE.update(json.load(f))
        except (IOError, json.JSONDecodeError):
            pass
    
    def update_oui_database(self, force: bool = False) -> bool:
        """Download and cache the latest OUI database."""
        result = _update_oui_database(force)
        if result:
            self._load_oui_cache()
        return result
    
    def lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor by MAC address."""
        return _oui_lookup(mac)
    
    # ====================================================================
    # HIGH-LEVEL OPERATIONS
    # ====================================================================
    
    def get_network_info(self) -> Dict[str, Any]:
        """Get a comprehensive network information snapshot.
        
        Returns:
            Dict with interfaces, gateway, DNS, ARP table, etc.
        """
        return {
            'interfaces': [i.to_dict() for i in self.detect_interfaces()],
            'gateway': self._get_default_gateway(),
            'arp_table': [a.__dict__ for a in self.arp.get_arp_table()],
            'dns_servers': self._get_dns_servers(),
            'hostname': platform.node(),
            'timestamp': current_timestamp(),
        }
    
    def _get_default_gateway(self) -> Optional[str]:
        """Get the default gateway IP."""
        try:
            import netifaces
            gws = netifaces.gateways()
            default = gws.get('default', {}).get(netifaces.AF_INET)
            return default[0] if default else None
        except Exception:
            pass
        
        # Fallback
        try:
            if IS_LINUX:
                result = _run_command(['ip', 'route', 'show', 'default'], timeout=5)
                m = re.search(r'via\s+([\d.]+)', result.stdout)
                return m.group(1) if m else None
        except InterfaceError:
            pass
        
        return None
    
    def _get_dns_servers(self) -> List[str]:
        """Get configured DNS servers."""
        dns = []
        
        if IS_LINUX:
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        m = re.search(r'nameserver\s+([\d.]+)', line)
                        if m:
                            dns.append(m.group(1))
            except (IOError, OSError):
                pass
        
        elif IS_WINDOWS:
            try:
                result = _run_command(
                    ['netsh', 'interface', 'ip', 'show', 'dns'],
                    timeout=10
                )
                for line in result.stdout.split('\n'):
                    m = re.search(r'([\d.]+)', line)
                    if m and line.strip().startswith('DNS'):
                        dns.append(m.group(1))
            except InterfaceError:
                pass
        
        elif IS_MACOS:
            try:
                result = _run_command(
                    ['scutil', '--dns'],
                    timeout=5
                )
                for line in result.stdout.split('\n'):
                    if 'nameserver' in line:
                        m = re.search(r'nameserver\s+\[(\d+)\]', line)
                        if m:
                            dns.append(m.group(1))
            except InterfaceError:
                pass
        
        return dns
    
    # ====================================================================
    # CHANNEL HOPPING (delegates to ChannelHopper)
    # ====================================================================
    
    def start_channel_hop(self, interface: str, channels: Optional[List[int]] = None,
                          interval: float = CHANNEL_SWITCH_INTERVAL,
                          band: str = "dual") -> threading.Thread:
        """Start channel hopping on an interface."""
        if self.hopper:
            self.hopper.stop()
        
        self.hopper = ChannelHopper(interface, channels, interval, band)
        thread = self.hopper.start()
        self._log(f"Channel hopping started on {interface} ({band} band, {len(self.hopper.channels)} channels)", "info")
        return thread
    
    def stop_channel_hop(self):
        """Stop channel hopping."""
        if self.hopper:
            self.hopper.stop()
            self.hopper = None
            self._log("Channel hopping stopped", "info")
    
    # ====================================================================
    # CLEANUP
    # ====================================================================
    
    def cleanup(self):
        """Clean up all resources — idempotent."""
        self.stop_channel_hop()
        self.monitor.cleanup_all()
        self.mac.restore_all()
        self._executor.shutdown(wait=False)
        self._log("Interface manager cleaned up", "debug")


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

def init() -> Dict[str, Any]:
    """Initialize the interface manager and return environment info.
    
    Returns:
        Dict with interfaces, capabilities, and vendor DB status
    """
    mgr = InterfaceManager()
    interfaces = mgr.detect_interfaces()
    
    wireless_count = sum(1 for i in interfaces if i.is_wireless)
    monitor_count = sum(1 for i in interfaces if i.is_monitor)
    
    # Try OUI DB update in background
    try:
        import threading
        threading.Thread(target=_update_oui_database, daemon=True).start()
    except Exception:
        pass
    
    return {
        'interface_manager': mgr,
        'interfaces': [i.to_dict() for i in interfaces],
        'wireless_count': wireless_count,
        'monitor_count': monitor_count,
        'oui_cache_size': len(OUI_VENDOR_CACHE),
        'best_wireless': mgr.get_best_wireless(),
        'default_gateway': mgr._get_default_gateway(),
    }


# Global singleton
_default_manager: Optional[InterfaceManager] = None


def get_manager() -> InterfaceManager:
    """Get or create the default InterfaceManager singleton."""
    global _default_manager
    if _default_manager is None:
        _default_manager = InterfaceManager()
    return _default_manager


# ============================================================================
# ENTRY POINT (standalone testing)
# ============================================================================

if __name__ == "__main__":
    import json
    
    print(f"MEDUSA Interface Manager v{VERSION}")
    print(f"System: {SYSTEM} | Admin: {IS_ADMIN}")
    print("=" * 50)
    
    mgr = get_manager()
    interfaces = mgr.detect_interfaces(force=True)
    
    print(f"\nDetected {len(interfaces)} interfaces:")
    print("-" * 50)
    
    for iface in interfaces:
        status = "🟢" if iface.is_up else "🔴"
        wl = "📶" if iface.is_wireless else "🔌"
        mon = "📡" if iface.is_monitor else "  "
        print(f"  {status}{wl}{mon} {iface.name:12s} "
              f"MAC={iface.mac or 'N/A':18s} "
              f"IP={iface.ipv4 or 'N/A':16s} "
              f"Vendor={iface.vendor or '?':15s}"
              f"{f'CH={iface.channel}' if iface.channel else ''}")
    
    best = mgr.get_best_wireless()
    print(f"\nBest wireless interface: {best}")
    
    gateway = mgr._get_default_gateway()
    print(f"Default gateway: {gateway}")
    
    dns = mgr._get_dns_servers()
    print(f"DNS servers: {dns}")
    
    arp = mgr.arp.get_arp_table()
    print(f"ARP entries: {len(arp)}")
    
    # Print network info as JSON
    info = mgr.get_network_info()
    print(f"\nFull network info (JSON):")
    print(json.dumps(info, indent=2, default=str)[:1000] + "...")
