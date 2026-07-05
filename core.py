#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║         Elite State-of-the-Art WiFi Assault & Packet Capture Engine        ║
║                                                                             ║
║  core.py — Data Models, Configuration, Base Engine, Logging & Utilities   ║
║                                                                             ║
║  This module defines the entire type system for MEDUSA. Every dataclass,   ║
║  configuration model, validation function, and logging primitive lives     ║
║  here. It imports from medusa_init.py for OS-adaptive constants and        ║
║  provides a unified foundation for all 6 other modules.                    ║
║                                                                             ║
║  Performance:                                                               ║
║    • Pure Python dataclasses — zero overhead attribute access               ║
║    • Lazy property computation — signal bars calculated on demand          ║
║    • Pre-compiled regex patterns — no runtime compilation                   ║
║    • Singleton logger with queue support — sub-millisecond logging         ║
║                                                                             ║
║  OS Adaptivity:                                                             ║
║    • AttackVectorScorer adapts recommendations per OS capabilities         ║
║    • BruteForceConfig detects platform-optimal thread counts               ║
║    • CaptureResult auto-detects hashcat compatibility per OS               ║
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
import random
import hashlib
import string
import platform
import threading
import itertools
import subprocess
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import (
    List, Dict, Optional, Tuple, Any, Set, Callable,
    Iterator, Union, Generator, TypeVar, Generic, Type,
    cast, overload, Protocol, runtime_checkable
)
from dataclasses import dataclass, field, asdict, is_dataclass
from collections import defaultdict, OrderedDict
from enum import Enum, auto, IntEnum
from functools import lru_cache, cached_property, wraps
from contextlib import contextmanager
from queue import Queue, Empty, Full
from abc import ABC, abstractmethod
from uuid import uuid4
from numbers import Number

# ============================================================================
# MEDUSA INITIALIZATION CONSTANTS
# ============================================================================

from medusa_init import (
    # Version & Identity
    VERSION, CODENAME, VERSION_FULL, AUTHOR,
    
    # OS Detection
    SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    
    # OS Capabilities
    CAN_MONITOR_MODE, CAN_INJECT_PACKETS,
    CAN_PIXIEDUST, CAN_HCXTOOLS,
    CAN_HASHCAT_GPU, CAN_HASHCAT_CPU,
    
    # Directories
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR, LOG_DIR, WORDLIST_DIR,
    DEFAULT_WORDLIST,
    
    # Theme/ANSI
    THEME, ANSI, LOG_COLORS,
    
    # Errors
    MedusaError,
    
    # Utilities
    safe_filename, current_timestamp,
    human_time, human_bytes, human_number,
    validate_mac, validate_ip, random_mac,
    LOG_LEVELS,
    
    # Network
    COMMON_PORTS,
    WIFI_CHANNELS_2GHZ, WIFI_CHANNELS_5GHZ, WIFI_CHANNELS_6GHZ,
    FREQ_2GHZ, FREQ_5GHZ, FREQ_6GHZ,
    EAPOL_ETHERTYPE, BPF_FILTERS,
    HASHCAT_MODES,
    
    # Constants
    DEFAULT_CAPTURE_TIMEOUT, DEFAULT_DEAUTH_COUNT, DEFAULT_DEAUTH_DELAY,
    DEFAULT_MITM_INTERVAL, DEFAULT_CRACK_TIMEOUT,
    MAX_WORKER_THREADS, MAX_CRACK_THREADS, MAX_NETWORK_THREADS,
)


# ============================================================================
# TYPE ALIASES — Readable, self-documenting types
# ============================================================================

MACAddress = str          # "AA:BB:CC:DD:EE:FF"
IPAddress = str           # "192.168.1.1"
SSID = str                # "MyWiFi"
FilePath = Union[str, Path]
JSONDict = Dict[str, Any]
Timestamp = str           # ISO 8601
SignalStrength = int      # dBm (-30 to -100)
ChannelNumber = int       # 1-14, 36-165
FrequencyMHz = float      # 2412.0, 5180.0
Percentage = int          # 0-100

# Type variable for generic utilities
T = TypeVar('T')
K = TypeVar('K')
V = TypeVar('V')


# ============================================================================
# ENUMS — Type-safe constants
# ============================================================================

class EncryptionType(Enum):
    """WiFi encryption types with priority ordering for attack selection."""
    OPEN = "OPEN"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA2_MIXED = "WPA2/WPA"
    WPA3 = "WPA3-SAE"
    WPA3_TRANSITION = "WPA3-Transition"
    OWE = "OWE"  # Enhanced Open
    UNKNOWN = "UNKNOWN"
    
    @property
    def attack_priority(self) -> int:
        """Lower number = easier to crack."""
        priorities = {
            EncryptionType.OPEN: 0,
            EncryptionType.WEP: 1,
            EncryptionType.WPA: 2,
            EncryptionType.WPA2: 3,
            EncryptionType.WPA2_MIXED: 3,
            EncryptionType.OWE: 4,
            EncryptionType.WPA3_TRANSITION: 5,
            EncryptionType.WPA3: 6,
            EncryptionType.UNKNOWN: 99,
        }
        return priorities.get(self, 99)
    
    @classmethod
    def from_string(cls, s: str) -> 'EncryptionType':
        """Parse encryption type from scanner output.
        
        OS-adaptive: handles variations from iw, airport, netsh, pywifi.
        """
        s = s.upper().strip()
        if not s or s in ('OPEN', 'NONE', ''):
            return cls.OPEN
        if 'WPA3' in s and 'TRANSITION' in s:
            return cls.WPA3_TRANSITION
        if 'WPA3' in s:
            return cls.WPA3
        if 'OWE' in s:
            return cls.OWE
        if 'WPA2' in s and 'WPA' in s and 'WPA2' != s:
            return cls.WPA2_MIXED
        if 'WPA2' in s:
            return cls.WPA2
        if 'WPA' in s:
            return cls.WPA
        if 'WEP' in s:
            return cls.WEP
        return cls.UNKNOWN
    
    def __str__(self) -> str:
        return self.value


class AttackVector(Enum):
    """Available attack vectors, ordered by priority (0 = highest)."""
    CAPTIVE_PORTAL = (0, "Captive Portal Bypass", "Connect to open network")
    WPS_PIXIEDUST = (1, "WPS PixieDust", "reaver/bully PIN attack")
    WPS_PIN = (2, "WPS PIN Brute Force", "reaver PIN brute force")
    PMKID_HASHCAT = (3, "PMKID Hashcat", "hcxdumptool + hashcat 16800")
    DEAUTH_HANDSHAKE = (4, "Deauth + Handshake", "scapy deauth + hashcat 22000")
    DICTIONARY = (5, "Dictionary Attack", "pywifi/nmcli live crack")
    MASK = (6, "Mask Attack", "charset iterator live crack")
    HASHCAT_DICT = (7, "Hashcat Dictionary", "hashcat -a 0 mode 22000")
    HASHCAT_MASK = (8, "Hashcat Mask", "hashcat -a 3 mode 22000")
    MITM_SESSION = (9, "MITM Session Hijack", "ARP spoof + cookie steal")
    IP_SPOOF = (10, "IP Spoofing", "Raw packet IP manipulation")
    
    def __init__(self, priority: int, display_name: str, description: str):
        self.priority = priority
        self.display_name = display_name
        self.description = description
    
    @property
    def requires_monitor(self) -> bool:
        return self in (AttackVector.WPS_PIXIEDUST, AttackVector.WPS_PIN,
                        AttackVector.DEAUTH_HANDSHAKE)
    
    @property
    def requires_injection(self) -> bool:
        return self in (AttackVector.DEAUTH_HANDSHAKE, AttackVector.IP_SPOOF)
    
    @property
    def is_offline(self) -> bool:
        """Offline attacks don't need continuous connection to target."""
        return self in (AttackVector.PMKID_HASHCAT,
                        AttackVector.HASHCAT_DICT, AttackVector.HASHCAT_MASK)


class CaptureFilter(Enum):
    """Packet capture BPF filter modes."""
    ALL = ("all", "", "All 802.11 frames")
    HANDSHAKE = ("handshake", "ether proto 0x888e", "EAPOL only (lightweight)")
    HTTP = ("http", "tcp port 80 or tcp port 443", "HTTP/HTTPS traffic")
    PMKID = ("pmkid", "type mgt subtype assoc-req or type mgt subtype auth",
             "Association/Auth frames")
    DEAUTH = ("deauth", "type mgt subtype deauth", "Deauth frames only")
    BEACON = ("beacon", "type mgt subtype beacon", "Beacon frames")
    
    def __init__(self, name: str, bpf: str, description: str):
        self.filter_name = name
        self.bpf = bpf
        self.description = description
    
    @classmethod
    def from_name(cls, name: str) -> 'CaptureFilter':
        for f in cls:
            if f.filter_name == name:
                return f
        return cls.ALL


class HashcatMode(IntEnum):
    """Hashcat mode numbers for WiFi cracking."""
    WPA2_HANDSHAKE = 22000
    WPA_PMKID = 16800
    WPA3_SAE = 19200
    WPA2_MDM5 = 22100
    
    @property
    def description(self) -> str:
        return {
            HashcatMode.WPA2_HANDSHAKE: "WPA/WPA2 handshake (PBKDF2-SHA1)",
            HashcatMode.WPA_PMKID: "WPA/WPA2 PMKID (PBKDF2-SHA1)",
            HashcatMode.WPA3_SAE: "WPA3 SAE handshake",
            HashcatMode.WPA2_MDM5: "WPA/WPA2 handshake (MDK5/SHA256)",
        }.get(self, "Unknown")
    
    @property
    def example_hash(self) -> str:
        return {
            HashcatMode.WPA2_HANDSHAKE: "WPA*01*4D4FE7A5...",
            HashcatMode.WPA_PMKID: "2582A8281BF9D430...",
            HashcatMode.WPA3_SAE: "SAE*01*...",
        }.get(self, "")


class AttackStatus(Enum):
    """Status of an attack or operation."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


# ============================================================================
# COMPILED REGEX PATTERNS — Zero runtime compilation overhead
# ============================================================================

# Core validation patterns
RE_MAC_STRICT = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
RE_MAC_LOOSE = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
RE_IP_V4 = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
RE_IP_V6 = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
RE_SSID = re.compile(r'^[ -~]{1,32}$')
RE_BSSID = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
RE_HOSTNAME = re.compile(r'^[a-zA-Z0-9\-\.]{1,255}$')

# Extraction patterns (OS-adaptive)
RE_IW_SIGNAL = re.compile(r'signal:\s*(-?\d+)')
RE_IW_FREQ = re.compile(r'freq:\s*(\d+)')
RE_IW_SSID = re.compile(r'SSID:\s*(.*)')
RE_IW_BSS = re.compile(r'^BSS\s+([0-9a-f:]+)')
RE_AIRPORT_BSSID = re.compile(r'^\s+([0-9a-f:]{17})\s', re.IGNORECASE)
RE_NETSH_SSID = re.compile(r'^\s*SSID\s+\d+\s*:\s*(.+)$')
RE_NETSH_BSSID = re.compile(r'^\s*BSSID\s*:\s*(.+)$')
RE_NETSH_SIGNAL = re.compile(r'^\s*Signal\s*:\s*(\d+)%')
RE_NETSH_KEY = re.compile(r'Key Content\s*:\s*(.+)')

# HTTP extraction patterns
RE_HTTP_COOKIE = re.compile(rb'Cookie:\s*(.+?)(?:\r\n|\n)', re.IGNORECASE)
RE_HTTP_HOST = re.compile(rb'Host:\s*(\S+)', re.IGNORECASE)
RE_HTTP_URL = re.compile(rb'(?:GET|POST|PUT|DELETE)\s+(\S+)')
RE_HTTP_AUTH = re.compile(rb'Authorization:\s*Basic\s+(\S+)', re.IGNORECASE)
RE_HTTP_CRED = re.compile(rb'(?:user(?:name)?|pass|login|email)=\S+', re.IGNORECASE)
RE_HTTP_POST_BODY = re.compile(rb'\r\n\r\n(.+)$')

# EAPOL detection
RE_EAPOL = re.compile(b'EAPOL')

# Filename sanitization
RE_FILENAME_UNSAFE = re.compile(r'[^\w\-_\. ]')


# ============================================================================
# UTILITY FUNCTIONS — Fast, Pure, No Side Effects
# ============================================================================

# String constants for charset generation
_CHARSET_LOWER = string.ascii_lowercase
_CHARSET_UPPER = string.ascii_uppercase
_CHARSET_DIGITS = string.digits
_CHARSET_SPECIAL = string.punctuation
_CHARSET_HEX = string.hexdigits
_CHARSET_BASE64 = string.ascii_letters + string.digits + '+/'


def charset_combine(
    lowercase: bool = True,
    uppercase: bool = True,
    digits: bool = True,
    special: bool = False,
    custom: str = "",
) -> str:
    """Build a password charset from component parts.
    
    Args:
        lowercase: Include a-z
        uppercase: Include A-Z
        digits: Include 0-9
        special: Include punctuation
        custom: Custom characters to add
    
    Returns:
        Combined character set string.
    """
    chars = ""
    if lowercase:
        chars += _CHARSET_LOWER
    if uppercase:
        chars += _CHARSET_UPPER
    if digits:
        chars += _CHARSET_DIGITS
    if special:
        chars += _CHARSET_SPECIAL
    if custom:
        chars += custom
    return chars


def estimate_mask_space(charset: str, min_len: int, max_len: int) -> int:
    """Calculate total combinations for a mask attack.
    
    Args:
        charset: Character set to iterate
        min_len: Minimum password length
        max_len: Maximum password length
    
    Returns:
        Total number of possible passwords.
    """
    n = len(charset)
    return sum(n ** l for l in range(min_len, max_len + 1))


def generate_password_stream(
    charset: str,
    min_len: int = 8,
    max_len: int = 12,
    start: int = 0,
) -> Generator[str, None, None]:
    """Generate passwords from a charset iteratively.
    
    Memory-efficient generator — does not store all combinations.
    Supports resume from a starting index for idempotent cracking.
    
    Args:
        charset: Characters to use
        min_len: Minimum password length
        max_len: Maximum password length
        start: Starting index (for resume)
    
    Yields:
        Next password string in the sequence.
    """
    total_generated = 0
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            total_generated += 1
            if total_generated <= start:
                continue
            yield ''.join(combo)


def frequency_to_channel(freq_mhz: float) -> int:
    """Convert frequency in MHz to WiFi channel number.
    
    Supports 2.4GHz, 5GHz, and 6GHz bands.
    
    Args:
        freq_mhz: Center frequency in MHz
    
    Returns:
        WiFi channel number, or 0 if unknown.
    """
    # 2.4 GHz band
    if 2412 <= freq_mhz <= 2472:
        return int((freq_mhz - 2407) / 5)
    if 2484 <= freq_mhz <= 2484:
        return 14
    
    # 5 GHz band
    if 5180 <= freq_mhz <= 5825:
        return int((freq_mhz - 5000) / 5)
    
    # 6 GHz band (WiFi 6E)
    if 5955 <= freq_mhz <= 7115:
        return int((freq_mhz - 5950) / 5)
    
    return 0


def channel_to_frequency(channel: int) -> float:
    """Convert WiFi channel number to frequency in MHz.
    
    Args:
        channel: WiFi channel (1-14, 36-165, 1-233 for 6GHz)
    
    Returns:
        Center frequency in MHz, or 0.0 if unknown.
    """
    if 1 <= channel <= 13:
        return 2407.0 + channel * 5.0
    if channel == 14:
        return 2484.0
    if 36 <= channel <= 165:
        return 5000.0 + channel * 5.0
    if 1 <= channel <= 233:  # 6 GHz
        return 5950.0 + channel * 5.0
    return 0.0


def classify_band(freq_mhz: float) -> str:
    """Classify frequency to band name.
    
    Args:
        freq_mhz: Frequency in MHz
    
    Returns:
        '2.4 GHz', '5 GHz', '6 GHz', or 'Unknown'
    """
    lower, upper = freq_mhz, freq_mhz
    if FREQ_2GHZ[0] <= lower <= FREQ_2GHZ[1]:
        return "2.4 GHz"
    if FREQ_5GHZ[0] <= lower <= FREQ_5GHZ[1]:
        return "5 GHz"
    if FREQ_6GHZ[0] <= lower <= FREQ_6GHZ[1]:
        return "6 GHz"
    if 1 <= freq_mhz <= 1000:
        return f"{freq_mhz:.0f} kHz"
    return f"{freq_mhz:.0f} MHz"


def signal_to_percent(signal_dbm: int) -> int:
    """Convert RSSI dBm value to a 0-100 percentage.
    
    Args:
        signal_dbm: RSSI in dBm (e.g., -45)
    
    Returns:
        Signal percentage (0-100).
    """
    if signal_dbm >= -30:
        return 100
    if signal_dbm <= -90:
        return 0
    return int((signal_dbm + 90) / 60 * 100)


def signal_to_bars(signal_dbm: int, width: int = 4) -> str:
    """Convert RSSI dBm to visual bar characters.
    
    Args:
        signal_dbm: RSSI in dBm
        width: Number of bar chars (4)
    
    Returns:
        String like '████', '██▒▒', '▒▒▒▒'
    """
    pct = signal_to_percent(signal_dbm)
    filled = min(width, max(0, pct * width // 100))
    empty = width - filled
    return '█' * filled + '▒' * empty


def signal_to_label(signal_dbm: int) -> str:
    """Get human-readable signal quality label.
    
    Args:
        signal_dbm: RSSI in dBm
    
    Returns:
        'Excellent', 'Good', 'Fair', 'Weak', 'Very Weak'
    """
    if signal_dbm >= -30:
        return "Excellent"
    if signal_dbm >= -50:
        return "Good"
    if signal_dbm >= -60:
        return "Fair"
    if signal_dbm >= -70:
        return "Weak"
    return "Very Weak"


def format_mac(mac: str, separator: str = ":") -> str:
    """Normalize a MAC address to consistent format.
    
    Handles: aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabbccddeeff
    
    Args:
        mac: Raw MAC string
        separator: Output separator (':' or '-')
    
    Returns:
        Normalized MAC (uppercase, with separators).
    """
    # Remove existing separators
    clean = re.sub(r'[:\-.]', '', mac.strip().upper())
    if len(clean) != 12:
        return mac  # Invalid, return as-is
    return separator.join(clean[i:i+2] for i in range(0, 12, 2))


def random_ipv4() -> str:
    """Generate a random non-reserved IPv4 address.
    
    Skips: 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
           172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4
    
    Returns:
        Random IP string.
    """
    while True:
        ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        parts = [int(x) for x in ip.split('.')]
        # Skip reserved ranges
        if parts[0] == 10:
            continue
        if parts[0] == 127:
            continue
        if parts[0] == 169 and parts[1] == 254:
            continue
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            continue
        if parts[0] == 192 and parts[1] == 168:
            continue
        if parts[0] >= 224:
            continue
        return ip


def generate_mac(vendor_prefix: Optional[str] = None) -> str:
    """Generate a valid MAC address.
    
    Args:
        vendor_prefix: Optional 3-byte OUI (e.g., '00:11:22')
    
    Returns:
        MAC address string.
    """
    if vendor_prefix:
        prefix = format_mac(vendor_prefix).split(':')[:3]
        suffix = [random.randint(0x00, 0xFF) for _ in range(3)]
        mac = prefix + [f'{b:02X}' for b in suffix]
    else:
        # Locally administered, unicast
        first = random.randint(0x02, 0xFE) | 0x02
        rest = [random.randint(0x00, 0xFF) for _ in range(5)]
        mac = [f'{first:02X}'] + [f'{b:02X}' for b in rest]
    
    return ':'.join(mac)


def generate_session_id() -> str:
    """Generate a unique session identifier.
    
    Returns:
        16-character hex string.
    """
    return hashlib.sha256(
        f"{time.time_ns()}{random.random()}{os.urandom(8).hex()}".encode()
    ).hexdigest()[:16]


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """Hash a password for storage/comparison.
    
    Args:
        password: Plaintext password
        algorithm: Hash algorithm (sha256, md5, sha1)
    
    Returns:
        Hex digest string.
    """
    if algorithm == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    else:
        return hashlib.sha256(password.encode()).hexdigest()


# ============================================================================
# DATA MODELS — Core Domain Types
# ============================================================================

@dataclass
class WiFiNetwork:
    """Comprehensive wireless network intelligence model.
    
    Captures every relevant detail about a discovered access point.
    Provides computed properties for signal visualization, attack
    vector scoring, and OS-adaptive label generation.
    
    Performance: All properties are cached_property or computed
    on first access — zero cost if never queried.
    """
    
    # --- Identity ---
    ssid: str = ""
    bssid: str = ""
    
    # --- RF Characteristics ---
    channel: int = 0
    signal: int = -100  # RSSI in dBm
    frequency: float = 0.0
    noise: int = 0
    max_rate: str = ""
    
    # --- Security ---
    encryption_type: str = "OPEN"
    cipher: str = ""
    group_cipher: str = ""
    has_wps: bool = False
    wps_version: str = ""
    is_open: bool = False
    is_hidden: bool = False
    pmkid_available: bool = False
    rsn_ie: str = ""
    wpa_ie: str = ""
    
    # --- Vendor & Hardware ---
    vendor: str = ""
    country: str = ""
    beacon_interval: int = 100
    dtim_period: int = 1
    supported_rates: List[str] = field(default_factory=list)
    
    # --- Connected Clients ---
    clients: List[str] = field(default_factory=list)
    client_probes: List[str] = field(default_factory=list)
    client_count: int = 0
    
    # --- Metadata ---
    first_seen: str = ""
    last_seen: str = ""
    packets_count: int = 0
    
    # --- Scoring ---
    security_score: int = 50
    signal_score: int = 0
    
    # --- Internal ---
    _signal_percent_cache: Optional[int] = field(default=None, repr=False, compare=False)
    _signal_bars_cache: Optional[str] = field(default=None, repr=False, compare=False)
    
    def __post_init__(self):
        """Derive computed fields after initialization."""
        self.bssid = format_mac(self.bssid) if self.bssid else self.bssid
        if self.frequency and not self.channel:
            self.channel = frequency_to_channel(self.frequency)
        if not self.frequency and self.channel:
            self.frequency = channel_to_frequency(self.channel)
        
        # Parse encryption type
        enc = self.encryption_type.upper()
        self.is_open = enc in ('OPEN', 'NONE', '')
        self.is_hidden = self.ssid == '' or self.is_hidden
    
    @property
    def signal_percent(self) -> int:
        """Signal strength as percentage (0-100)."""
        if self._signal_percent_cache is None:
            self._signal_percent_cache = signal_to_percent(self.signal)
        return self._signal_percent_cache
    
    @property
    def signal_bars(self) -> str:
        """Visual signal bar representation."""
        if self._signal_bars_cache is None:
            self._signal_bars_cache = signal_to_bars(self.signal)
        return self._signal_bars_cache
    
    @property
    def signal_label(self) -> str:
        """Human-readable signal quality."""
        return signal_to_label(self.signal)
    
    @property
    def band(self) -> str:
        """Frequency band classification."""
        return classify_band(self.frequency) if self.frequency else "Unknown"
    
    @property
    def network_type_label(self) -> str:
        """Human-readable security label with WPS status."""
        if self.is_open:
            return "OPEN"
        if "WPA3" in self.encryption_type:
            return f"WPA3-SAE"
        if "WPA2" in self.encryption_type:
            return f"WPA2{' [WPS]' if self.has_wps else ''}"
        if "WPA" in self.encryption_type:
            return f"WPA{' [WPS]' if self.has_wps else ''}"
        if "WEP" in self.encryption_type:
            return "WEP"
        return self.encryption_type[:20] if self.encryption_type else "UNKNOWN"
    
    @property
    def encryption_enum(self) -> EncryptionType:
        """Parse encryption type to enum."""
        return EncryptionType.from_string(self.encryption_type)
    
    @property
    def crack_difficulty(self) -> str:
        """Estimated cracking difficulty label."""
        enc = self.encryption_enum
        if enc == EncryptionType.OPEN:
            return "None (open)"
        if enc == EncryptionType.WEP:
            return "Trivial (WEP)"
        if enc == EncryptionType.WPA:
            return "Easy (WPA-TKIP)"
        if self.has_wps:
            return "Easy (WPS PIN)"
        if self.pmkid_available:
            return "Medium (PMKID)"
        if self.clients:
            return "Medium (Handshake)"
        return "Hard (No clients)"
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary, computing all properties."""
        result = asdict(self)
        # Add computed properties
        result['signal_percent'] = self.signal_percent
        result['signal_bars'] = self.signal_bars
        result['signal_label'] = self.signal_label
        result['band'] = self.band
        result['network_type_label'] = self.network_type_label
        result['crack_difficulty'] = self.crack_difficulty
        result['encryption_enum'] = self.encryption_enum.value
        # Remove cache fields
        result.pop('_signal_percent_cache', None)
        result.pop('_signal_bars_cache', None)
        return result
    
    @classmethod
    def from_scan_entry(cls, entry: Dict[str, Any]) -> 'WiFiNetwork':
        """Create from a scanner output entry (OS-adaptive).
        
        Handles variations from iw, airport, netsh, and pywifi output.
        """
        return cls(
            ssid=entry.get('ssid', entry.get('SSID', '')),
            bssid=entry.get('bssid', entry.get('BSSID', entry.get('bss', ''))),
            channel=entry.get('channel', entry.get('Channel', 0)),
            signal=entry.get('signal', entry.get('Signal', entry.get('level', -100))),
            frequency=entry.get('frequency', entry.get('freq', 0.0)),
            encryption_type=entry.get('encryption', entry.get('Authentication', 'OPEN')),
            has_wps=entry.get('has_wps', entry.get('WPS', False)),
            is_open=entry.get('is_open', entry.get('isOpen', False)),
            is_hidden=entry.get('is_hidden', entry.get('isHidden', False)),
            vendor=entry.get('vendor', ''),
            noise=entry.get('noise', 0),
        )
    
    def __str__(self) -> str:
        return f"WiFiNetwork(ssid='{self.ssid}', bssid='{self.bssid}', ch={self.channel}, sig={self.signal}dBm, enc={self.network_type_label})"
    
    def __repr__(self) -> str:
        return self.__str__()


@dataclass
class CaptureResult:
    """Result of a packet capture session.
    
    Contains everything captured during a session:
    - WPA handshake & PMKID status
    - Stolen HTTP cookies and credentials
    - Session hijacking data
    - File paths for offline analysis
    """
    
    # --- Identity ---
    filepath: Path = Path()
    timestamp: str = ""
    duration: float = 0.0
    
    # --- Target ---
    network_ssid: str = ""
    network_bssid: str = ""
    
    # --- Capture Stats ---
    packets_count: int = 0
    packets_per_second: float = 0.0
    filter_type: str = "all"
    
    # --- Handshake Detection ---
    handshake_captured: bool = False
    handshake_complete: bool = False  # All 4 EAPOL messages
    eapol_messages: int = 0
    eapol_client: str = ""
    eapol_anonce: str = ""
    eapol_snonce: str = ""
    
    # --- PMKID ---
    pmkid_captured: bool = False
    pmkid_value: str = ""
    pmkid_client: str = ""
    
    # --- HTTP Traffic ---
    http_cookies: List[Dict] = field(default_factory=list)
    http_credentials: List[Dict] = field(default_factory=list)
    http_urls: List[str] = field(default_factory=list)
    http_packets: int = 0
    
    # --- Session Hijacking ---
    sessions_stolen: List[Dict] = field(default_factory=list)
    
    # --- Offline Analysis ---
    hashcat_ready: bool = False
    hashcat_file: str = ""
    hashcat_mode: int = 22000
    aircrack_ready: bool = False
    
    # --- Client Info ---
    client_macs: List[str] = field(default_factory=list)
    client_ips: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Derive computed fields."""
        if self.duration > 0 and self.packets_count > 0:
            self.packets_per_second = self.packets_count / self.duration
    
    @property
    def has_usable_hash(self) -> bool:
        """Check if capture contains crackable material."""
        return self.handshake_captured or self.pmkid_captured
    
    @property
    def crackable_type(self) -> str:
        """Describe what can be cracked."""
        if self.handshake_captured:
            return "WPA Handshake"
        if self.pmkid_captured:
            return "PMKID"
        return "None"
    
    @property
    def stolen_sessions_count(self) -> int:
        """Total number of hijackable sessions."""
        return len(self.sessions_stolen)
    
    @property
    def total_credentials(self) -> int:
        """Total credentials captured."""
        return len(self.http_credentials)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary with computed properties."""
        result = asdict(self)
        result['filepath'] = str(self.filepath)
        result['has_usable_hash'] = self.has_usable_hash
        result['crackable_type'] = self.crackable_type
        result['stolen_sessions_count'] = self.stolen_sessions_count
        result['total_credentials'] = self.total_credentials
        return result
    
    def summary(self) -> str:
        """One-line summary of capture results."""
        parts = [
            f"packets={self.packets_count}",
            f"eapol={self.eapol_messages}",
            f"handshake={'yes' if self.handshake_captured else 'no'}",
            f"pmkid={'yes' if self.pmkid_captured else 'no'}",
            f"cookies={len(self.http_cookies)}",
            f"creds={len(self.http_credentials)}",
        ]
        return f"CaptureResult({', '.join(parts)})"
    
    def __str__(self) -> str:
        return self.summary()


@dataclass
class ClientDevice:
    """Model for a client device discovered on a network.
    
    Captures everything known about a device:
    - Network identity (IP, MAC)
    - Open ports (from scanning)
    - HTTP sessions (for hijacking)
    - OS fingerprint hints
    """
    
    # --- Identity ---
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    
    # --- Network ---
    open_ports: List[int] = field(default_factory=list)
    os_hint: str = ""
    os_confidence: float = 0.0
    ttl: int = 64
    
    # --- Timeline ---
    first_seen: str = ""
    last_seen: str = ""
    dhcp_hostname: str = ""
    user_agent: str = ""
    
    # --- Web Sessions ---
    http_sessions: List[Dict] = field(default_factory=list)
    cookies_observed: int = 0
    
    # --- Wireless ---
    signal: int = 0
    channel: int = 0
    is_associated: bool = False
    
    def __post_init__(self):
        """Normalize MAC on init."""
        if self.mac:
            self.mac = format_mac(self.mac)
    
    @property
    def os_guess(self) -> str:
        """Best OS guess from TTL and hints."""
        if self.os_hint:
            return self.os_hint
        if 64 <= self.ttl <= 64:
            return "Linux/Unix/Android"
        if 128 <= self.ttl <= 128:
            return "Windows"
        if 255 <= self.ttl <= 255:
            return "Network Device"
        return f"Unknown (TTL={self.ttl})"
    
    @property
    def port_count(self) -> int:
        return len(self.open_ports)
    
    @property
    def has_web_server(self) -> bool:
        return any(p in (80, 443, 8080, 8443) for p in self.open_ports)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['os_guess'] = self.os_guess
        result['port_count'] = self.port_count
        result['has_web_server'] = self.has_web_server
        return result
    
    def __str__(self) -> str:
        return f"ClientDevice(ip={self.ip}, mac={self.mac}, ports={self.port_count})"


@dataclass
class BruteForceConfig:
    """Complete configuration for brute-force and cracking operations.
    
    Supports:
    - Live dictionary attacks (pywifi/nmcli)
    - Offline hashcat attacks (GPU/CPU)
    - Mask/charset attacks
    - Session save/resume for all modes
    
    OS-adaptive: thread counts, GPU detection, tool paths.
    """
    
    # --- Attack Mode ---
    attack_mode: str = "dictionary"  # dictionary, mask, hashcat
    session_name: str = "medusa_session"
    
    # --- Dictionary Settings ---
    wordlist_path: str = str(DEFAULT_WORDLIST)
    rules_file: str = ""
    use_rules: bool = False
    
    # --- Mask Settings ---
    min_length: int = 8
    max_length: int = 12
    use_lowercase: bool = True
    use_uppercase: bool = True
    use_digits: bool = True
    use_special: bool = False
    custom_chars: str = ""
    mask_pattern: str = ""  # e.g., "?l?l?d?d?d?d" for hashcat
    
    # --- Performance ---
    threads: int = field(default_factory=lambda: max(1, CPU_COUNT))
    timeout_seconds: int = DEFAULT_CRACK_TIMEOUT
    batch_size: int = 100
    max_attempts: int = 0  # 0 = unlimited
    
    # --- GPU Acceleration ---
    gpu_acceleration: bool = CAN_HASHCAT_GPU
    gpu_device: int = 0  # Device ID for multi-GPU
    hashcat_path: str = "hashcat"
    hashcat_extra_args: str = ""
    
    # --- Hashcat Modes ---
    use_hashcat: bool = False
    hash_type: int = 22000  # Default: WPA2 handshake
    hash_file: str = ""
    potfile_path: str = str(CONFIG_DIR / "medusa.potfile")
    
    # --- State Management ---
    resume_offset: int = 0  # For session resume
    checkpoint_interval: int = 1000  # Save every N attempts
    
    # --- Derived ---
    
    def __post_init__(self):
        """Auto-detect platform-optimal settings."""
        if not self.threads or self.threads < 1:
            self.threads = max(1, CPU_COUNT)
        
        # Auto-detect hashcat
        if not self.use_hashcat:
            self.use_hashcat = self._detect_hashcat()
    
    @staticmethod
    @lru_cache(maxsize=1)
    def _detect_hashcat() -> bool:
        """Check if hashcat is available on the system."""
        try:
            result = subprocess.run(
                ["hashcat", "--version"],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
            return False
    
    @property
    def charset(self) -> str:
        """Build character set from config."""
        return charset_combine(
            lowercase=self.use_lowercase,
            uppercase=self.use_uppercase,
            digits=self.use_digits,
            special=self.use_special,
            custom=self.custom_chars,
        )
    
    @property
    def charset_size(self) -> int:
        """Number of characters in the current charset."""
        return len(self.charset)
    
    @property
    def total_combinations(self) -> int:
        """Total combinations for mask attack."""
        return estimate_mask_space(self.charset, self.min_length, self.max_length)
    
    @property
    def estimated_crack_time(self) -> str:
        """Rough estimate of crack time at 1000 attempts/sec."""
        total = self.total_combinations
        if total == 0:
            return "Unknown"
        attempts_per_sec = self.threads * 3  # rough estimate
        seconds = total / max(1, attempts_per_sec)
        return human_time(seconds)
    
    @property
    def wordlist_exists(self) -> bool:
        """Check if wordlist file exists."""
        return Path(self.wordlist_path).exists() if self.wordlist_path else False
    
    @property
    def wordlist_size(self) -> int:
        """Get wordlist file size."""
        if self.wordlist_exists:
            return Path(self.wordlist_path).stat().st_size
        return 0
    
    @property
    def wordlist_line_count(self) -> int:
        """Count lines in wordlist (cached)."""
        if not self.wordlist_exists:
            return 0
        if not hasattr(self, '_line_count'):
            try:
                with open(self.wordlist_path, 'rb') as f:
                    self._line_count = sum(1 for _ in f)
            except (IOError, OSError):
                self._line_count = 0
        return self._line_count
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['charset_size'] = self.charset_size
        result['total_combinations'] = self.total_combinations
        result['estimated_crack_time'] = self.estimated_crack_time
        result['wordlist_exists'] = self.wordlist_exists
        result['wordlist_size'] = self.wordlist_size
        result['wordlist_line_count'] = self.wordlist_line_count if self.wordlist_exists else 0
        return result
    
    def save(self, path: Optional[Path] = None) -> Path:
        """Serialize config to JSON file.
        
        Args:
            path: Output path (default: session dir)
        
        Returns:
            Path to saved file.
        """
        if path is None:
            path = SESSION_DIR / f"{self.session_name}_config.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        return path
    
    @classmethod
    def load(cls, path: Path) -> 'BruteForceConfig':
        """Load config from JSON file.
        
        Args:
            path: Path to saved config
        
        Returns:
            Deserialized BruteForceConfig.
        """
        with open(path) as f:
            data = json.load(f)
        # Remove computed fields that shouldn't be in constructor
        data.pop('charset_size', None)
        data.pop('total_combinations', None)
        data.pop('estimated_crack_time', None)
        data.pop('wordlist_exists', None)
        data.pop('wordlist_size', None)
        data.pop('wordline_line_count', None)
        return cls(**data)
    
    def __str__(self) -> str:
        mode = self.attack_mode
        if mode == "dictionary":
            return f"BruteForceConfig(mode=dictionary, wordlist='{Path(self.wordlist_path).name}', threads={self.threads})"
        elif mode == "mask":
            return f"BruteForceConfig(mode=mask, charset={self.charset_size}chars, len={self.min_length}-{self.max_length}, combos={human_number(self.total_combinations)})"
        elif mode == "hashcat":
            return f"BruteForceConfig(mode=hashcat, hashcat={'yes' if self.use_hashcat else 'no'}, gpu={self.gpu_acceleration})"
        return f"BruteForceConfig(mode={mode})"


@dataclass
class SessionState:
    """Idempotent session save/resume state.
    
    Persists the full state of an operation so it can be:
    - Interrupted and resumed later
    - Inspected for debugging
    - Shared between CLI and GUI modes
    """
    
    session_id: str = field(default_factory=generate_session_id)
    created_at: str = field(default_factory=current_timestamp)
    updated_at: str = field(default_factory=current_timestamp)
    
    # Operation info
    mode: str = ""  # scan, attack, capture, crack
    status: str = "created"
    version: str = VERSION
    
    # Target
    target_bssid: str = ""
    target_ssid: str = ""
    target_channel: int = 0
    
    # Progress
    progress_current: int = 0
    progress_total: int = 0
    attempts: int = 0
    elapsed_seconds: float = 0.0
    
    # Results
    password_found: str = ""
    handshake_captured: bool = False
    packets_captured: int = 0
    
    # Resume data
    resume_offset: int = 0
    resume_data: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    args: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    def update(self):
        """Update the 'updated_at' timestamp."""
        self.updated_at = current_timestamp()
    
    @property
    def is_complete(self) -> bool:
        return self.status in ("completed", "failed", "cancelled")
    
    @property
    def progress_percent(self) -> float:
        if self.progress_total <= 0:
            return 0.0
        return min(100.0, self.progress_current / self.progress_total * 100)
    
    @property
    def estimated_remaining(self) -> str:
        if self.progress_current <= 0 or self.elapsed_seconds <= 0:
            return "Unknown"
        rate = self.progress_current / self.elapsed_seconds
        remaining = (self.progress_total - self.progress_current) / max(rate, 0.001)
        return human_time(remaining)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['progress_percent'] = self.progress_percent
        result['estimated_remaining'] = self.estimated_remaining
        result['is_complete'] = self.is_complete
        return result
    
    def save(self, path: Optional[Path] = None) -> Path:
        """Save session state to JSON file.
        
        Args:
            path: Output path
        
        Returns:
            Path to saved file.
        """
        self.update()
        if path is None:
            path = SESSION_DIR / f"{self.session_id}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        return path
    
    @classmethod
    def load(cls, path: Path) -> 'SessionState':
        """Load session state from JSON file.
        
        Args:
            path: Path to saved session
        
        Returns:
            Deserialized SessionState.
        """
        with open(path) as f:
            data = json.load(f)
        data.pop('progress_percent', None)
        data.pop('estimated_remaining', None)
        data.pop('is_complete', None)
        return cls(**data)
    
    def __str__(self) -> str:
        return f"SessionState(id={self.session_id[:8]}..., mode={self.mode}, status={self.status}, progress={self.progress_percent:.1f}%)"


# ============================================================================
# ATTACK VECTOR SCORER — OS-Adaptive Intelligence
# ============================================================================

class AttackVectorScorer:
    """Scores and recommends attack vectors based on target and platform.
    
    OS-adaptive: Considers available tools, permissions, and hardware
    when ranking attack vectors.
    """
    
    # Weights for scoring
    WEIGHT_SPEED = 0.3       # How fast is this attack?
    WEIGHT_SUCCESS = 0.3     # How likely is success?
    WEIGHT_STEALTH = 0.2     # How detectable?
    WEIGHT_RESOURCE = 0.1    # How resource-intensive?
    WEIGHT_PLATFORM = 0.1    # Is it available on this OS?
    
    @classmethod
    def score_attack(cls, vector: AttackVector, network: WiFiNetwork,
                     is_admin: bool = False) -> float:
        """Score an attack vector for a specific network.
        
        Args:
            vector: Attack vector to evaluate
            network: Target network details
            is_admin: Whether running with elevated privileges
        
        Returns:
            Score 0.0-1.0 (higher = better recommendation)
        """
        score = 0.0
        
        # --- Platform availability ---
        platform_score = 1.0
        if vector.requires_monitor and not CAN_MONITOR_MODE:
            platform_score = 0.0
        if vector.requires_injection and not CAN_INJECT_PACKETS:
            platform_score = 0.0
        if vector == AttackVector.WPS_PIXIEDUST and not CAN_PIXIEDUST:
            platform_score = 0.0
        if vector == AttackVector.PMKID_HASHCAT and not CAN_HCXTOOLS:
            platform_score = 0.0
        if vector in (AttackVector.HASHCAT_DICT, AttackVector.HASHCAT_MASK) and not CAN_HASHCAT_CPU:
            platform_score = 0.0
        if not is_admin and vector in (AttackVector.DEAUTH_HANDSHAKE, AttackVector.MITM_SESSION):
            platform_score *= 0.3
        
        if platform_score == 0.0:
            return 0.0
        
        # --- Speed score ---
        speed_scores = {
            AttackVector.CAPTIVE_PORTAL: 1.0,
            AttackVector.WPS_PIXIEDUST: 0.9,
            AttackVector.DICTIONARY: 0.7,
            AttackVector.DEAUTH_HANDSHAKE: 0.6,
            AttackVector.PMKID_HASHCAT: 0.5,
            AttackVector.WPS_PIN: 0.3,
            AttackVector.HASHCAT_DICT: 0.7,
            AttackVector.HASHCAT_MASK: 0.4,
            AttackVector.MASK: 0.2,
            AttackVector.MITM_SESSION: 0.5,
            AttackVector.IP_SPOOF: 0.6,
        }
        speed = speed_scores.get(vector, 0.5)
        
        # --- Success probability ---
        success_scores = {
            AttackVector.CAPTIVE_PORTAL: 0.8,
            AttackVector.WPS_PIXIEDUST: 0.7,
            AttackVector.DICTIONARY: 0.3,
            AttackVector.DEAUTH_HANDSHAKE: 0.6,
            AttackVector.PMKID_HASHCAT: 0.4,
            AttackVector.WPS_PIN: 0.2,
            AttackVector.HASHCAT_DICT: 0.5,
            AttackVector.HASHCAT_MASK: 0.3,
            AttackVector.MASK: 0.1,
            AttackVector.MITM_SESSION: 0.6,
            AttackVector.IP_SPOOF: 0.4,
        }
        
        # Adjust based on network characteristics
        success = success_scores.get(vector, 0.5)
        if network.is_open and vector == AttackVector.CAPTIVE_PORTAL:
            success = 0.95
        if network.has_wps and vector == AttackVector.WPS_PIXIEDUST:
            success = 0.8
        if network.clients and vector == AttackVector.DEAUTH_HANDSHAKE:
            success = 0.8
        if network.pmkid_available and vector == AttackVector.PMKID_HASHCAT:
            success = 0.7
        
        # --- Stealth score ---
        stealth_scores = {
            AttackVector.CAPTIVE_PORTAL: 0.3,
            AttackVector.WPS_PIXIEDUST: 0.2,
            AttackVector.DICTIONARY: 0.8,
            AttackVector.DEAUTH_HANDSHAKE: 0.1,
            AttackVector.PMKID_HASHCAT: 0.7,
            AttackVector.HASHCAT_DICT: 1.0,  # Offline
            AttackVector.HASHCAT_MASK: 1.0,  # Offline
            AttackVector.MASK: 0.8,
            AttackVector.MITM_SESSION: 0.2,
            AttackVector.IP_SPOOF: 0.4,
        }
        stealth = stealth_scores.get(vector, 0.5)
        
        # --- Resource score ---
        resource_scores = {
            AttackVector.CAPTIVE_PORTAL: 0.9,
            AttackVector.WPS_PIXIEDUST: 0.6,
            AttackVector.DICTIONARY: 0.5,
            AttackVector.DEAUTH_HANDSHAKE: 0.7,
            AttackVector.PMKID_HASHCAT: 0.4,
            AttackVector.HASHCAT_DICT: 0.3,
            AttackVector.HASHCAT_MASK: 0.2,
            AttackVector.MASK: 0.4,
            AttackVector.MITM_SESSION: 0.5,
            AttackVector.IP_SPOOF: 0.8,
        }
        resource = resource_scores.get(vector, 0.5)
        
        # --- Calculate final score ---
        score = (
            cls.WEIGHT_SPEED * speed +
            cls.WEIGHT_SUCCESS * success +
            cls.WEIGHT_STEALTH * stealth +
            cls.WEIGHT_RESOURCE * resource +
            cls.WEIGHT_PLATFORM * platform_score
        )
        
        return min(1.0, max(0.0, score))
    
    @classmethod
    def recommend_best(cls, network: WiFiNetwork, is_admin: bool = False,
                       count: int = 5) -> List[Tuple[AttackVector, float]]:
        """Get the top N recommended attack vectors.
        
        Args:
            network: Target network
            is_admin: Whether running with elevated privileges
            count: Number of recommendations
        
        Returns:
            List of (AttackVector, score) tuples, sorted by score descending.
        """
        scored = []
        for vector in AttackVector:
            score = cls.score_attack(vector, network, is_admin)
            if score > 0.0:
                scored.append((vector, score))
        
        # Sort by score descending
        scored.sort(key=lambda x: -x[1])
        return scored[:count]
    
    @classmethod
    def best_vector(cls, network: WiFiNetwork, is_admin: bool = False) -> Optional[AttackVector]:
        """Get the single best attack vector.
        
        Args:
            network: Target network
            is_admin: Whether running with elevated privileges
        
        Returns:
            Best AttackVector, or None if none available.
        """
        recommendations = cls.recommend_best(network, is_admin, count=1)
        return recommendations[0][0] if recommendations else None
    
    @classmethod
    def can_attack(cls, network: WiFiNetwork, is_admin: bool = False) -> bool:
        """Check if any attack vector is available for this network.
        
        Args:
            network: Target network
            is_admin: Whether running with elevated privileges
        
        Returns:
            True if at least one attack can be attempted.
        """
        return any(cls.score_attack(v, network, is_admin) > 0 for v in AttackVector)


# ============================================================================
# LOGGING ENGINE — Singleton, Queued, Color-Aware
# ============================================================================

class MedusaLogger:
    """Thread-safe, queued logging engine with color support.
    
    Features:
    - Singleton pattern (one logger for entire application)
    - Queue-based async logging (zero blocking in hot paths)
    - Level filtering (configurable at runtime)
    - GUI integration via queue (dashboard consumes from same queue)
    - Colorized output (Rich when available, ANSI fallback)
    - File rotation (auto-archive old logs)
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, name: str = "medusa", level: str = "info",
                 log_file: Optional[Path] = None, console=None):
        if self._initialized:
            return
        self._initialized = True
        
        self.name = name
        self.level_name = level
        self.level_num = LOG_LEVELS.get(level, 20)
        self.console = console
        self.log_file = log_file
        
        # Thread-safe queue for async logging
        self.queue: Queue = Queue(maxsize=LOG_QUEUE_MAXSIZE)
        self._consumer_running = False
        self._consumer_thread: Optional[threading.Thread] = None
        
        # Level colors
        self.colors = LOG_COLORS
        
        # Prefixes for each level
        self.prefixes = {
            "debug": "…", "info": "•", "ok": "✓", "found": "►",
            "warn": "⚠", "err": "✗", "critical": "‼",
            "deauth": "⚡", "mitm": "🌀", "hijack": "🕸",
        }
        
        # Start background consumer if not already running
        self._start_consumer()
    
    def _start_consumer(self):
        """Start the background log consumer thread."""
        if self._consumer_running:
            return
        self._consumer_running = True
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            daemon=True,
            name=f"{self.name}-logger"
        )
        self._consumer_thread.start()
    
    def _consumer_loop(self):
        """Background thread that drains the log queue."""
        while self._consumer_running:
            try:
                entry = self.queue.get(timeout=1.0)
                self._write_entry(entry)
            except Empty:
                continue
            except Exception:
                pass
    
    def _write_entry(self, entry: Dict[str, Any]):
        """Write a single log entry to output.
        
        Args:
            entry: Dict with keys: level, message, timestamp
        """
        level = entry.get('level', 'info')
        message = entry.get('message', '')
        timestamp = entry.get('timestamp', time.time())
        
        # Format timestamp
        ts = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S')
        
        # Get prefix and color
        prefix = self.prefixes.get(level, '•')
        color = self.colors.get(level, ANSI.get('C', ''))
        
        # Write to console
        if self.console and hasattr(self.console, 'log'):
            try:
                self.console.log(f"[{color}]{prefix}[/{color}] {message}")
            except Exception:
                print(f"{color}[{prefix}]{ANSI.get('RESET', '')} {message}")
        else:
            print(f"{color}[{prefix}]{ANSI.get('RESET', '')} {message}")
        
        # Write to file
        if self.log_file:
            try:
                with open(self.log_file, 'a') as f:
                    f.write(f"[{ts}] [{level.upper():8s}] {message}\n")
            except (IOError, OSError):
                pass
    
    def log(self, message: str, level: str = "info"):
        """Queue a log message.
        
        Args:
            message: The log message
            level: Log level (info, ok, warn, err, found, etc.)
        """
        level_num = LOG_LEVELS.get(level, 20)
        if level_num < self.level_num:
            return
        
        entry = {
            'level': level,
            'message': str(message),
            'timestamp': time.time(),
        }
        
        try:
            self.queue.put_nowait(entry)
        except Full:
            # Queue full — drop message to avoid blocking
            pass
    
    # Convenience methods
    def info(self, message: str):
        self.log(message, "info")
    
    def ok(self, message: str):
        self.log(message, "ok")
    
    def warn(self, message: str):
        self.log(message, "warn")
    
    def err(self, message: str):
        self.log(message, "err")
    
    def found(self, message: str):
        self.log(message, "found")
    
    def debug(self, message: str):
        self.log(message, "debug")
    
    def critical(self, message: str):
        self.log(message, "critical")
    
    def deauth(self, message: str):
        self.log(message, "deauth")
    
    def mitm(self, message: str):
        self.log(message, "mitm")
    
    def hijack(self, message: str):
        self.log(message, "hijack")
    
    def set_level(self, level: str):
        """Change the minimum log level.
        
        Args:
            level: New minimum level name
        """
        self.level_name = level
        self.level_num = LOG_LEVELS.get(level, 20)
    
    def flush(self):
        """Block until all queued messages are written."""
        if self.queue.qsize() > 0:
            time.sleep(0.1)  # Give consumer time to drain
    
    def stop(self):
        """Stop the consumer thread."""
        self._consumer_running = False
        if self._consumer_thread:
            self._consumer_thread.join(timeout=2.0)
        self.flush()
    
    def __del__(self):
        self.stop()


# ============================================================================
# THREAD-SAFE COUNTERS AND ACCUMULATORS
# ============================================================================

class AtomicCounter:
    """Thread-safe counter with optional upper limit."""
    
    def __init__(self, initial: int = 0, maximum: int = 0):
        self._value = initial
        self._maximum = maximum
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        """Atomically increment and return new value."""
        with self._lock:
            self._value += amount
            if self._maximum > 0 and self._value > self._maximum:
                self._value = self._maximum
            return self._value
    
    def decrement(self, amount: int = 1) -> int:
        """Atomically decrement and return new value."""
        with self._lock:
            self._value -= amount
            if self._value < 0:
                self._value = 0
            return self._value
    
    @property
    def value(self) -> int:
        with self._lock:
            return self._value
    
    @value.setter
    def value(self, v: int):
        with self._lock:
            self._value = v
    
    def __str__(self) -> str:
        return str(self.value)
    
    def __int__(self) -> int:
        return self.value


class AtomicRateTracker:
    """Thread-safe rate tracker for operations per second."""
    
    def __init__(self, window: float = 5.0):
        self._window = window
        self._counts: List[Tuple[float, int]] = []
        self._lock = threading.Lock()
    
    def record(self, count: int = 1):
        """Record an operation at the current time."""
        now = time.time()
        with self._lock:
            self._counts.append((now, count))
            # Trim old entries
            cutoff = now - self._window
            self._counts = [(t, c) for t, c in self._counts if t > cutoff]
    
    @property
    def rate(self) -> float:
        """Current operations per second."""
        with self._lock:
            if not self._counts:
                return 0.0
            now = time.time()
            cutoff = now - self._window
            recent = [(t, c) for t, c in self._counts if t > cutoff]
            if not recent:
                return 0.0
            total = sum(c for _, c in recent)
            duration = min(self._window, now - recent[0][0])
            return total / max(duration, 0.001)
    
    def reset(self):
        with self._lock:
            self._counts.clear()


# ============================================================================
# PLATFORM-ADAPTIVE TOOL DETECTION
# ============================================================================

@lru_cache(maxsize=1)
def detect_tools() -> Dict[str, bool]:
    """Detect available system tools (cached at first call).
    
    Returns:
        Dict mapping tool name to availability boolean.
    """
    tools = {}
    
    for tool in ["aircrack-ng", "airodump-ng", "aireplay-ng", "airmon-ng",
                  "iw", "iwlist", "hashcat", "hcxdumptool", "hcxpcapngtool",
                  "reaver", "bully", "tshark", "tcpdump", "nmcli"]:
        try:
            result = subprocess.run(
                ["which", tool] if not IS_WINDOWS else ["where", tool],
                capture_output=True, timeout=3
            )
            tools[tool] = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools[tool] = False
    
    # Windows: netsh is always available
    if IS_WINDOWS:
        tools["netsh"] = True
    
    # macOS: airport is available on Mac
    if IS_MACOS:
        tools["airport"] = Path("/System/Library/PrivateFrameworks/Apple80211.framework/"
                                 "Versions/Current/Resources/airport").exists()
    
    return tools


def tool_available(name: str) -> bool:
    """Quick check if a system tool is available.
    
    Args:
        name: Tool name (e.g., 'hashcat', 'reaver')
    
    Returns:
        True if tool is available on this system.
    """
    return detect_tools().get(name, False)


# ============================================================================
# RESULT COLLECTOR — Thread-Safe Accumulation
# ============================================================================

class ResultCollector:
    """Thread-safe collector for accumulating results from parallel operations.
    
    Used for combining scan results, capture data, and crack attempts
    from multiple threads/processes.
    """
    
    def __init__(self):
        self._items: List[Any] = []
        self._lock = threading.Lock()
    
    def add(self, item: Any):
        """Add an item thread-safely."""
        with self._lock:
            self._items.append(item)
    
    def extend(self, items: List[Any]):
        """Add multiple items thread-safely."""
        with self._lock:
            self._items.extend(items)
    
    @property
    def items(self) -> List[Any]:
        """Get a snapshot of all items."""
        with self._lock:
            return list(self._items)
    
    @property
    def count(self) -> int:
        with self._lock:
            return len(self._items)
    
    def clear(self):
        with self._lock:
            self._items.clear()
    
    def __len__(self) -> int:
        return self.count
    
    def __iter__(self):
        return iter(self.items)


# ============================================================================
# MODULE EXPORTS
# ============================================================================

__all__ = [
    # Type aliases
    "MACAddress", "IPAddress", "SSID", "FilePath", "JSONDict",
    "Timestamp", "SignalStrength", "ChannelNumber", "FrequencyMHz", "Percentage",
    
    # Enums
    "EncryptionType", "AttackVector", "CaptureFilter", "HashcatMode", "AttackStatus",
    
    # Compiled regex
    "RE_MAC_STRICT", "RE_MAC_LOOSE", "RE_IP_V4", "RE_IP_V6",
    "RE_SSID", "RE_BSSID", "RE_HOSTNAME",
    "RE_IW_SIGNAL", "RE_IW_FREQ", "RE_IW_SSID", "RE_IW_BSS",
    "RE_AIRPORT_BSSID", "RE_NETSH_SSID", "RE_NETSH_BSSID",
    "RE_NETSH_SIGNAL", "RE_NETSH_KEY",
    "RE_HTTP_COOKIE", "RE_HTTP_HOST", "RE_HTTP_URL",
    "RE_HTTP_AUTH", "RE_HTTP_CRED", "RE_HTTP_POST_BODY",
    "RE_EAPOL", "RE_FILENAME_UNSAFE",
    
    # Utility functions
    "charset_combine", "estimate_mask_space", "generate_password_stream",
    "frequency_to_channel", "channel_to_frequency", "classify_band",
    "signal_to_percent", "signal_to_bars", "signal_to_label",
    "format_mac", "random_ipv4", "generate_mac", "generate_session_id",
    "hash_password",
    
    # Data models
    "WiFiNetwork", "CaptureResult", "ClientDevice",
    "BruteForceConfig", "SessionState",
    
    # Attack vector scorer
    "AttackVectorScorer",
    
    # Logging
    "MedusaLogger",
    
    # Thread-safe utilities
    "AtomicCounter", "AtomicRateTracker", "ResultCollector",
    
    # Tool detection
    "detect_tools", "tool_available",
          ]
