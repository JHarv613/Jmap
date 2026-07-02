#!/usr/bin/env python3
"""
Jmap - Network Port Scanner & Network Mapper
Pure Python3 | No external dependencies | Ubuntu 22.04 LTS compatible
Author: Joshua Harvey
"""

import argparse
import concurrent.futures
import csv
import datetime
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

VERSION = "2.0.0"

# ══════════════════════════════════════════════════════════════
#  COLOURS
# ══════════════════════════════════════════════════════════════
class C:
    GREEN   = "\033[92m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    BLUE    = "\033[94m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def disable() -> None:
        for attr in ["GREEN","RED","YELLOW","CYAN","MAGENTA","BLUE","BOLD","DIM","RESET"]:
            setattr(C, attr, "")

BANNER = f"""
{C.CYAN}{C.BOLD}
     ██╗███╗   ███╗ █████╗ ██████╗ 
     ██║████╗ ████║██╔══██╗██╔══██╗
     ██║██╔████╔██║███████║██████╔╝
██   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
╚█████╔╝██║ ╚═╝ ██║██║  ██║██║     
 ╚════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{C.RESET}{C.DIM}  Pure Python3 Network Scanner  |  v{VERSION}  |  No Dependencies{C.RESET}
"""

# ══════════════════════════════════════════════════════════════
#  CONFIG & DEFAULTS
# ══════════════════════════════════════════════════════════════
DEFAULT_CONFIG: Dict[str, Any] = {
    "threads": 100,
    "timeout": 1.0,
    "retries": 1,
    "rate":    0.0,
}

def load_config() -> Dict[str, Any]:
    """
    Read ~/.jmaprc  (key = value, lines starting with # ignored).
    Recognised keys: threads, retries, timeout, rate.
    Falls back to DEFAULT_CONFIG for any missing / invalid value.
    """
    config = dict(DEFAULT_CONFIG)
    path = os.path.expanduser("~/.jmaprc")
    if not os.path.isfile(path):
        return config
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = [p.strip() for p in line.split("=", 1)]
                if key in ("threads", "retries"):
                    try:
                        config[key] = int(value)
                    except ValueError:
                        pass
                elif key in ("timeout", "rate"):
                    try:
                        config[key] = float(value)
                    except ValueError:
                        pass
    except Exception:
        pass
    return config


# ══════════════════════════════════════════════════════════════
#  PORT PROFILES & TOP-N
# ══════════════════════════════════════════════════════════════
PROFILE_PORTS: Dict[str, Set[int]] = {
    "web": {
        20, 21, 25, 80, 110, 143, 443, 465, 587,
        993, 995, 8000, 8080, 8081, 8443, 8888, 9000, 9080,
    },
    "database": {
        389, 636, 1433, 1521, 3306, 5000, 5001,
        5432, 6379, 9200, 9300, 11211, 27017,
    },
    "common": {
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 111, 123,
        135, 137, 138, 139, 143, 161, 162, 389, 443, 445,
        465, 500, 514, 587, 636, 993, 995, 1433, 1521,
        1723, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443,
    },
    "full": set(range(1, 1025)),
}

_TOP_PORTS_LIST: List[int] = sorted(
    PROFILE_PORTS["common"]
    | PROFILE_PORTS["web"]
    | PROFILE_PORTS["database"]
    | set(range(1, 201))
)

def top_ports(n: int) -> Set[int]:
    return set(_TOP_PORTS_LIST[: min(n, len(_TOP_PORTS_LIST))])

def parse_port_spec(spec: str) -> Set[int]:
    """
    Parse port specification into a set of ints.
    Supports: single (22), range (1-1024), list (80,443), mixed (1-1024,3306).
    """
    ports: Set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                start, end = int(a), int(b)
            except ValueError:
                raise ValueError(f"Invalid port range '{part}'")
            if not (1 <= start <= end <= 65535):
                raise ValueError(f"Port range out of bounds: '{part}'")
            ports.update(range(start, end + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"Invalid port '{part}'")
            if not (1 <= p <= 65535):
                raise ValueError(f"Port out of range: {p}")
            ports.add(p)
    return ports


# ══════════════════════════════════════════════════════════════
#  RATE LIMITER
# ══════════════════════════════════════════════════════════════
class RateLimiter:
    """Thread-safe token bucket: limits to `rate` operations/second."""
    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._lock = threading.Lock()
        self._next = time.monotonic()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next = now + (1.0 / self.rate)


# ══════════════════════════════════════════════════════════════
#  HOST RESOLUTION
# ══════════════════════════════════════════════════════════════
def expand_target(spec: str) -> List[str]:
    """
    Expand a single spec into one or more IP strings.
    Handles: plain IPv4, hostname, IPv4 CIDR.
    """
    spec = spec.strip()
    if not spec or spec.startswith("#"):
        return []
    if "/" in spec:
        try:
            net = ipaddress.ip_network(spec, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            pass
    return [spec]


def resolve_targets(
    single: Optional[str],
    filename: Optional[str],
) -> List[Dict[str, str]]:
    """
    Build deduplicated list of {address, ip} dicts from -a and/or -f.
    """
    raw: List[str] = []
    if single:
        raw.extend(expand_target(single))
    if filename:
        if not os.path.isfile(filename):
            print(f"{C.RED}[!] Host file not found: '{filename}'{C.RESET}", file=sys.stderr)
            sys.exit(1)
        with open(filename, "r", encoding="utf-8") as fh:
            for line in fh:
                raw.extend(expand_target(line))

    if not raw:
        print(f"{C.RED}[!] No targets specified.{C.RESET}", file=sys.stderr)
        sys.exit(1)

    seen: Dict[str, Dict[str, str]] = {}
    for target in raw:
        ip_str: Optional[str] = None
        try:
            ipaddress.ip_address(target)
            ip_str = target
        except ValueError:
            try:
                ip_str = socket.gethostbyname(target)
            except socket.gaierror:
                print(f"{C.YELLOW}[!] Cannot resolve '{target}' — skipping.{C.RESET}")
                continue
        if ip_str and ip_str not in seen:
            seen[ip_str] = {"address": target, "ip": ip_str}

    if not seen:
        print(f"{C.RED}[!] No resolvable targets.{C.RESET}", file=sys.stderr)
        sys.exit(1)
    return list(seen.values())


# ══════════════════════════════════════════════════════════════
#  OS DETECTION & REVERSE DNS & TRACEROUTE
# ══════════════════════════════════════════════════════════════
def reverse_dns(ip: str) -> Optional[str]:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None


def detect_os_ttl(ip: str, timeout: float = 3.0) -> Tuple[Optional[str], Optional[int]]:
    """
    Ping once and read TTL from the reply.
    TTL <= 64   → Linux / Unix / macOS
    TTL <= 128  → Windows
    TTL >  128  → Network device / router
    """
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 1,
        )
        m = re.search(r"ttl=(\d+)", proc.stdout + proc.stderr, re.IGNORECASE)
        if not m:
            return None, None
        ttl = int(m.group(1))
        if ttl <= 64:
            guess = "Linux/Unix/macOS"
        elif ttl <= 128:
            guess = "Windows"
        else:
            guess = "Network device/router"
        return guess, ttl
    except Exception:
        return None, None


def do_traceroute(ip: str, max_hops: int = 30, timeout: float = 3.0) -> List[Tuple[int, str]]:
    """
    Trace route to `ip` using ping -c1 -t TTL (no raw sockets, no sudo).
    Returns list of (hop_number, ip_or_asterisk).
    """
    hops: List[Tuple[int, str]] = []
    for ttl in range(1, max_hops + 1):
        try:
            proc = subprocess.run(
                ["ping", "-c", "1", "-t", str(ttl),
                 "-W", str(max(1, int(timeout))), ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout + 1,
            )
            out = proc.stdout + proc.stderr
            # Intermediate hop: "From X.X.X.X: ..."
            m = re.search(r"From ([\d\.]+)", out)
            if m:
                hops.append((ttl, m.group(1)))
                continue
            # Destination reached: "bytes from X.X.X.X"
            m2 = re.search(r"bytes from ([\d\.]+)", out)
            if m2:
                hops.append((ttl, m2.group(1)))
                break
            hops.append((ttl, "*"))
        except Exception:
            hops.append((ttl, "*"))
            break
    return hops


# ══════════════════════════════════════════════════════════════
#  SERVICE & VERSION PARSING
# ══════════════════════════════════════════════════════════════
def parse_service_version(
    port: int, banner: Optional[str]
) -> Tuple[Optional[str], Optional[str]]:
    """
    Infer service name and version from a banner string.
    Returns (service, version).
    """
    if not banner:
        return None, None
    b = banner.strip()

    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
    if b.startswith("SSH-"):
        m = re.match(r"SSH-[\d\.]+-(.+)", b)
        return "ssh", m.group(1).strip() if m else None

    # SMTP: "220 mail.example.com ESMTP Postfix ..."
    if b.startswith("220 "):
        m = re.search(r"(Postfix|Exim|Sendmail|ESMTP)\s*([\d\.]*)", b, re.IGNORECASE)
        if m:
            svc = m.group(1).lower()
            ver = m.group(2).strip() or None
            return svc, ver
        return "smtp", None

    # HTTP Server header
    m = re.search(r"Server:\s*(.+)", b, re.IGNORECASE)
    if m:
        server_str = m.group(1).strip()
        # e.g. "nginx/1.18.0 (Ubuntu)"
        m2 = re.match(r"([A-Za-z0-9_\-\.]+)(?:/([^\s]+))?", server_str)
        if m2:
            return m2.group(1).lower(), m2.group(2)
        return "http", server_str

    # FTP: "220 ProFTPD ..."
    if b.startswith("220") and "FTP" in b.upper():
        return "ftp", None

    # Generic: first word of banner
    m = re.match(r"([A-Za-z0-9_\-\.]+)", b)
    if m:
        return m.group(1).lower(), None

    return None, None


# ══════════════════════════════════════════════════════════════
#  UDP PROBES
# ══════════════════════════════════════════════════════════════
def _dns_query() -> bytes:
    return (
        b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07version\x04bind\x00"
        b"\x00\x10\x00\x03"
    )

def _ntp_request() -> bytes:
    return b"\x1b" + b"\x00" * 47

def _snmp_get() -> bytes:
    return bytes([
        0x30, 0x26, 0x02, 0x01, 0x00,
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
        0xa0, 0x19,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x01, 0x00,
        0x02, 0x01, 0x00,
        0x30, 0x0b, 0x30, 0x09,
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,
        0x05, 0x00,
    ])

def _netbios_status() -> bytes:
    return (
        b"\xaa\xbb\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00"
        b"\x00\x21\x00\x01"
    )

def _ssdp_search() -> bytes:
    return (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"HOST:239.255.255.250:1900\r\n"
        b'MAN:"ssdp:discover"\r\n'
        b"MX:1\r\n"
        b"ST:ssdp:all\r\n\r\n"
    )

UDP_PROBES: Dict[int, bytes] = {
    53:   _dns_query(),
    123:  _ntp_request(),
    137:  _netbios_status(),
    161:  _snmp_get(),
    1900: _ssdp_search(),
    5353: _dns_query(),
}
UDP_GENERIC_PROBE = b"\x00\x00"


# ══════════════════════════════════════════════════════════════
#  TCP SCAN
# ══════════════════════════════════════════════════════════════
def scan_tcp(
    ip: str, port: int,
    timeout: float, retries: int,
    rate: RateLimiter, grab: bool,
) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    TCP connect scan with optional banner grab.
    Returns (state, service, version, banner).
    state: "open" | "closed" | "filtered"
    """
    last_state = "closed"
    for _ in range(max(1, retries)):
        rate.acquire()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            rc = sock.connect_ex((ip, port))
            if rc == 0:
                banner: Optional[str] = None
                if grab:
                    try:
                        if port in (80, 8080, 8000, 8081, 8888):
                            sock.sendall(
                                f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
                                .encode("ascii", errors="ignore")
                            )
                        else:
                            sock.sendall(b"\r\n")
                        sock.settimeout(timeout)
                        raw = sock.recv(1024)
                        if raw:
                            banner = raw.decode("utf-8", errors="ignore").strip()
                    except Exception:
                        banner = None
                service, version = parse_service_version(port, banner)
                return "open", service, version, banner
            # connect_ex non-zero: refused → closed
            last_state = "closed"
        except socket.timeout:
            last_state = "filtered"
        except OSError:
            last_state = "closed"
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return last_state, None, None, None


# ══════════════════════════════════════════════════════════════
#  UDP SCAN
# ══════════════════════════════════════════════════════════════
def scan_udp(
    ip: str, port: int,
    timeout: float, retries: int,
    rate: RateLimiter,
) -> Tuple[str, Optional[str], Optional[str], Optional[str]]:
    """
    UDP probe scan (no raw sockets — no root needed).
    Returns (state, service, version, banner).
    state: "open" | "open|filtered"
    """
    probe = UDP_PROBES.get(port, UDP_GENERIC_PROBE)
    for _ in range(max(1, retries)):
        rate.acquire()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(probe, (ip, port))
            data, _ = sock.recvfrom(1024)
            banner = data.decode("utf-8", errors="ignore").strip() or None
            service, version = parse_service_version(port, banner)
            return "open", service, version, banner
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass
    return "open|filtered", None, None, None


# ══════════════════════════════════════════════════════════════
#  SCAN AGGREGATOR & CHECKPOINT
# ══════════════════════════════════════════════════════════════
class CheckpointManager:
    """Writes scan progress to JSON atomically, at most once per second."""
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._last = 0.0

    def save(self, data: Dict[str, Any]) -> None:
        now = time.monotonic()
        with self._lock:
            if now - self._last < 1.0:
                return
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, indent=2)
                os.replace(tmp, self.path)
                self._last = now
            except Exception:
                pass

    def load(self) -> Optional[Dict[str, Any]]:
        if not os.path.isfile(self.path):
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            return None


class ScanData:
    """
    Thread-safe in-memory store for scan results.

    Structure:
    {
        "meta": {...},
        "hosts": {
            "<ip>": {
                "address":  str,
                "ip":       str,
                "hostname": str | null,
                "os": { "guess": str | null, "ttl": int | null },
                "ports": {
                    "tcp": { "<port>": { state, service, version, banner } },
                    "udp": { "<port>": { state, service, version, banner } },
                }
            }
        }
    }
    """
    def __init__(self) -> None:
        self._data: Dict[str, Any] = {"meta": {}, "hosts": {}}
        self._lock = threading.Lock()

    @property
    def raw(self) -> Dict[str, Any]:
        with self._lock:
            return self._data

    def set_meta(self, meta: Dict[str, Any]) -> None:
        with self._lock:
            self._data["meta"] = dict(meta)

    def add_host(
        self, ip: str, address: str,
        hostname: Optional[str],
        os_guess: Optional[str], os_ttl: Optional[int],
    ) -> None:
        with self._lock:
            hosts = self._data.setdefault("hosts", {})
            if ip not in hosts:
                hosts[ip] = {
                    "address":  address,
                    "ip":       ip,
                    "hostname": hostname,
                    "os":       {"guess": os_guess, "ttl": os_ttl},
                    "ports":    {"tcp": {}, "udp": {}},
                }

    def merge(self, other: Dict[str, Any]) -> None:
        """Merge checkpoint data — skips ports that are already recorded."""
        with self._lock:
            for ip, entry in other.get("hosts", {}).items():
                hosts = self._data.setdefault("hosts", {})
                if ip not in hosts:
                    hosts[ip] = entry
                else:
                    for proto in ("tcp", "udp"):
                        existing = hosts[ip].setdefault("ports", {}).setdefault(proto, {})
                        for port_str, pdata in entry.get("ports", {}).get(proto, {}).items():
                            if port_str not in existing:
                                existing[port_str] = pdata

    def has_result(self, ip: str, port: int, proto: str) -> bool:
        with self._lock:
            return (
                str(port)
                in self._data.get("hosts", {})
                .get(ip, {})
                .get("ports", {})
                .get(proto, {})
            )

    def record(
        self, ip: str, port: int, proto: str,
        state: str, service: Optional[str],
        version: Optional[str], banner: Optional[str],
    ) -> None:
        with self._lock:
            hosts = self._data.setdefault("hosts", {})
            host  = hosts.setdefault(ip, {
                "address":  ip, "ip": ip, "hostname": None,
                "os":       {"guess": None, "ttl": None},
                "ports":    {"tcp": {}, "udp": {}},
            })
            host.setdefault("ports", {}).setdefault(proto, {})[str(port)] = {
                "state":   state,
                "service": service,
                "version": version,
                "banner":  banner,
            }


# ══════════════════════════════════════════════════════════════
#  PROGRESS BAR
# ══════════════════════════════════════════════════════════════
class Progress:
    def __init__(self, total: int) -> None:
        self.total = max(total, 1)
        self._done = 0
        self._lock = threading.Lock()

    def tick(self) -> None:
        with self._lock:
            self._done += 1
            pct   = int((self._done / self.total) * 40)
            bar   = "█" * pct + "░" * (40 - pct)
            line  = (
                f"\r  {C.CYAN}[{bar}]{C.RESET} "
                f"{self._done}/{self.total}"
            )
            if sys.stdout.isatty():
                sys.stdout.write(line)
                sys.stdout.flush()

    def done(self) -> None:
        if sys.stdout.isatty():
            sys.stdout.write("\n")
            sys.stdout.flush()


# ══════════════════════════════════════════════════════════════
#  OUTPUT FORMATTERS
# ══════════════════════════════════════════════════════════════
OPEN_STATES = {"open", "open|filtered"}

SERVICE_MAP: Dict[int, str] = {
    20: "FTP-Data",    21: "FTP",          22: "SSH",
    23: "Telnet",      25: "SMTP",         53: "DNS",
    67: "DHCP",        68: "DHCP",         80: "HTTP",
    110: "POP3",       111: "RPC",         123: "NTP",
    135: "MSRPC",      137: "NetBIOS-NS",  138: "NetBIOS-DG",
    139: "NetBIOS",    143: "IMAP",        161: "SNMP",
    162: "SNMP-Trap",  389: "LDAP",        443: "HTTPS",
    445: "SMB",        465: "SMTPS",       500: "IKE/VPN",
    514: "Syslog",     587: "SMTP",        636: "LDAPS",
    993: "IMAPS",      995: "POP3S",       1080: "SOCKS",
    1433: "MSSQL",     1521: "Oracle-DB",  1723: "PPTP",
    1900: "SSDP",      2049: "NFS",        3306: "MySQL",
    3389: "RDP",       5353: "mDNS",       5432: "PostgreSQL",
    5900: "VNC",       6379: "Redis",      8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

def _svc(port: int, detected: Optional[str]) -> str:
    return detected or SERVICE_MAP.get(port, "unknown")


def format_cli(data: Dict[str, Any], verbose: bool, udp: bool) -> str:
    lines: List[str] = []
    meta  = data.get("meta", {})

    lines.append(f"\n{C.BOLD}{'═'*62}{C.RESET}")
    lines.append(f"  {C.BOLD}Jmap Scan Results{C.RESET}  |  {meta.get('timestamp','')}")
    lines.append(f"{C.BOLD}{'═'*62}{C.RESET}\n")

    hosts = data.get("hosts", {})
    if not hosts:
        lines.append(f"  {C.RED}No hosts in result.{C.RESET}")
        return "\n".join(lines)

    for ip in sorted(hosts.keys()):
        h   = hosts[ip]
        hn  = h.get("hostname")
        os_ = h.get("os", {})

        # Host header
        host_line = f"  {C.BOLD}{C.CYAN}{ip}{C.RESET}"
        if hn:
            host_line += f"  {C.DIM}({hn}){C.RESET}"
        if os_.get("guess"):
            ttl_str = f", ttl={os_['ttl']}" if os_.get("ttl") is not None else ""
            host_line += f"  {C.MAGENTA}[{os_['guess']}{ttl_str}]{C.RESET}"
        lines.append(host_line)
        lines.append(f"  {'─'*58}")

        ports_map = h.get("ports", {})
        any_result = False

        for proto in (["tcp"] if not udp else ["tcp", "udp"]):
            proto_ports = ports_map.get(proto, {})
            open_rows = []
            closed_rows = []
            for port_str in sorted(proto_ports.keys(), key=lambda x: int(x)):
                p     = int(port_str)
                pd    = proto_ports[port_str]
                state = pd.get("state", "")
                svc   = _svc(p, pd.get("service"))
                ver   = pd.get("version")
                svc_str = svc
                if ver:
                    svc_str += f" ({ver})"
                row = (p, proto, state, svc_str)
                if state in OPEN_STATES:
                    open_rows.append(row)
                elif verbose:
                    closed_rows.append(row)

            for (p, pr, state, svc_str) in open_rows:
                color = C.GREEN if state == "open" else C.YELLOW
                lines.append(
                    f"  {color}{p}/{pr}{C.RESET:<12} "
                    f"{color}{state:<16}{C.RESET} "
                    f"{svc_str}"
                )
                any_result = True

            if verbose:
                for (p, pr, state, svc_str) in closed_rows:
                    lines.append(
                        f"  {C.DIM}{p}/{pr}{'':<12} "
                        f"{state:<16} {svc_str}{C.RESET}"
                    )

        if not any_result:
            lines.append(f"  {C.DIM}No open ports found.{C.RESET}")
        lines.append("")

    return "\n".join(lines)


def write_output(
    data: Dict[str, Any],
    output_path: Optional[str],
    verbose: bool,
    udp: bool,
) -> None:
    if not output_path:
        print(format_cli(data, verbose, udp))
        return

    ext = os.path.splitext(output_path)[1].lower()

    try:
        if ext == ".txt":
            C.disable()
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(format_cli(data, verbose, udp))
            print(f"{C.GREEN}[+] Saved text report  → {output_path}{C.RESET}")

        elif ext == ".json":
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2)
            print(f"{C.GREEN}[+] Saved JSON report  → {output_path}{C.RESET}")

        elif ext == ".csv":
            hosts = data.get("hosts", {})
            with open(output_path, "w", encoding="utf-8", newline="") as fh:
                writer = csv.writer(fh)
                writer.writerow([
                    "ip","hostname","os_guess","os_ttl",
                    "protocol","port","state","service","version","banner",
                ])
                for ip, h in sorted(hosts.items()):
                    hn  = h.get("hostname","") or ""
                    os_ = h.get("os", {})
                    og  = os_.get("guess","") or ""
                    ot  = str(os_.get("ttl","")) if os_.get("ttl") is not None else ""
                    for proto in ("tcp","udp"):
                        for port_str, pd in sorted(
                            h.get("ports",{}).get(proto,{}).items(),
                            key=lambda kv: int(kv[0])
                        ):
                            writer.writerow([
                                ip, hn, og, ot, proto, port_str,
                                pd.get("state",""),
                                pd.get("service","") or "",
                                pd.get("version","") or "",
                                (pd.get("banner","") or "").replace("\n","\\n")[:120],
                            ])
            print(f"{C.GREEN}[+] Saved CSV report   → {output_path}{C.RESET}")

        elif ext == ".html":
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(_render_html(data))
            print(f"{C.GREEN}[+] Saved HTML report  → {output_path}{C.RESET}")

        else:
            print(
                f"{C.RED}[!] Unsupported extension '{ext}'. "
                f"Use .txt  .json  .csv  or  .html{C.RESET}",
                file=sys.stderr,
            )
    except PermissionError:
        print(f"{C.RED}[!] Permission denied writing to '{output_path}'{C.RESET}", file=sys.stderr)
    except OSError as e:
        print(f"{C.RED}[!] Failed to write '{output_path}': {e}{C.RESET}", file=sys.stderr)


def _render_html(data: Dict[str, Any]) -> str:
    meta = data.get("meta", {})
    rows: List[str] = []
    for ip, h in sorted(data.get("hosts", {}).items()):
        hn  = h.get("hostname","") or ""
        os_ = h.get("os", {})
        og  = os_.get("guess","") or ""
        ot  = str(os_.get("ttl","")) if os_.get("ttl") is not None else ""
        for proto in ("tcp","udp"):
            for port_str, pd in sorted(
                h.get("ports",{}).get(proto,{}).items(),
                key=lambda kv: int(kv[0])
            ):
                state = pd.get("state","")
                color = (
                    "#d4edda" if state == "open" else
                    "#fff3cd" if state == "open|filtered" else
                    "#f8f9fa"
                )
                banner = (pd.get("banner","") or "").replace("<","&lt;").replace(">","&gt;")
                rows.append(
                    f'<tr style="background:{color}">'
                    f"<td>{ip}</td><td>{hn}</td><td>{og}</td><td>{ot}</td>"
                    f"<td>{proto}</td><td>{port_str}</td><td><b>{state}</b></td>"
                    f"<td>{pd.get('service','') or ''}</td>"
                    f"<td>{pd.get('version','') or ''}</td>"
                    f"<td><pre>{banner[:200]}</pre></td></tr>"
                )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Jmap Scan Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:1.5em;background:#f5f5f5}}
h1{{color:#333}}
.meta{{background:#fff;border:1px solid #ccc;padding:.6em 1em;margin-bottom:1em}}
table{{border-collapse:collapse;width:100%;background:#fff}}
th,td{{border:1px solid #ccc;padding:4px 7px;font-size:.88em}}
th{{background:#e9ecef;text-align:left}}
pre{{margin:0;white-space:pre-wrap;word-wrap:break-word;font-size:.8em}}
</style>
</head><body>
<h1>Jmap Scan Report</h1>
<div class="meta">
  <strong>Version:</strong> {meta.get('version','')}&nbsp;&nbsp;
  <strong>Timestamp:</strong> {meta.get('timestamp','')}&nbsp;&nbsp;
  <strong>Command:</strong> <code>{meta.get('cmdline','')}</code>
</div>
<table>
<thead><tr>
  <th>IP</th><th>Hostname</th><th>OS Guess</th><th>TTL</th>
  <th>Proto</th><th>Port</th><th>State</th>
  <th>Service</th><th>Version</th><th>Banner</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
</body></html>"""


# ══════════════════════════════════════════════════════════════
#  DIFF
# ══════════════════════════════════════════════════════════════
def _summary(data: Dict[str, Any]) -> Dict[str, Dict[str, Dict[str, str]]]:
    out: Dict[str, Dict[str, Dict[str, str]]] = {}
    for ip, h in data.get("hosts", {}).items():
        out[ip] = {"tcp": {}, "udp": {}}
        for proto in ("tcp", "udp"):
            for port_str, pd in h.get("ports", {}).get(proto, {}).items():
                out[ip][proto][port_str] = pd.get("state","")
    return out


def diff_scans(
    old: Dict[str, Any], new: Dict[str, Any]
) -> Dict[str, Any]:
    os_ = _summary(old)
    ns_ = _summary(new)
    old_ips = set(os_)
    new_ips = set(ns_)

    changes: Dict[str, Any] = {
        "new_hosts":      sorted(new_ips - old_ips),
        "removed_hosts":  sorted(old_ips - new_ips),
        "new_open_ports": {},
        "closed_ports":   {},
    }

    for ip in sorted(old_ips & new_ips):
        for proto in ("tcp", "udp"):
            old_p = os_[ip].get(proto, {})
            new_p = ns_[ip].get(proto, {})

            newly_open = [
                (int(ps), ns)
                for ps, ns in new_p.items()
                if ns in OPEN_STATES and old_p.get(ps) not in OPEN_STATES
            ]
            newly_closed = [
                (int(ps), new_p.get(ps, "closed"))
                for ps, os in old_p.items()
                if os in OPEN_STATES and new_p.get(ps) not in OPEN_STATES
            ]

            if newly_open:
                changes["new_open_ports"].setdefault(ip, {}).setdefault(proto, []).extend(
                    sorted(newly_open)
                )
            if newly_closed:
                changes["closed_ports"].setdefault(ip, {}).setdefault(proto, []).extend(
                    sorted(newly_closed)
                )
    return changes


def print_diff(changes: Dict[str, Any]) -> None:
    new_h    = changes.get("new_hosts", [])
    rem_h    = changes.get("removed_hosts", [])
    new_open = changes.get("new_open_ports", {})
    closed   = changes.get("closed_ports", {})

    if not any([new_h, rem_h, new_open, closed]):
        print(f"  {C.DIM}No changes detected.{C.RESET}")
        return

    if new_h:
        print(f"{C.GREEN}  New hosts:{C.RESET}")
        for ip in new_h:
            print(f"    {C.GREEN}+{C.RESET} {ip}")
    if rem_h:
        print(f"{C.RED}  Removed hosts:{C.RESET}")
        for ip in rem_h:
            print(f"    {C.RED}-{C.RESET} {ip}")
    if new_open:
        print(f"{C.GREEN}  New open ports:{C.RESET}")
        for ip, per_proto in new_open.items():
            for proto, ports in per_proto.items():
                for port, state in ports:
                    print(f"    {C.GREEN}+{C.RESET} {ip}  {proto.upper()} {port}  {state}")
    if closed:
        print(f"{C.YELLOW}  Ports now closed:{C.RESET}")
        for ip, per_proto in closed.items():
            for proto, ports in per_proto.items():
                for port, state in ports:
                    print(f"    {C.YELLOW}-{C.RESET} {ip}  {proto.upper()} {port}  → {state}")


def perform_diff(f1: str, f2: str) -> None:
    for path in (f1, f2):
        if not os.path.isfile(path):
            print(f"{C.RED}[!] File not found: '{path}'{C.RESET}", file=sys.stderr)
            sys.exit(1)
    try:
        with open(f1, encoding="utf-8") as fh:
            d1 = json.load(fh)
        with open(f2, encoding="utf-8") as fh:
            d2 = json.load(fh)
    except json.JSONDecodeError as e:
        print(f"{C.RED}[!] Invalid JSON: {e}{C.RESET}", file=sys.stderr)
        sys.exit(1)
    changes = diff_scans(d1, d2)
    print_diff(changes)


# ══════════════════════════════════════════════════════════════
#  WATCH INTERVAL PARSER
# ══════════════════════════════════════════════════════════════
def parse_interval(s: str) -> float:
    s = s.strip().lower()
    m = re.fullmatch(r"(\d+)([smh]?)", s)
    if not m:
        raise ValueError(f"Invalid interval '{s}'. Use e.g. 30s, 5m, 1h")
    n = int(m.group(1))
    unit = m.group(2)
    return n * {"s": 1, "m": 60, "h": 3600, "": 1}[unit]


# ══════════════════════════════════════════════════════════════
#  CORE RUN_SCAN
# ══════════════════════════════════════════════════════════════
def run_scan(args: argparse.Namespace) -> Dict[str, Any]:
    """Execute one full scan pass and return scan_data dict."""
    targets = resolve_targets(args.address, args.address_file)

    # Build port set
    ports: Set[int] = set()
    if args.ports:
        try:
            ports.update(parse_port_spec(args.ports))
        except ValueError as e:
            print(f"{C.RED}[!] {e}{C.RESET}", file=sys.stderr)
            sys.exit(1)
    if args.profile:
        for name in args.profile:
            ports.update(PROFILE_PORTS.get(name, set()))
    if args.top:
        ports.update(top_ports(args.top))
    if not ports:
        ports = set(PROFILE_PORTS["common"])

    store   = ScanData()
    ckpt_mgr: Optional[CheckpointManager] = (
        CheckpointManager(args.checkpoint) if args.checkpoint else None
    )

    # Meta
    store.set_meta({
        "timestamp": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version":   VERSION,
        "cmdline":   " ".join(sys.argv),
    })

    # Host enrichment
    print(f"\n{C.CYAN}[*]{C.RESET} Resolving hosts, reverse DNS and OS detection...")
    for entry in targets:
        ip   = entry["ip"]
        addr = entry["address"]
        hn   = reverse_dns(ip)
        og, ot = detect_os_ttl(ip, timeout=args.timeout)
        store.add_host(ip, addr, hn, og, ot)
        label = f"{ip}"
        if hn:
            label += f" ({hn})"
        os_str = f"  {C.MAGENTA}[{og}, ttl={ot}]{C.RESET}" if og else ""
        print(f"  {C.GREEN}[+]{C.RESET} {label}{os_str}")

    # Traceroute
    if args.traceroute:
        for entry in targets:
            ip = entry["ip"]
            print(f"\n{C.CYAN}[*]{C.RESET} Traceroute → {ip}")
            hops = do_traceroute(ip, timeout=args.timeout)
            for hop, hop_ip in hops:
                print(f"  {hop:2d}  {hop_ip}")
        print()

    # Checkpoint resume
    if ckpt_mgr:
        cp = ckpt_mgr.load()
        if cp:
            store.merge(cp)
            print(f"{C.CYAN}[*]{C.RESET} Resumed from checkpoint: {args.checkpoint}")

    # Build task list — skip already checkpointed ports
    protos = ["tcp"] + (["udp"] if args.udp else [])
    tasks: List[Tuple[str, str, int]] = [
        (proto, entry["ip"], port)
        for entry in targets
        for port  in sorted(ports)
        for proto in protos
        if not store.has_result(entry["ip"], port, proto)
    ]

    total = len(tasks)
    if total == 0:
        print(f"{C.CYAN}[*]{C.RESET} Checkpoint complete — nothing left to scan.")
        return store.raw

    print(
        f"{C.CYAN}[*]{C.RESET} Scanning {len(targets)} host(s)  "
        f"| {len(ports)} port(s)  "
        f"| {len(protos)} protocol(s)  "
        f"| {total} total probes  "
        f"| {args.threads} threads"
    )

    rate    = RateLimiter(args.rate)
    prog    = Progress(total)

    def worker(proto: str, ip: str, port: int) -> None:
        try:
            if proto == "tcp":
                state, svc, ver, banner = scan_tcp(
                    ip, port, args.timeout, args.retries, rate, not args.no_banner
                )
            else:
                state, svc, ver, banner = scan_udp(
                    ip, port, args.timeout, args.retries, rate
                )
            store.record(ip, port, proto, state, svc, ver, banner)
        except Exception:
            store.record(ip, port, proto, "error", None, None, None)
        finally:
            prog.tick()
            if ckpt_mgr:
                ckpt_mgr.save(store.raw)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = [ex.submit(worker, proto, ip, port) for proto, ip, port in tasks]
        try:
            for f in concurrent.futures.as_completed(futures):
                f.result()
        except KeyboardInterrupt:
            print(f"\n{C.YELLOW}[!] Interrupted — partial results below.{C.RESET}")

    prog.done()

    # Final checkpoint flush
    if ckpt_mgr:
        ckpt_mgr.save(store.raw)

    return store.raw


# ══════════════════════════════════════════════════════════════
#  CLI ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════
def build_parser(cfg: Dict[str, Any]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Jmap",
        add_help=True,
        formatter_class=argparse.RawTextHelpFormatter,
        description="Jmap — Pure Python3 Network Scanner (no root required)",
        epilog=(
            "Examples:\n"
            "  Jmap -a 192.168.1.1 -p 22,80,443\n"
            "  Jmap -a 10.0.0.0/24 --profile web --top 50\n"
            "  Jmap -f hosts.txt --profile common -o scan.json\n"
            "  Jmap -a 192.168.1.1 -p 1-1024 --udp -t 2\n"
            "  Jmap --diff old.json new.json\n"
            "  Jmap -a 192.168.1.0/24 --watch 5m --profile common\n"
            "  Jmap -a 10.0.0.1 --traceroute --profile web\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"Jmap {VERSION}")
    parser.add_argument("--diff", nargs=2, metavar=("OLD_JSON","NEW_JSON"),
                        help="Compare two JSON scan files and show changes.")

    tgt = parser.add_argument_group("Targets")
    tgt.add_argument("-a","--address",
                     help="Single IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    tgt.add_argument("-f","--address-file", dest="address_file",
                     help="File with one host/IP/CIDR per line. # comments and blank lines ignored.")

    prt = parser.add_argument_group("Ports")
    prt.add_argument("-p","--ports",
                     help="Ports: 22  or  1-1024  or  80,443,8080  or  1-1024,3306")
    prt.add_argument("--profile", choices=list(PROFILE_PORTS.keys()), action="append",
                     help="Named port profile (repeatable). Choices: web, database, common, full")
    prt.add_argument("--top", type=int, metavar="N",
                     help="Add top N common ports to the scan.")

    opt = parser.add_argument_group("Scan options")
    opt.add_argument("--udp", action="store_true",
                     help="Also probe UDP ports (no root needed; open|filtered if no response).")
    opt.add_argument("--threads", type=int, default=cfg["threads"],
                     help=f"Parallel threads (default: {cfg['threads']})")
    opt.add_argument("--timeout", type=float, default=cfg["timeout"],
                     help=f"Socket timeout in seconds (default: {cfg['timeout']})")
    opt.add_argument("-t","--retries", type=int, default=cfg["retries"],
                     help=f"Retries per port (default: {cfg['retries']})")
    opt.add_argument("--rate", type=float, default=cfg["rate"],
                     help=f"Max probes/second, 0 = unlimited (default: {cfg['rate']})")
    opt.add_argument("--no-banner", action="store_true",
                     help="Disable TCP banner grabbing.")
    opt.add_argument("--traceroute", action="store_true",
                     help="Traceroute to each host before scanning (ping-based, no root).")

    out = parser.add_argument_group("Output")
    out.add_argument("-o","--output",
                     help="Output file. Extension selects format: .txt  .json  .csv  .html")
    out.add_argument("-v","--verbose", action="store_true",
                     help="Show closed and filtered ports too.")
    out.add_argument("--watch", metavar="INTERVAL",
                     help="Repeat scan every INTERVAL (e.g. 30s, 5m, 1h), printing only changes.")
    out.add_argument("--checkpoint", metavar="FILE",
                     help="Save/resume scan progress to a JSON file.")
    return parser


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main() -> None:
    print(BANNER)
    cfg    = load_config()
    parser = build_parser(cfg)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    # ── Diff mode ─────────────────────────────────────────────
    if args.diff:
        perform_diff(args.diff[0], args.diff[1])
        return

    # ── Validate ──────────────────────────────────────────────
    if not args.address and not args.address_file:
        print(f"{C.RED}[!] Specify a target: -a <IP/CIDR>  or  -f <file>{C.RESET}\n",
              file=sys.stderr)
        parser.print_help()
        sys.exit(1)

    if args.threads < 1 or args.threads > 2000:
        print(f"{C.RED}[!] --threads must be 1-2000{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if args.timeout <= 0:
        print(f"{C.RED}[!] --timeout must be > 0{C.RESET}", file=sys.stderr)
        sys.exit(1)

    if args.retries < 1:
        print(f"{C.RED}[!] --retries (-t) must be >= 1{C.RESET}", file=sys.stderr)
        sys.exit(1)

    # ── Watch mode ────────────────────────────────────────────
    if args.watch:
        try:
            interval = parse_interval(args.watch)
        except ValueError as e:
            print(f"{C.RED}[!] {e}{C.RESET}", file=sys.stderr)
            sys.exit(1)

        print(f"{C.CYAN}[*]{C.RESET} Watch mode — interval {interval:.0f}s")
        baseline = run_scan(args)
        write_output(baseline, args.output, args.verbose, args.udp)

        while True:
            print(f"\n{C.DIM}[*] Next scan in {interval:.0f}s... (Ctrl+C to stop){C.RESET}")
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}[!] Watch mode stopped.{C.RESET}")
                break
            new_data = run_scan(args)
            print(f"\n{C.BOLD}Changes since last scan:{C.RESET}")
            changes = diff_scans(baseline, new_data)
            print_diff(changes)
            baseline = new_data
        return

    # ── Single scan ───────────────────────────────────────────
    data = run_scan(args)
    write_output(data, args.output, args.verbose, args.udp)

    # Summary
    hosts      = data.get("hosts", {})
    open_tcp   = sum(
        1 for h in hosts.values()
        for pd in h.get("ports",{}).get("tcp",{}).values()
        if pd.get("state") == "open"
    )
    open_udp   = sum(
        1 for h in hosts.values()
        for pd in h.get("ports",{}).get("udp",{}).values()
        if pd.get("state") in OPEN_STATES
    )
    print(f"{C.BOLD}{'─'*62}{C.RESET}")
    print(
        f"  {C.GREEN}Done.{C.RESET}  {len(hosts)} host(s)  |  "
        f"{C.GREEN}{open_tcp} TCP open{C.RESET}"
        + (f"  |  {C.YELLOW}{open_udp} UDP open/filtered{C.RESET}" if args.udp else "")
    )
    print(f"{C.BOLD}{'─'*62}{C.RESET}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted.{C.RESET}", file=sys.stderr)
        sys.exit(1)
