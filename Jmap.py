#!/usr/bin/env python3
"""
Jmap - Network Port Scanner
Pure Python3 | No external dependencies | Ubuntu 22.04 LTS compatible
Author: Joshua Harvey
"""

import socket
import sys
import os
import json
import csv
import time
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from io import StringIO


# ══════════════════════════════════════════════════════════════
#  COLORS
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
    def disable():
        """Disable colors (for file output)."""
        for attr in ["GREEN","RED","YELLOW","CYAN","MAGENTA","BLUE","BOLD","DIM","RESET"]:
            setattr(C, attr, "")


# ══════════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════════
VERSION = "1.0.0"

SERVICE_MAP = {
    20: "FTP-Data",    21: "FTP",          22: "SSH",
    23: "Telnet",      25: "SMTP",         53: "DNS",
    67: "DHCP",        68: "DHCP",         80: "HTTP",
    110: "POP3",       111: "RPC",         119: "NNTP",
    123: "NTP",        135: "MSRPC",       139: "NetBIOS",
    143: "IMAP",       161: "SNMP",        194: "IRC",
    389: "LDAP",       443: "HTTPS",       445: "SMB",
    465: "SMTPS",      514: "Syslog",      587: "SMTP",
    636: "LDAPS",      993: "IMAPS",       995: "POP3S",
    1080: "SOCKS",     1433: "MSSQL",      1521: "Oracle-DB",
    1723: "PPTP",      2049: "NFS",        2181: "ZooKeeper",
    3306: "MySQL",     3389: "RDP",        4444: "Metasploit",
    5432: "PostgreSQL",5900: "VNC",        6379: "Redis",
    6443: "Kubernetes",8080: "HTTP-Alt",   8443: "HTTPS-Alt",
    8888: "HTTP-Alt2", 9200: "Elasticsearch", 27017: "MongoDB",
}

BANNER = f"""
{C.CYAN}{C.BOLD}
     ██╗███╗   ███╗ █████╗ ██████╗ 
     ██║████╗ ████║██╔══██╗██╔══██╗
     ██║██╔████╔██║███████║██████╔╝
██   ██║██║╚██╔╝██║██╔══██║██╔═══╝ 
╚█████╔╝██║ ╚═╝ ██║██║  ██║██║     
 ╚════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{C.RESET}{C.DIM}  Pure Python3 Port Scanner  |  v{VERSION}  |  No Dependencies
{C.RESET}"""

USAGE_TEXT = f"""
{C.BOLD}USAGE:{C.RESET}
  Jmap -a <IP> -p <PORT(S)> [OPTIONS]
  Jmap -f <targets.txt> -p <PORT(S)> [OPTIONS]

{C.BOLD}TARGET (provide one):{C.RESET}
  {C.GREEN}-a  IP_ADDRESS{C.RESET}        Single target IP  (e.g. 192.168.1.1)
  {C.GREEN}-f  FILE.txt{C.RESET}          Text file, one IP per line

{C.BOLD}PORTS (required):{C.RESET}
  {C.GREEN}-p  PORT(S){C.RESET}           Supports three formats:
                         Single :  -p 22
                         Range  :  -p 1-1024
                         List   :  -p 80,443,8080

{C.BOLD}OPTIONS:{C.RESET}
  {C.YELLOW}-t  NUMBER{C.RESET}           Retries per port if closed/filtered (default: 1)
  {C.YELLOW}-o  FILE{C.RESET}             Save output to file:
                           .txt  → plain text (same as CLI view)
                           .json → structured JSON
                           .csv  → comma-separated values
  {C.YELLOW}--timeout SECS{C.RESET}      Connection timeout per attempt  (default: 0.5)
  {C.YELLOW}--threads NUM{C.RESET}       Parallel threads                (default: 100)
  {C.YELLOW}-v, --verbose{C.RESET}       Also show closed/filtered ports
  {C.YELLOW}--no-banner{C.RESET}         Skip service banner grabbing
  {C.YELLOW}--version{C.RESET}           Show version and exit

{C.BOLD}EXAMPLES:{C.RESET}
  {C.CYAN}Jmap -a 192.168.1.1 -p 80{C.RESET}
      Scan port 80 on a single host

  {C.CYAN}Jmap -a 10.0.0.1 -p 1-1024 -t 3{C.RESET}
      Scan ports 1-1024, retry closed ports 3 times

  {C.CYAN}Jmap -a 10.0.0.1 -p 80,443,8080 -o results.json{C.RESET}
      Scan specific ports and save as JSON

  {C.CYAN}Jmap -f targets.txt -p 22 -t 2 -o scan.csv{C.RESET}
      Scan port 22 on all IPs in file, save as CSV

  {C.CYAN}Jmap -f targets.txt -p 1-65535 --threads 200 -v{C.RESET}
      Full port scan on all file targets, verbose output

{C.BOLD}FILE FORMAT (-f):{C.RESET}
  One IP address per line. Blank lines and lines
  starting with # are ignored.

  Example targets.txt:
    192.168.1.1
    192.168.1.50
    10.0.0.1
    # this line is a comment and will be skipped
"""


# ══════════════════════════════════════════════════════════════
#  VALIDATION HELPERS
# ══════════════════════════════════════════════════════════════
def validate_ip(ip: str) -> str:
    """Validate an IP address string. Returns the IP or raises ValueError."""
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip}'")


def parse_ports(port_arg: str) -> list[int]:
    """
    Parse port argument into a sorted list of integers.
    Supports: single (80), range (1-1024), list (80,443,8080).
    """
    ports = set()
    try:
        for segment in port_arg.split(","):
            segment = segment.strip()
            if "-" in segment:
                parts = segment.split("-")
                if len(parts) != 2:
                    raise ValueError
                start, end = int(parts[0]), int(parts[1])
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(f"Port out of range in '{segment}'")
                if start > end:
                    raise ValueError(f"Start port > end port in '{segment}'")
                ports.update(range(start, end + 1))
            else:
                p = int(segment)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Port {p} is out of valid range (1-65535)")
                ports.add(p)
    except ValueError as e:
        raise ValueError(
            f"Invalid port specification '{port_arg}'. "
            f"Use: single (80), range (1-1024), or list (80,443,8080). Detail: {e}"
        )
    return sorted(ports)


def read_targets_file(filepath: str) -> list[str]:
    """
    Read IPs from a text file. One IP per line.
    Skips blank lines and lines starting with #.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Target file not found: '{filepath}'")

    targets = []
    errors  = []

    with open(filepath, "r") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                targets.append(validate_ip(line))
            except ValueError:
                errors.append(f"  Line {lineno}: '{line}' is not a valid IP — skipped")

    if not targets:
        raise ValueError(f"No valid IP addresses found in '{filepath}'")

    if errors:
        print(f"{C.YELLOW}[!] Skipped {len(errors)} invalid line(s) in '{filepath}':{C.RESET}")
        for e in errors:
            print(e)

    return targets


def validate_output_path(filepath: str) -> str:
    """Validate the output file path and extension."""
    allowed_extensions = {".txt", ".json", ".csv"}
    _, ext = os.path.splitext(filepath.lower())

    if ext not in allowed_extensions:
        raise ValueError(
            f"Output file must end in .txt, .json, or .csv — got '{ext}'"
        )

    parent_dir = os.path.dirname(os.path.abspath(filepath)) or "."
    if not os.path.isdir(parent_dir):
        raise FileNotFoundError(
            f"Output directory does not exist: '{parent_dir}'"
        )

    return filepath


# ══════════════════════════════════════════════════════════════
#  BANNER GRABBING
# ══════════════════════════════════════════════════════════════
def grab_banner(host: str, port: int, timeout: float = 1.5) -> str:
    """Attempt to read a service banner from an open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send an appropriate probe based on port
        if port in (80, 8080, 8000, 8888):
            sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        elif port == 443:
            pass  # TLS — skip banner, just note HTTPS
        else:
            sock.send(b"\r\n")

        data = sock.recv(512).decode(errors="replace").strip()
        sock.close()
        first_line = data.splitlines()[0] if data else ""
        return first_line[:70]
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════
#  CORE PORT SCANNER
# ══════════════════════════════════════════════════════════════
def scan_port(
    host: str,
    port: int,
    retries: int,
    timeout: float,
    grab_svc_banner: bool,
) -> dict:
    """
    Attempt a TCP connect scan on a single port.
    Retries up to `retries` times if the port appears closed/filtered.

    Returns a result dict:
      { host, port, state, service, banner, attempts }
    """
    service = SERVICE_MAP.get(port, "unknown")
    result = {
        "host":     host,
        "port":     port,
        "state":    "closed",
        "service":  service,
        "banner":   "",
        "attempts": 0,
    }

    for attempt in range(1, retries + 1):
        result["attempts"] = attempt
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            rc = sock.connect_ex((host, port))
            sock.close()

            if rc == 0:
                result["state"] = "open"
                if grab_svc_banner:
                    result["banner"] = grab_banner(host, port, timeout + 1.0)
                return result

        except socket.timeout:
            result["state"] = "filtered"
        except OSError:
            result["state"] = "closed"

        # Back off slightly between retries
        if attempt < retries:
            time.sleep(0.1 * attempt)

    return result


def scan_host(
    host: str,
    ports: list[int],
    retries: int,
    timeout: float,
    threads: int,
    grab_svc_banner: bool,
    verbose: bool,
    show_progress: bool = True,
) -> list[dict]:
    """
    Scan all specified ports on a single host using a thread pool.
    Returns list of result dicts for open (and optionally closed) ports.
    """
    results       = []
    total         = len(ports)
    completed     = 0

    with ThreadPoolExecutor(max_workers=min(threads, total)) as executor:
        future_map = {
            executor.submit(scan_port, host, p, retries, timeout, grab_svc_banner): p
            for p in ports
        }

        for future in as_completed(future_map):
            completed += 1
            r = future.result()

            if r["state"] == "open" or verbose:
                results.append(r)

            # Live progress bar
            if show_progress and sys.stdout.isatty():
                pct  = int((completed / total) * 40)
                bar  = "█" * pct + "░" * (40 - pct)
                open_count = sum(1 for x in results if x["state"] == "open")
                sys.stdout.write(
                    f"\r  {C.CYAN}[{bar}]{C.RESET} "
                    f"{completed}/{total} ports  "
                    f"{C.GREEN}{open_count} open{C.RESET}   "
                )
                sys.stdout.flush()

    if show_progress and sys.stdout.isatty():
        sys.stdout.write("\n")

    results.sort(key=lambda x: x["port"])
    return results


# ══════════════════════════════════════════════════════════════
#  HOST REACHABILITY CHECK
# ══════════════════════════════════════════════════════════════
def check_host_up(host: str, timeout: float = 1.0) -> bool:
    """
    Quick check if a host is reachable via TCP on common ports.
    (ICMP ping requires root; this works without elevated privileges.)
    """
    for probe_port in (22, 80, 443, 8080, 3389):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((host, probe_port)) == 0:
                sock.close()
                return True
            sock.close()
        except Exception:
            pass
    return False


# ══════════════════════════════════════════════════════════════
#  OUTPUT FORMATTERS
# ══════════════════════════════════════════════════════════════
def format_cli_results(
    host: str,
    results: list[dict],
    ports: list[int],
    retries: int,
    start_time: datetime,
    end_time: datetime,
    verbose: bool,
) -> str:
    """Format scan results as a coloured CLI string."""
    open_results   = [r for r in results if r["state"] == "open"]
    closed_results = [r for r in results if r["state"] != "open"]
    duration       = (end_time - start_time).total_seconds()

    lines = []
    lines.append(f"\n{C.BOLD}{'─'*60}{C.RESET}")
    lines.append(f"  {C.BOLD}Host    :{C.RESET}  {host}")
    lines.append(f"  {C.BOLD}Ports   :{C.RESET}  {len(ports)} scanned  |  Retries: {retries}")
    lines.append(f"  {C.BOLD}Started :{C.RESET}  {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"  {C.BOLD}Duration:{C.RESET}  {duration:.2f}s")
    lines.append(f"{C.BOLD}{'─'*60}{C.RESET}\n")

    if not open_results:
        lines.append(f"  {C.RED}No open ports found.{C.RESET}\n")
    else:
        header = f"  {'PORT':<12} {'STATE':<10} {'SERVICE':<16} {'BANNER'}"
        lines.append(f"{C.BOLD}{header}{C.RESET}")
        lines.append(f"  {'─'*58}")
        for r in open_results:
            banner_str = f"  {C.DIM}{r['banner']}{C.RESET}" if r["banner"] else ""
            lines.append(
                f"  {C.GREEN}{r['port']}/tcp{C.RESET:<12} "
                f"{'open':<10} "
                f"{r['service']:<16}"
                f"{banner_str}"
            )

    if verbose and closed_results:
        lines.append(f"\n{C.DIM}  {'PORT':<12} {'STATE':<10} {'SERVICE':<16}{C.RESET}")
        lines.append(f"  {C.DIM}{'─'*40}{C.RESET}")
        for r in closed_results:
            state_color = C.YELLOW if r["state"] == "filtered" else C.DIM
            lines.append(
                f"  {C.DIM}{r['port']}/tcp{C.RESET:<12} "
                f"{state_color}{r['state']:<10}{C.RESET} "
                f"{C.DIM}{r['service']:<16}{C.RESET}"
            )

    open_count = len(open_results)
    color = C.GREEN if open_count > 0 else C.RED
    lines.append(f"\n  {color}[+] {open_count} open port(s) found on {host}{C.RESET}")
    lines.append("")
    return "\n".join(lines)


def save_txt(filepath: str, all_results: list[dict], meta: dict):
    """Save results as plain text (mirrors CLI output, no colours)."""
    C.disable()   # strip ANSI for file
    with open(filepath, "w") as fh:
        fh.write(f"Jmap Scan Report\n")
        fh.write(f"Generated : {meta['timestamp']}\n")
        fh.write(f"Ports     : {meta['port_spec']}\n")
        fh.write(f"Retries   : {meta['retries']}\n")
        fh.write("=" * 60 + "\n\n")

        for entry in all_results:
            host    = entry["host"]
            results = entry["results"]
            duration = entry["duration"]
            open_r  = [r for r in results if r["state"] == "open"]

            fh.write(f"Host     : {host}\n")
            fh.write(f"Duration : {duration:.2f}s\n")
            fh.write(f"Open     : {len(open_r)} port(s)\n")
            fh.write("-" * 40 + "\n")

            if open_r:
                fh.write(f"  {'PORT':<12} {'STATE':<10} {'SERVICE':<16} BANNER\n")
                for r in open_r:
                    fh.write(
                        f"  {r['port']}/tcp{'':<8} "
                        f"{'open':<10} "
                        f"{r['service']:<16} "
                        f"{r['banner']}\n"
                    )
            else:
                fh.write("  No open ports found.\n")
            fh.write("\n")

        fh.write("=" * 60 + "\n")
        fh.write(f"Scan complete. Total hosts: {len(all_results)}\n")


def save_json(filepath: str, all_results: list[dict], meta: dict):
    """Save results as structured JSON."""
    output = {
        "jmap_version": VERSION,
        "scan_metadata": meta,
        "hosts": []
    }
    for entry in all_results:
        host_block = {
            "host":       entry["host"],
            "duration_s": round(entry["duration"], 3),
            "open_ports": [
                {
                    "port":    r["port"],
                    "state":   r["state"],
                    "service": r["service"],
                    "banner":  r["banner"],
                }
                for r in entry["results"] if r["state"] == "open"
            ],
            "all_ports": entry["results"] if meta.get("verbose") else None,
        }
        output["hosts"].append(host_block)

    with open(filepath, "w") as fh:
        json.dump(output, fh, indent=2)


def save_csv(filepath: str, all_results: list[dict], meta: dict):
    """Save results as CSV — one row per port per host."""
    with open(filepath, "w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "host", "port", "protocol", "state", "service", "banner",
            "attempts", "scan_time"
        ])
        for entry in all_results:
            for r in entry["results"]:
                if r["state"] == "open" or meta.get("verbose"):
                    writer.writerow([
                        entry["host"],
                        r["port"],
                        "tcp",
                        r["state"],
                        r["service"],
                        r["banner"],
                        r["attempts"],
                        meta["timestamp"],
                    ])


# ══════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ══════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="Jmap",
        add_help=False,   # We handle help ourselves for custom formatting
    )
    parser.add_argument("-a",  dest="address",   metavar="IP")
    parser.add_argument("-f",  dest="file",      metavar="FILE")
    parser.add_argument("-p",  dest="ports",     metavar="PORT(S)")
    parser.add_argument("-t",  dest="retries",   metavar="N",   type=int, default=1)
    parser.add_argument("-o",  dest="output",    metavar="FILE")
    parser.add_argument("--timeout",  dest="timeout",  type=float, default=0.5)
    parser.add_argument("--threads",  dest="threads",  type=int,   default=100)
    parser.add_argument("-v", "--verbose", action="store_true", default=False)
    parser.add_argument("--no-banner",    action="store_true", default=False)
    parser.add_argument("--version",      action="store_true", default=False)
    parser.add_argument("-h", "--help",   action="store_true", default=False)
    return parser


# ══════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════
def main():
    print(BANNER)

    parser = build_parser()
    args   = parser.parse_args()

    # ── Version ───────────────────────────────────────────────
    if args.version:
        print(f"  Jmap version {VERSION}")
        sys.exit(0)

    # ── Help / no args ────────────────────────────────────────
    if args.help or len(sys.argv) == 1:
        print(USAGE_TEXT)
        sys.exit(0)

    # ══════════════════════════════════════════════════════════
    #  INPUT VALIDATION
    # ══════════════════════════════════════════════════════════
    errors = []

    # Target: must have -a OR -f, not both
    if args.address and args.file:
        errors.append("[-] Use either -a (single IP) or -f (file), not both.")
    elif not args.address and not args.file:
        errors.append("[-] A target is required: use -a <IP> or -f <file>.")

    # Ports: required
    if not args.ports:
        errors.append("[-] Port(s) required: use -p (e.g. -p 80, -p 1-1024, -p 80,443)")

    # Retries: must be positive integer
    if args.retries < 1:
        errors.append(f"[-] Retries (-t) must be at least 1, got: {args.retries}")

    # Threads: reasonable range
    if not (1 <= args.threads <= 1000):
        errors.append(f"[-] Threads (--threads) must be between 1 and 1000, got: {args.threads}")

    # Timeout: positive
    if args.timeout <= 0:
        errors.append(f"[-] Timeout (--timeout) must be > 0, got: {args.timeout}")

    if errors:
        for e in errors:
            print(f"  {C.RED}{e}{C.RESET}")
        print(f"\n  {C.DIM}Run 'Jmap --help' for usage information.{C.RESET}\n")
        sys.exit(1)

    # ── Parse ports ───────────────────────────────────────────
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"  {C.RED}[-] {e}{C.RESET}")
        print(f"  {C.DIM}Run 'Jmap --help' for usage examples.{C.RESET}\n")
        sys.exit(1)

    # ── Validate IP / file ────────────────────────────────────
    targets = []
    if args.address:
        try:
            targets = [validate_ip(args.address)]
        except ValueError as e:
            print(f"  {C.RED}[-] {e}{C.RESET}\n")
            sys.exit(1)
    else:
        try:
            targets = read_targets_file(args.file)
        except (FileNotFoundError, ValueError) as e:
            print(f"  {C.RED}[-] {e}{C.RESET}\n")
            sys.exit(1)

    # ── Validate output path ──────────────────────────────────
    output_path = None
    if args.output:
        try:
            output_path = validate_output_path(args.output)
        except (ValueError, FileNotFoundError) as e:
            print(f"  {C.RED}[-] {e}{C.RESET}\n")
            sys.exit(1)

    # ══════════════════════════════════════════════════════════
    #  SCAN SUMMARY HEADER
    # ══════════════════════════════════════════════════════════
    _, ext = os.path.splitext(output_path.lower()) if output_path else ("", "")

    print(f"  {C.BOLD}Targets   :{C.RESET}  {len(targets)} host(s)")
    print(f"  {C.BOLD}Ports     :{C.RESET}  {len(ports)} port(s)  [{args.ports}]")
    print(f"  {C.BOLD}Retries   :{C.RESET}  {args.retries} per port")
    print(f"  {C.BOLD}Timeout   :{C.RESET}  {args.timeout}s  |  Threads: {args.threads}")
    print(f"  {C.BOLD}Output    :{C.RESET}  {output_path if output_path else 'CLI only'}")
    print(f"  {C.BOLD}Started   :{C.RESET}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # ══════════════════════════════════════════════════════════
    #  RUN SCANS
    # ══════════════════════════════════════════════════════════
    scan_timestamp  = datetime.now().isoformat()
    all_results     = []
    grab_banner_flag = not args.no_banner

    for idx, host in enumerate(targets, start=1):
        print(f"{C.CYAN}[{idx}/{len(targets)}]{C.RESET} Scanning {C.BOLD}{host}{C.RESET} ...")

        # Resolve hostname to IP (if given as hostname)
        try:
            resolved = socket.gethostbyname(host)
            if resolved != host:
                print(f"  {C.DIM}Resolved → {resolved}{C.RESET}")
        except socket.gaierror:
            print(f"  {C.RED}[-] Cannot resolve '{host}' — skipping.{C.RESET}\n")
            continue

        # Reachability probe
        if not check_host_up(host, timeout=args.timeout + 0.5):
            print(f"  {C.YELLOW}[!] Host may be down or blocking common probes — scanning anyway.{C.RESET}")

        t_start = datetime.now()
        results = scan_host(
            host            = host,
            ports           = ports,
            retries         = args.retries,
            timeout         = args.timeout,
            threads         = args.threads,
            grab_svc_banner = grab_banner_flag,
            verbose         = args.verbose,
            show_progress   = True,
        )
        t_end    = datetime.now()
        duration = (t_end - t_start).total_seconds()

        # Print CLI result
        cli_str = format_cli_results(
            host       = host,
            results    = results,
            ports      = ports,
            retries    = args.retries,
            start_time = t_start,
            end_time   = t_end,
            verbose    = args.verbose,
        )
        print(cli_str)

        all_results.append({
            "host":     host,
            "results":  results,
            "duration": duration,
        })

    # ══════════════════════════════════════════════════════════
    #  SAVE OUTPUT FILE (if -o provided)
    # ══════════════════════════════════════════════════════════
    if output_path:
        meta = {
            "timestamp":  scan_timestamp,
            "port_spec":  args.ports,
            "retries":    args.retries,
            "timeout":    args.timeout,
            "threads":    args.threads,
            "verbose":    args.verbose,
            "total_hosts": len(targets),
        }
        try:
            if ext == ".json":
                save_json(output_path, all_results, meta)
            elif ext == ".csv":
                save_csv(output_path, all_results, meta)
            else:  # .txt
                save_txt(output_path, all_results, meta)

            print(f"  {C.GREEN}[✓] Results saved to:{C.RESET} {output_path}\n")

        except PermissionError:
            print(f"  {C.RED}[-] Permission denied writing to '{output_path}'{C.RESET}\n")
            sys.exit(1)
        except OSError as e:
            print(f"  {C.RED}[-] Failed to save file: {e}{C.RESET}\n")
            sys.exit(1)

    # ══════════════════════════════════════════════════════════
    #  FINAL SUMMARY
    # ══════════════════════════════════════════════════════════
    total_open = sum(
        sum(1 for r in entry["results"] if r["state"] == "open")
        for entry in all_results
    )
    print(f"{C.BOLD}{'─'*60}{C.RESET}")
    print(f"  {C.GREEN}Scan complete.{C.RESET}  "
          f"{len(all_results)} host(s) scanned  |  "
          f"{C.GREEN}{total_open} total open port(s){C.RESET}")
    print(f"{C.BOLD}{'─'*60}{C.RESET}\n")


if __name__ == "__main__":
    main()
