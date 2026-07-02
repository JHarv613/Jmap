# Jmap 🗺️

A pure Python 3 network port scanner and network mapper built for systems where you **cannot install packages**. No pip installs, no dependencies — just Python 3 and the standard library.

Built for and tested on **Ubuntu 22.04.5 LTS**.

---

## What's New in v2.0.0

- CIDR / subnet scanning (`192.168.1.0/24`)
- Scan profiles — `web`, `database`, `common`, `full`
- `--top N` most common ports
- UDP scanning (no root needed)
- OS detection via TTL
- Reverse DNS resolution
- Traceroute (ping-based, no root)
- Service version parsing from banners
- HTML report output
- Scan diff — compare two JSON scan files
- Watch mode — rescan on a schedule and show only changes
- Checkpoint / resume — pick up interrupted scans
- Config file (`~/.jmaprc`) for personal defaults
- `--update` flag in installer

---

## Features

- TCP port scanning — single port, range, list, or mixed
- UDP port scanning — protocol-aware probes, no root needed
- CIDR expansion — scan entire subnets in one command
- Scan profiles — built-in named port groups for common use cases
- Retry logic — retries closed/filtered ports N times before giving up
- Service detection — identifies 40+ services by port number
- Service version parsing — extracts version strings from SSH, HTTP, SMTP banners
- Banner grabbing — reads raw service banners from open ports
- OS detection — heuristic OS guess from ping TTL (no root)
- Reverse DNS — resolves IPs to hostnames automatically
- Traceroute — hop-by-hop path using ping, no raw sockets
- Scan from a file — one IP, hostname, or CIDR per line
- Flexible output — CLI, `.txt`, `.json`, `.csv`, `.html`
- Scan diff — compare two JSON results and highlight changes
- Watch mode — continuous monitoring with automatic diffing
- Checkpoint / resume — save progress and continue after interruption
- Config file — set personal defaults in `~/.jmaprc`
- Multi-threaded — configurable thread count for fast scans
- Rate limiting — cap probes/sec to protect small devices
- No root required — installs entirely to `~/.local/bin`
- Clean uninstall — removes all files and shell config entries

---

## Requirements

| Requirement | Detail |
|---|---|
| Python | 3.10+ (pre-installed on Ubuntu 22.04) |
| OS | Ubuntu 22.04.5 LTS (may work on other Linux distros) |
| Root / sudo | Not required |
| External packages | None |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/JHarv613/Jmap.git
cd Jmap

# Run the installer (no sudo needed)
chmod +x install.sh
./install.sh

# Activate in your current terminal
source ~/.bashrc.user

# Verify
Jmap --version
```

> In any new terminal after this, `Jmap` will be available automatically.

### Update

When a new version of `Jmap.py` is available:

```bash
./install.sh --update
```

This overwrites only the script — PATH and launcher are left untouched.

### Uninstall

```bash
./install.sh --uninstall
source ~/.bashrc.user
```

Removes the launcher, the library file, and the PATH block from `~/.bashrc.user` — nothing is left behind.

---

## Usage

```
Jmap -a <IP|CIDR> -p <PORT(S)> [OPTIONS]
Jmap -f <targets.txt> -p <PORT(S)> [OPTIONS]
Jmap --diff <old.json> <new.json>
```

Running `Jmap` with no arguments displays the full help screen.

---

## Flags

### Targets

| Flag | Description |
|---|---|
| `-a IP/CIDR` | Single IP, hostname, or CIDR (e.g. `192.168.1.0/24`) |
| `-f FILE` | File of targets — one IP, hostname, or CIDR per line |

### Ports

| Flag | Description |
|---|---|
| `-p PORT(S)` | Single (`22`), range (`1-1024`), list (`80,443`), or mixed (`1-1024,3306`) |
| `--profile NAME` | Named profile: `web`, `database`, `common`, `full` (repeatable) |
| `--top N` | Add the top N most commonly scanned ports |

### Scan Options

| Flag | Description |
|---|---|
| `--udp` | Also probe UDP ports (no root; `open\|filtered` if no response) |
| `-t / --retries N` | Retries per port before marking closed/filtered (default: 1) |
| `--timeout SECS` | Socket timeout in seconds (default: 1.0) |
| `--threads N` | Parallel threads (default: 100) |
| `--rate N` | Max probes per second, 0 = unlimited (default: 0) |
| `--no-banner` | Skip TCP banner grabbing |
| `--traceroute` | Ping-based traceroute to each host before scanning |

### Output

| Flag | Description |
|---|---|
| `-o FILE` | Save to file — extension selects format (see below) |
| `-v / --verbose` | Also show closed and filtered ports |
| `--watch INTERVAL` | Rescan every interval (e.g. `30s`, `5m`, `1h`), print only changes |
| `--checkpoint FILE` | Save/resume scan progress to a JSON file |

### Other

| Flag | Description |
|---|---|
| `--diff OLD NEW` | Compare two JSON scan files and print changes |
| `--version` | Show version and exit |

---

## Examples

```bash
# Single port
Jmap -a 192.168.1.1 -p 80

# Port range with 3 retries
Jmap -a 10.0.0.1 -p 1-1024 -t 3

# Specific ports
Jmap -a 10.0.0.1 -p 80,443,8080,3306

# Scan a whole subnet
Jmap -a 192.168.1.0/24 --profile common

# Use a profile
Jmap -a 10.0.0.1 --profile web
Jmap -a 10.0.0.1 --profile database

# Combine profile + extra ports
Jmap -a 10.0.0.1 --profile web -p 8888,9000

# Top 100 ports
Jmap -a 10.0.0.1 --top 100

# TCP + UDP
Jmap -a 10.0.0.1 -p 53,123,161 --udp

# Traceroute then scan
Jmap -a 10.0.0.1 --traceroute --profile web

# Save as JSON
Jmap -a 192.168.1.0/24 --profile common -o scan.json

# Save as HTML report
Jmap -a 192.168.1.0/24 --profile common -o report.html

# Save as CSV
Jmap -f targets.txt --profile common -o results.csv

# Diff two scans
Jmap --diff scan_monday.json scan_friday.json

# Watch mode — rescan every 5 minutes, show only changes
Jmap -a 192.168.1.0/24 --profile common --watch 5m

# Resume an interrupted scan
Jmap -a 192.168.1.0/24 -p 1-65535 --checkpoint progress.json
```

---

## Scan Profiles

| Profile | Ports included |
|---|---|
| `web` | HTTP, HTTPS, FTP, SMTP, IMAP, POP3 and common web ports |
| `database` | MySQL, PostgreSQL, MSSQL, Oracle, MongoDB, Redis, Elasticsearch |
| `common` | ~45 of the most commonly scanned ports across all categories |
| `full` | All ports 1–1024 |

Profiles can be stacked: `--profile web --profile database` unions both sets.

---

## UDP Notes

UDP is connectionless — responses are not guaranteed.

| Situation | Reported state |
|---|---|
| Got a response | `open` |
| No response after all retries | `open\|filtered` |

Protocol-aware probes are sent for well-known UDP services:

| Port | Protocol | Probe |
|---|---|---|
| 53 | DNS | DNS TXT query (`version.bind`) |
| 123 | NTP | NTP v3 client request |
| 137 | NetBIOS | Node Status Request |
| 161 | SNMP | v1 GetRequest for `sysDescr` |
| 1900 | SSDP | `M-SEARCH` discovery packet |
| 5353 | mDNS | DNS query (mDNS format) |
| All others | Generic | `\x00\x00` |

---

## Output Formats

| Extension | Format |
|---|---|
| *(none)* | Coloured CLI output only |
| `.txt` | Plain text — same layout as CLI, no colour codes |
| `.json` | Structured JSON — suitable for diffing and scripting |
| `.csv` | One row per port per host — import into spreadsheets or log tools |
| `.html` | Self-contained HTML report with colour-coded state table |

---

## Scan Diff

Compare any two `.json` scan outputs:

```bash
Jmap --diff scan_monday.json scan_friday.json
```

Output shows:

- New hosts discovered
- Hosts that disappeared
- Ports that opened since the last scan
- Ports that closed since the last scan

---

## Watch Mode

```bash
Jmap -a 192.168.1.0/24 --profile common --watch 5m
```

- First run prints full results
- Each subsequent run prints **only changes** since the previous scan
- Supports all interval formats: `30s`, `5m`, `1h`
- Press `Ctrl+C` to stop

---

## Checkpoint / Resume

For large scans that may be interrupted:

```bash
Jmap -a 192.168.1.0/24 -p 1-65535 --checkpoint progress.json
```

Progress is saved to `progress.json` continuously during the scan. If the scan is interrupted, re-run the exact same command and it will skip already-scanned ports and pick up where it left off.

---

## Config File (`~/.jmaprc`)

Set personal defaults so you don't retype them every time:

```ini
# ~/.jmaprc
threads = 150
timeout = 0.75
retries = 2
rate    = 200
```

Any CLI flag still overrides the config file value.

---

## Target File Format (`-f`)

One entry per line. Supports plain IPs, hostnames, and CIDRs.
Blank lines and lines beginning with `#` are ignored.

```
# Web servers
192.168.1.10
192.168.1.11

# Subnet
10.0.0.0/24

# By hostname
myserver.local

# This line is ignored
```

---

## Limitations

| Feature | Jmap | nmap |
|---|---|---|
| TCP connect scan | ✅ | ✅ |
| UDP scan (best-effort) | ✅ (no root) | ✅ |
| SYN / stealth scan | ❌ (needs raw sockets) | ✅ |
| OS fingerprinting | ⚠️ TTL heuristic only | ✅ Full fingerprint |
| Service version detection | ⚠️ Banner parsing only | ✅ |
| IPv6 | ❌ IPv4 only | ✅ |

---

## Repository Structure

```
Jmap/
├── Jmap.py        # Main scanner — pure Python 3 stdlib
├── install.sh     # Installer / updater / uninstaller (no root required)
└── README.md      # This file
```

---

## License

MIT License — free to use, modify, and distribute.

---

## Author

Joshua Harvey — BNEW RCE, Ericsson
