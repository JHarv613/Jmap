# Jmap
A lightweight, pure Python 3 network port scanner built for systems where you cannot install packages. No pip installs, no dependencies — just Python 3 and the standard library.
Built for and tested on Ubuntu 22.04.5 LTS.

**Features**
TCP port scanning — single port, range, or comma-separated list
Retry logic — automatically retries closed/filtered ports N times before giving up
Service detection — identifies 40+ common services by port number
Banner grabbing — reads service banners from open ports
Host reachability check — probes the target before scanning
Scan from a file — provide a list of IPs in a text file, one per line
Flexible output — results display in the CLI by default, or save to .txt, .json, or .csv
Multi-threaded — configurable thread count for fast scans
No root required — installs entirely to ~/.local/bin
Clean uninstall — removes all files and shell config entries

**Requirement**
**Version**
Python 3.10+ (pre-installed on Ubuntu 22.04)
**OS**
Ubuntu 22.04.5 LTS (may work on other Linux distros)
**Not required**
Root / sudo
External packages


# Clone the repository
git clone https://github.com/yourusername/jmap.git
cd jmap

# Run the installer (no sudo needed)
chmod +x install.sh
./install.sh

# Activate in your current terminal
source ~/.bashrc.user

# Verify
Jmap --version

**Uninstall**
./install.sh --uninstall
This removes the launcher, the library file, and the PATH entry added to your shell config — nothing is left behind.

**Usage**
Jmap -a <IP> -p <PORT(S)> [OPTIONS]
Jmap -f <targets.txt> -p <PORT(S)> [OPTIONS]

Running Jmap with no arguments displays the full help screen.

**Output Formats**
CLI (default)
Coloured, human-readable output printed directly to the terminal when no -o flag is provided.
Plain text (.txt)
Same layout as the CLI view, stripped of colour codes — easy to read in any text editor.
JSON (.json)
Structured output suitable for scripting or further processing.

Joshua Harvey — BNEW RCE, Ericsson
