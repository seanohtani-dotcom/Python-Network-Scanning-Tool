# Network Scanner Tool

A Python-based network scanning tool for authorized internal security testing.

## ⚠️ Security Disclaimer

**This tool is for AUTHORIZED security testing only.**

- Only use on networks you own or have explicit written permission to test
- Unauthorized network scanning may be illegal in your jurisdiction
- The tool includes rate limiting to avoid network overload
- No exploit functionality is included

## Features

- ✅ Detect active hosts (ping sweep)
- ✅ Scan for open TCP ports
- ✅ Identify common services on open ports
- ✅ Banner grabbing (optional)
- ✅ Multi-threaded scanning for speed
- ✅ Configurable timeout and thread settings
- ✅ Export results to JSON or CSV
- ✅ Clean terminal output with progress indicators
- ✅ Support for single IPs and CIDR ranges

## Requirements

- Python 3.6 or higher
- No external dependencies (uses standard library only)

## Installation

1. Clone or download this repository
2. Ensure Python 3.6+ is installed:
   ```
   python --version
   ```

No additional packages need to be installed - the tool uses only Python's standard library.

## Usage

### Basic Syntax

```bash
python network_scanner.py -t <target> [options]
```

### Examples

**Scan a single host (default ports 1-1000):**
```bash
python network_scanner.py -t 192.168.1.1
```

**Scan a subnet:**
```bash
python network_scanner.py -t 192.168.1.0/24
```

**Scan specific port range:**
```bash
python network_scanner.py -t 192.168.1.1 -p 20-443
```

**Scan with banner grabbing:**
```bash
python network_scanner.py -t 192.168.1.1 -p 1-1000 -b
```

**Export results to JSON:**
```bash
python network_scanner.py -t 192.168.1.0/24 -o results.json
```

**Export results to CSV:**
```bash
python network_scanner.py -t 192.168.1.1 -p 1-1000 -o results.csv
```

**Custom timeout and thread count:**
```bash
python network_scanner.py -t 192.168.1.1 --timeout 2 --threads 50
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `-t, --target` | Target IP or CIDR range (required) | - |
| `-p, --ports` | Port range to scan (e.g., 1-1000) | 1-1000 |
| `-b, --banner` | Enable banner grabbing | False |
| `-o, --output` | Export to file (.json or .csv) | - |
| `--timeout` | Socket timeout in seconds | 1.0 |
| `--threads` | Maximum number of threads | 100 |

### Help

```bash
python network_scanner.py -h
```

## Output Format

### Terminal Output

```
==============================================================
Network Scanner - Authorized Testing Only
==============================================================
Target: 192.168.1.0/24
Port Range: 1-1000
Hosts to scan: 254
==============================================================

[+] Host 192.168.1.1 is alive, scanning ports...
    [*] Port 22 open - SSH
    [*] Port 80 open - HTTP
    [*] Port 443 open - HTTPS

==============================================================
SCAN RESULTS
==============================================================

Host: 192.168.1.1
Status: ALIVE
Scan Time: 2024-01-15T10:30:45.123456
Open Ports (3):
  PORT     SERVICE              BANNER
  ----------------------------------------------------------
  22       SSH                  SSH-2.0-OpenSSH_8.2p1
  80       HTTP                 HTTP/1.1 200 OK
  443      HTTPS                N/A
```

### JSON Export Format

```json
[
  {
    "ip": "192.168.1.1",
    "alive": true,
    "scan_time": "2024-01-15T10:30:45.123456",
    "open_ports": [
      {
        "port": 22,
        "service": "SSH",
        "banner": "SSH-2.0-OpenSSH_8.2p1"
      }
    ]
  }
]
```

### CSV Export Format

```csv
IP,Status,Port,Service,Banner,Scan Time
192.168.1.1,ALIVE,22,SSH,SSH-2.0-OpenSSH_8.2p1,2024-01-15T10:30:45.123456
192.168.1.1,ALIVE,80,HTTP,HTTP/1.1 200 OK,2024-01-15T10:30:45.123456
```

## Technical Details

### Architecture

- **Ping Sweep**: Uses `subprocess` to execute system ping commands
- **Port Scanning**: Uses `socket` library for TCP connection attempts
- **Multi-threading**: Uses `concurrent.futures.ThreadPoolExecutor` for parallel scanning
- **Rate Limiting**: 0.1 second delay between host scans to avoid network overload

### Common Ports Detected

The tool recognizes these common services:
- FTP (20, 21)
- SSH (22)
- Telnet (23)
- SMTP (25)
- DNS (53)
- HTTP (80)
- POP3 (110)
- IMAP (143)
- HTTPS (443)
- SMB (445)
- MySQL (3306)
- RDP (3389)
- PostgreSQL (5432)
- VNC (5900)
- HTTP-Proxy (8080)
- HTTPS-Alt (8443)

### Performance Considerations

- Default thread count: 100 (adjustable)
- Default timeout: 1 second (adjustable)
- Rate limiting: 0.1s between hosts
- Suitable for small to medium networks (up to /24)

## Limitations

- TCP scanning only (no UDP support)
- Basic banner grabbing (may not work for all services)
- No OS detection or service version detection
- Requires appropriate network permissions
- May be blocked by firewalls or IDS/IPS systems

## Troubleshooting

**Permission denied errors:**
- Some systems require elevated privileges for ping
- Try running with `sudo` on Linux/Mac or as Administrator on Windows

**Slow scanning:**
- Reduce port range with `-p` flag
- Increase timeout with `--timeout` flag
- Adjust thread count with `--threads` flag

**No hosts found:**
- Verify network connectivity
- Check firewall settings
- Ensure ICMP is not blocked

## Legal Notice

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any network. Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA) in the United States and similar legislation in other countries.

## License

This tool is provided as-is for educational purposes. Use at your own risk.
