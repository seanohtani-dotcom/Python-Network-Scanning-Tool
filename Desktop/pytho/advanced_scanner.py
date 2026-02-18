#!/usr/bin/env python3
"""
Advanced Network Scanner Tool
For authorized security testing only.
Includes OS detection, service fingerprinting, and vulnerability checks.
"""

import socket
import subprocess
import argparse
import ipaddress
import json
import csv
import sys
import time
import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Extended port database with more services
EXTENDED_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
    110: "POP3", 111: "RPC", 123: "NTP", 135: "MSRPC", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
    587: "SMTP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "HTTP-Alt", 27017: "MongoDB"
}

# OS fingerprinting signatures based on TTL and TCP window size
OS_SIGNATURES = {
    (64, 5840): "Linux 2.4/2.6",
    (64, 5720): "Linux 3.x",
    (64, 65535): "FreeBSD",
    (128, 65535): "Windows XP/7/8/10",
    (128, 8192): "Windows Vista/7",
    (255, 4128): "Cisco IOS",
    (255, 4096): "Solaris"
}

class AdvancedScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 100, verbose: bool = False):
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.results = []
    
    def log(self, message: str):
        """Print verbose logging messages."""
        if self.verbose:
            print(f"[DEBUG] {message}")
    
    def ping_host(self, ip: str) -> Tuple[bool, Optional[int]]:
        """Check if host is alive and get TTL value."""
        try:
            param = '-n' if sys.platform.startswith('win') else '-c'
            command = ['ping', param, '1', '-w' if sys.platform.startswith('win') else '-W',
                      str(int(self.timeout * 1000)) if sys.platform.startswith('win') else str(int(self.timeout)),
                      str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  timeout=self.timeout + 1, text=True)
            
            if result.returncode == 0:
                # Extract TTL from ping output
                ttl_match = re.search(r'TTL=(\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    return True, int(ttl_match.group(1))
                return True, None
            return False, None
        except Exception as e:
            self.log(f"Ping error for {ip}: {e}")
            return False, None
    
    def scan_port_advanced(self, ip: str, port: int) -> Dict:
        """Advanced port scan with service detection."""
        result = {
            'port': port,
            'state': 'closed',
            'service': EXTENDED_PORTS.get(port, 'Unknown'),
            'banner': '',
            'version': '',
            'ssl': False
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            connect_result = sock.connect_ex((str(ip), port))
            
            if connect_result == 0:
                result['state'] = 'open'
                
                # Try to grab banner
                try:
                    if port in [80, 8080, 8000, 8888]:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    elif port == 21:
                        pass  # FTP sends banner automatically
                    elif port == 22:
                        pass  # SSH sends banner automatically
                    elif port == 25:
                        sock.send(b'EHLO test\r\n')
                    else:
                        sock.send(b'\r\n')
                    
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner[:200]
                        result['version'] = self.extract_version(banner)
                except:
                    pass
                
                # Check for SSL/TLS
                if port in [443, 465, 636, 993, 995, 8443]:
                    result['ssl'] = self.check_ssl(ip, port)
            
            sock.close()
        except Exception as e:
            self.log(f"Port scan error {ip}:{port} - {e}")
        
        return result
    
    def extract_version(self, banner: str) -> str:
        """Extract version information from banner."""
        version_patterns = [
            r'(\d+\.\d+\.\d+)',
            r'Version\s+(\d+\.\d+)',
            r'v(\d+\.\d+)',
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return ''
    
    def check_ssl(self, ip: str, port: int) -> Dict:
        """Check SSL/TLS configuration."""
        ssl_info = {'enabled': False, 'version': '', 'cipher': ''}
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((str(ip), port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=str(ip)) as ssock:
                    ssl_info['enabled'] = True
                    ssl_info['version'] = ssock.version()
                    ssl_info['cipher'] = ssock.cipher()[0] if ssock.cipher() else ''
        except Exception as e:
            self.log(f"SSL check error {ip}:{port} - {e}")
        
        return ssl_info
    
    def detect_os(self, ip: str, ttl: Optional[int]) -> str:
        """Attempt OS detection based on TTL and other factors."""
        if ttl is None:
            return "Unknown"
        
        # TTL-based detection
        if ttl <= 64:
            return "Linux/Unix"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
        
        return "Unknown"

    def check_vulnerabilities(self, ip: str, open_ports: List[Dict]) -> List[Dict]:
        """Check for common vulnerabilities and misconfigurations."""
        vulnerabilities = []
        
        for port_info in open_ports:
            port = port_info['port']
            service = port_info['service']
            
            # Check for unencrypted services
            if port in [21, 23, 80, 8080] and port_info['state'] == 'open':
                vulnerabilities.append({
                    'port': port,
                    'severity': 'Medium',
                    'issue': f'Unencrypted {service} service detected',
                    'recommendation': f'Consider using encrypted alternative (SFTP, SSH, HTTPS)'
                })
            
            # Check for default/dangerous ports
            if port == 23 and port_info['state'] == 'open':
                vulnerabilities.append({
                    'port': port,
                    'severity': 'High',
                    'issue': 'Telnet service is insecure',
                    'recommendation': 'Disable Telnet and use SSH instead'
                })
            
            # Check for SMB
            if port == 445 and port_info['state'] == 'open':
                vulnerabilities.append({
                    'port': port,
                    'severity': 'Medium',
                    'issue': 'SMB service exposed',
                    'recommendation': 'Ensure SMB is properly secured and patched'
                })
            
            # Check for RDP
            if port == 3389 and port_info['state'] == 'open':
                vulnerabilities.append({
                    'port': port,
                    'severity': 'Medium',
                    'issue': 'RDP service exposed to network',
                    'recommendation': 'Use VPN or restrict access with firewall rules'
                })
            
            # Check for database ports
            if port in [3306, 5432, 1433, 27017] and port_info['state'] == 'open':
                vulnerabilities.append({
                    'port': port,
                    'severity': 'High',
                    'issue': f'Database service ({service}) exposed',
                    'recommendation': 'Database should not be directly accessible from network'
                })
        
        return vulnerabilities
    
    def scan_host_advanced(self, ip: str, port_range: Tuple[int, int], 
                          check_vulns: bool = False) -> Dict:
        """Perform advanced scan on a single host."""
        host_result = {
            'ip': str(ip),
            'alive': False,
            'ttl': None,
            'os_guess': 'Unknown',
            'scan_time': datetime.now().isoformat(),
            'open_ports': [],
            'vulnerabilities': []
        }
        
        # Check if host is alive
        is_alive, ttl = self.ping_host(ip)
        if not is_alive:
            return host_result
        
        host_result['alive'] = True
        host_result['ttl'] = ttl
        host_result['os_guess'] = self.detect_os(ip, ttl)
        
        print(f"[+] Host {ip} is alive (TTL: {ttl}, OS: {host_result['os_guess']})")
        
        # Scan ports
        start_port, end_port = port_range
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_port_advanced, ip, port): port
                      for port in range(start_port, end_port + 1)}
            
            for future in as_completed(futures):
                port_result = future.result()
                if port_result['state'] == 'open':
                    host_result['open_ports'].append(port_result)
                    ssl_status = f" [SSL: {port_result['ssl']['version']}]" if isinstance(port_result['ssl'], dict) and port_result['ssl'].get('enabled') else ""
                    version = f" v{port_result['version']}" if port_result['version'] else ""
                    print(f"    [*] Port {port_result['port']} open - {port_result['service']}{version}{ssl_status}")
        
        # Check for vulnerabilities
        if check_vulns and host_result['open_ports']:
            host_result['vulnerabilities'] = self.check_vulnerabilities(ip, host_result['open_ports'])
        
        return host_result
    
    def scan_network(self, target: str, port_range: Tuple[int, int], 
                    check_vulns: bool = False, fast_mode: bool = False):
        """Scan network with advanced features."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            
            print(f"\n{'='*70}")
            print(f"Advanced Network Scanner - Authorized Testing Only")
            print(f"{'='*70}")
            print(f"Target: {target}")
            print(f"Port Range: {port_range[0]}-{port_range[1]}")
            print(f"Hosts to scan: {len(hosts)}")
            print(f"Vulnerability Check: {'Enabled' if check_vulns else 'Disabled'}")
            print(f"Mode: {'Fast' if fast_mode else 'Normal'}")
            print(f"{'='*70}\n")
            
            for ip in hosts:
                result = self.scan_host_advanced(ip, port_range, check_vulns)
                if result['alive']:
                    self.results.append(result)
                    if not fast_mode:
                        time.sleep(0.1)  # Rate limiting
            
            self.display_results()
            
        except ValueError as e:
            print(f"[!] Invalid IP address or network: {e}")
            sys.exit(1)
    
    def display_results(self):
        """Display comprehensive scan results."""
        print(f"\n{'='*70}")
        print("SCAN RESULTS")
        print(f"{'='*70}\n")
        
        if not self.results:
            print("[!] No active hosts found.")
            return
        
        for host in self.results:
            print(f"{'─'*70}")
            print(f"Host: {host['ip']}")
            print(f"Status: {'ALIVE' if host['alive'] else 'DOWN'}")
            print(f"TTL: {host['ttl']}")
            print(f"OS Guess: {host['os_guess']}")
            print(f"Scan Time: {host['scan_time']}")
            
            if host['open_ports']:
                print(f"\nOpen Ports ({len(host['open_ports'])}):")
                print(f"  {'PORT':<8} {'SERVICE':<15} {'VERSION':<12} {'SSL':<10} {'BANNER':<25}")
                print(f"  {'-'*68}")
                for port_info in host['open_ports']:
                    ssl_status = 'Yes' if isinstance(port_info['ssl'], dict) and port_info['ssl'].get('enabled') else 'No'
                    banner = port_info['banner'][:25] if port_info['banner'] else 'N/A'
                    version = port_info['version'][:12] if port_info['version'] else 'N/A'
                    print(f"  {port_info['port']:<8} {port_info['service']:<15} {version:<12} {ssl_status:<10} {banner:<25}")
            else:
                print("\n  No open ports found in specified range.")
            
            if host['vulnerabilities']:
                print(f"\n⚠️  Vulnerabilities Found ({len(host['vulnerabilities'])}):")
                for vuln in host['vulnerabilities']:
                    print(f"  [{vuln['severity']}] Port {vuln['port']}: {vuln['issue']}")
                    print(f"      → {vuln['recommendation']}")
            
            print()
    
    def export_html(self, filename: str):
        """Export results to HTML report."""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .host {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .host-header {{ background: #4CAF50; color: white; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #333; color: white; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background: #f5f5f5; }}
        .vuln {{ background: #fff3cd; padding: 10px; margin: 10px 0; border-left: 4px solid #ffc107; }}
        .vuln.high {{ border-left-color: #dc3545; background: #f8d7da; }}
        .severity {{ font-weight: bold; }}
        .high {{ color: #dc3545; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #28a745; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Scan Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Hosts Scanned:</strong> {len(self.results)}</p>
"""
        
        for host in self.results:
            html_content += f"""
        <div class="host">
            <div class="host-header">
                <h2>Host: {host['ip']}</h2>
            </div>
            <p><strong>Status:</strong> {'✅ ALIVE' if host['alive'] else '❌ DOWN'}</p>
            <p><strong>TTL:</strong> {host['ttl']}</p>
            <p><strong>OS Guess:</strong> {host['os_guess']}</p>
            <p><strong>Scan Time:</strong> {host['scan_time']}</p>
"""
            
            if host['open_ports']:
                html_content += """
            <h3>Open Ports</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>SSL</th>
                    <th>Banner</th>
                </tr>
"""
                for port in host['open_ports']:
                    ssl_status = '✅' if isinstance(port['ssl'], dict) and port['ssl'].get('enabled') else '❌'
                    html_content += f"""
                <tr>
                    <td>{port['port']}</td>
                    <td>{port['service']}</td>
                    <td>{port['version'] or 'N/A'}</td>
                    <td>{ssl_status}</td>
                    <td>{port['banner'][:50] or 'N/A'}</td>
                </tr>
"""
                html_content += "            </table>\n"
            
            if host['vulnerabilities']:
                html_content += "            <h3>⚠️ Vulnerabilities</h3>\n"
                for vuln in host['vulnerabilities']:
                    severity_class = vuln['severity'].lower()
                    html_content += f"""
            <div class="vuln {severity_class}">
                <p><span class="severity {severity_class}">[{vuln['severity']}]</span> Port {vuln['port']}: {vuln['issue']}</p>
                <p><strong>Recommendation:</strong> {vuln['recommendation']}</p>
            </div>
"""
            
            html_content += "        </div>\n"
        
        html_content += """
    </div>
</body>
</html>
"""
        
        try:
            with open(filename, 'w') as f:
                f.write(html_content)
            print(f"[+] HTML report exported to {filename}")
        except Exception as e:
            print(f"[!] Error exporting HTML: {e}")
    
    def export_json(self, filename: str):
        """Export results to JSON."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Results exported to {filename}")
        except Exception as e:
            print(f"[!] Error exporting JSON: {e}")


def main():
    """Main function with enhanced CLI."""
    parser = argparse.ArgumentParser(
        description='Advanced Network Scanner - For authorized security testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic scan:
    python advanced_scanner.py -t 192.168.1.1
  
  Scan with vulnerability check:
    python advanced_scanner.py -t 192.168.1.0/24 -v
  
  Fast scan with HTML report:
    python advanced_scanner.py -t 10.0.0.0/24 -p 1-1000 --fast -o report.html
  
  Verbose mode with all features:
    python advanced_scanner.py -t 192.168.1.1 -p 1-65535 -v --verbose -o scan.json

Features:
  • OS Detection (TTL-based)
  • Service Version Detection
  • SSL/TLS Detection
  • Vulnerability Assessment
  • HTML Report Generation
  • Banner Grabbing

DISCLAIMER: This tool is for authorized security testing only.
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or CIDR range')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan. Default: 1-1000')
    parser.add_argument('-v', '--vulns', action='store_true',
                       help='Enable vulnerability checking')
    parser.add_argument('-o', '--output',
                       help='Export results (supports .json, .html)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds. Default: 1.0')
    parser.add_argument('--threads', type=int, default=100,
                       help='Maximum threads. Default: 100')
    parser.add_argument('--fast', action='store_true',
                       help='Fast mode (no rate limiting)')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose debug output')
    
    args = parser.parse_args()
    
    # Display disclaimer
    print("\n" + "="*70)
    print("⚠️  SECURITY DISCLAIMER ⚠️")
    print("="*70)
    print("This tool is for AUTHORIZED security testing only.")
    print("Unauthorized network scanning may be illegal.")
    print("Ensure you have explicit permission before scanning.")
    print("="*70 + "\n")
    
    response = input("Do you have authorization to scan this network? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("[!] Scan cancelled. Authorization required.")
        sys.exit(0)
    
    # Parse port range
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
        
        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        if start_port > end_port:
            raise ValueError("Start port must be <= end port")
    except ValueError as e:
        print(f"[!] Invalid port range: {e}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = AdvancedScanner(
        timeout=args.timeout,
        max_workers=args.threads,
        verbose=args.verbose
    )
    
    # Run scan
    try:
        start_time = time.time()
        scanner.scan_network(
            args.target,
            (start_port, end_port),
            check_vulns=args.vulns,
            fast_mode=args.fast
        )
        elapsed_time = time.time() - start_time
        
        print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
        
        # Export results
        if args.output:
            if args.output.endswith('.html'):
                scanner.export_html(args.output)
            elif args.output.endswith('.json'):
                scanner.export_json(args.output)
            else:
                print("[!] Unsupported format. Use .json or .html")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
