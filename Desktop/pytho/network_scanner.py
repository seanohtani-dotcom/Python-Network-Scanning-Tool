#!/usr/bin/env python3
"""
Network Scanner Tool
For authorized security testing only.
"""

import socket
import subprocess
import argparse
import ipaddress
import json
import csv
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Tuple

# Common ports and their services
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

class NetworkScanner:
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers
        self.results = []
    
    def ping_host(self, ip: str) -> bool:
        """Check if host is alive using ping."""
        try:
            param = '-n' if sys.platform.startswith('win') else '-c'
            command = ['ping', param, '1', '-w' if sys.platform.startswith('win') else '-W', 
                      str(int(self.timeout * 1000)) if sys.platform.startswith('win') else str(int(self.timeout)), 
                      str(ip)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout + 1)
            return result.returncode == 0
        except Exception:
            return False
    
    def scan_port(self, ip: str, port: int) -> Tuple[int, bool, str]:
        """Scan a single port on the target IP."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return (port, True, service)
            return (port, False, "")
        except Exception:
            return (port, False, "")
    
    def grab_banner(self, ip: str, port: int) -> str:
        """Attempt to grab banner from open port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((str(ip), port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else ""
        except Exception:
            return ""

    def scan_host(self, ip: str, port_range: Tuple[int, int], grab_banners: bool = False) -> Dict:
        """Scan all ports on a single host."""
        host_result = {
            'ip': str(ip),
            'alive': False,
            'scan_time': datetime.now().isoformat(),
            'open_ports': []
        }
        
        # Check if host is alive
        if not self.ping_host(ip):
            return host_result
        
        host_result['alive'] = True
        print(f"[+] Host {ip} is alive, scanning ports...")
        
        # Scan ports
        start_port, end_port = port_range
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port 
                      for port in range(start_port, end_port + 1)}
            
            for future in as_completed(futures):
                port, is_open, service = future.result()
                if is_open:
                    port_info = {
                        'port': port,
                        'service': service,
                        'banner': ''
                    }
                    
                    if grab_banners:
                        banner = self.grab_banner(ip, port)
                        port_info['banner'] = banner
                    
                    host_result['open_ports'].append(port_info)
                    print(f"    [*] Port {port} open - {service}")
        
        return host_result
    
    def scan_network(self, target: str, port_range: Tuple[int, int], grab_banners: bool = False):
        """Scan network range or single IP."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
            
            print(f"\n{'='*60}")
            print(f"Network Scanner - Authorized Testing Only")
            print(f"{'='*60}")
            print(f"Target: {target}")
            print(f"Port Range: {port_range[0]}-{port_range[1]}")
            print(f"Hosts to scan: {len(hosts)}")
            print(f"{'='*60}\n")
            
            for ip in hosts:
                result = self.scan_host(ip, port_range, grab_banners)
                if result['alive']:
                    self.results.append(result)
                    time.sleep(0.1)  # Rate limiting
            
            self.display_results()
            
        except ValueError as e:
            print(f"[!] Invalid IP address or network: {e}")
            sys.exit(1)
    
    def display_results(self):
        """Display scan results in terminal."""
        print(f"\n{'='*60}")
        print("SCAN RESULTS")
        print(f"{'='*60}\n")
        
        if not self.results:
            print("[!] No active hosts found.")
            return
        
        for host in self.results:
            print(f"Host: {host['ip']}")
            print(f"Status: {'ALIVE' if host['alive'] else 'DOWN'}")
            print(f"Scan Time: {host['scan_time']}")
            
            if host['open_ports']:
                print(f"Open Ports ({len(host['open_ports'])}):")
                print(f"  {'PORT':<8} {'SERVICE':<20} {'BANNER':<30}")
                print(f"  {'-'*58}")
                for port_info in host['open_ports']:
                    banner = port_info['banner'][:30] if port_info['banner'] else 'N/A'
                    print(f"  {port_info['port']:<8} {port_info['service']:<20} {banner:<30}")
            else:
                print("  No open ports found in specified range.")
            print()
    
    def export_json(self, filename: str):
        """Export results to JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Results exported to {filename}")
        except Exception as e:
            print(f"[!] Error exporting to JSON: {e}")
    
    def export_csv(self, filename: str):
        """Export results to CSV file."""
        try:
            with open(filename, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'Status', 'Port', 'Service', 'Banner', 'Scan Time'])
                
                for host in self.results:
                    if host['open_ports']:
                        for port_info in host['open_ports']:
                            writer.writerow([
                                host['ip'],
                                'ALIVE' if host['alive'] else 'DOWN',
                                port_info['port'],
                                port_info['service'],
                                port_info['banner'],
                                host['scan_time']
                            ])
                    else:
                        writer.writerow([
                            host['ip'],
                            'ALIVE' if host['alive'] else 'DOWN',
                            'N/A', 'N/A', 'N/A',
                            host['scan_time']
                        ])
            print(f"[+] Results exported to {filename}")
        except Exception as e:
            print(f"[!] Error exporting to CSV: {e}")


def main():
    """Main function with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description='Network Scanner - For authorized security testing only',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan single host:
    python network_scanner.py -t 192.168.1.1
  
  Scan subnet:
    python network_scanner.py -t 192.168.1.0/24 -p 1-1000
  
  Scan with banner grabbing and export:
    python network_scanner.py -t 10.0.0.0/24 -p 20-443 -b -o results.json
  
  Custom timeout and threads:
    python network_scanner.py -t 192.168.1.1 --timeout 2 --threads 50

DISCLAIMER: This tool is for authorized security testing only.
Unauthorized scanning of networks may be illegal.
        """
    )
    
    parser.add_argument('-t', '--target', required=True,
                       help='Target IP address or CIDR range (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='1-1000',
                       help='Port range to scan (e.g., 1-1000, 80-443). Default: 1-1000')
    parser.add_argument('-b', '--banner', action='store_true',
                       help='Enable banner grabbing')
    parser.add_argument('-o', '--output',
                       help='Export results to file (JSON or CSV based on extension)')
    parser.add_argument('--timeout', type=float, default=1.0,
                       help='Socket timeout in seconds. Default: 1.0')
    parser.add_argument('--threads', type=int, default=100,
                       help='Maximum number of threads. Default: 100')
    
    args = parser.parse_args()
    
    # Display disclaimer
    print("\n" + "="*60)
    print("⚠️  SECURITY DISCLAIMER ⚠️")
    print("="*60)
    print("This tool is for AUTHORIZED security testing only.")
    print("Unauthorized network scanning may be illegal in your jurisdiction.")
    print("Ensure you have explicit permission before scanning any network.")
    print("="*60 + "\n")
    
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
            raise ValueError("Start port must be less than or equal to end port")
    except ValueError as e:
        print(f"[!] Invalid port range: {e}")
        sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(timeout=args.timeout, max_workers=args.threads)
    
    # Run scan
    try:
        start_time = time.time()
        scanner.scan_network(args.target, (start_port, end_port), args.banner)
        elapsed_time = time.time() - start_time
        
        print(f"\n[+] Scan completed in {elapsed_time:.2f} seconds")
        
        # Export results if requested
        if args.output:
            if args.output.endswith('.json'):
                scanner.export_json(args.output)
            elif args.output.endswith('.csv'):
                scanner.export_csv(args.output)
            else:
                print("[!] Unsupported output format. Use .json or .csv extension.")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"[!] Error during scan: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
