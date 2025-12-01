#!/usr/bin/env python3
"""
Port Scanner Module for PayBuddy Cybersecurity Testing Toolkit
TCP port scanning with banner grabbing and threaded implementation
"""

import socket
import threading
import json
import time
from datetime import datetime
import argparse
import ipaddress
from pathlib import Path
import queue
import sys
import os

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from identity_verifier import IdentityVerifier

class PortScanner:
    def __init__(self, max_threads=50, timeout=3):
        self.max_threads = max_threads
        self.timeout = timeout
        self.results = []
        self.lock = threading.Lock()
        self.thread_queue = queue.Queue()
        
        # Common services and their typical banners
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        
    def scan_port(self, host, port):
        """Scan a single port and attempt banner grabbing"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            start_time = time.time()
            result = sock.connect_ex((host, port))
            end_time = time.time()
            
            if result == 0:  # Port is open
                banner = ""
                service = self.common_ports.get(port, "Unknown")
                
                # Attempt banner grabbing
                try:
                    if port in [21, 22, 23, 25, 110]:  # Services that send banners immediately
                        sock.settimeout(2)
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    elif port in [80, 8080]:  # HTTP services
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        response = sock.recv(1024).decode('utf-8', errors='ignore')
                        if 'Server:' in response:
                            for line in response.split('\n'):
                                if line.strip().startswith('Server:'):
                                    banner = line.strip()
                                    break
                except:
                    pass  # Banner grabbing failed, but port is still open
                
                result_entry = {
                    'host': host,
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'banner': banner,
                    'response_time': round((end_time - start_time) * 1000, 2)
                }
                
                with self.lock:
                    self.results.append(result_entry)
                    print(f"[+] {host}:{port} - {service} - {banner[:50]}{'...' if len(banner) > 50 else ''}")
            
            sock.close()
            
        except Exception as e:
            pass  # Silently ignore connection errors for closed ports
    
    def worker(self):
        """Worker thread function"""
        while True:
            try:
                host, port = self.thread_queue.get(timeout=1)
                self.scan_port(host, port)
                self.thread_queue.task_done()
            except queue.Empty:
                break
            except Exception as e:
                self.thread_queue.task_done()
    
    def scan_host(self, host, ports):
        """Scan multiple ports on a host using threading"""
        print(f"🔍 Scanning {host} for {len(ports)} ports...")
        print(f"📊 Using {self.max_threads} threads with {self.timeout}s timeout")
        
        # Add all port scan tasks to queue
        for port in ports:
            self.thread_queue.put((host, port))
        
        # Start worker threads
        threads = []
        for i in range(min(self.max_threads, len(ports))):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all tasks to complete
        self.thread_queue.join()
        
        return self.results
    
    def parse_ports(self, port_string):
        """Parse port specification string"""
        ports = set()
        
        for part in port_string.split(','):
            part = part.strip()
            if '-' in part:
                # Range of ports
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            else:
                # Single port
                ports.add(int(part))
        
        return sorted(list(ports))
    
    def get_common_ports(self):
        """Return list of common ports to scan"""
        return sorted(list(self.common_ports.keys()))
    
    def export_results(self, output_file, format='json'):
        """Export scan results to file"""
        if not self.results:
            print("⚠️  No results to export")
            return
        
        # Add metadata
        scan_info = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_ports_scanned': len(self.results),
                'open_ports': len([r for r in self.results if r['status'] == 'open']),
                'scanner_version': 'PayBuddy PortScanner v1.0'
            },
            'results': self.results
        }
        
        try:
            # Ensure the directory exists
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                if format.lower() == 'json':
                    json.dump(scan_info, f, indent=2)
                elif format.lower() == 'html':
                    self._export_html(f, scan_info)
            
            print(f"📄 Results exported to: {output_file}")
            
        except Exception as e:
            print(f"❌ Error exporting results: {e}")
    
    def _export_html(self, f, scan_info):
        """Export results as HTML report"""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>PayBuddy Port Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; margin: 10px 0; border-radius: 5px; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #34495e; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .open { color: #27ae60; font-weight: bold; }
        .banner { font-family: monospace; font-size: 0.9em; max-width: 300px; word-break: break-all; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 PayBuddy Port Scan Report</h1>
        <p>Generated on: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Ports Scanned:</strong> {total_scanned}</p>
        <p><strong>Open Ports Found:</strong> {open_ports}</p>
        <p><strong>Scanner Version:</strong> {version}</p>
    </div>
    
    <h2>🎯 Scan Results</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Port</th>
            <th>Status</th>
            <th>Service</th>
            <th>Banner</th>
            <th>Response Time (ms)</th>
        </tr>
        {table_rows}
    </table>
</body>
</html>
        """
        
        # Generate table rows
        table_rows = ""
        for result in scan_info['results']:
            banner_text = result['banner'][:100] + ('...' if len(result['banner']) > 100 else '')
            table_rows += f"""
        <tr>
            <td>{result['host']}</td>
            <td>{result['port']}</td>
            <td class="open">{result['status']}</td>
            <td>{result['service']}</td>
            <td class="banner">{banner_text}</td>
            <td>{result['response_time']}</td>
        </tr>
            """
        
        html_content = html_template.format(
            timestamp=scan_info['scan_info']['timestamp'],
            total_scanned=scan_info['scan_info']['total_ports_scanned'],
            open_ports=scan_info['scan_info']['open_ports'],
            version=scan_info['scan_info']['scanner_version'],
            table_rows=table_rows
        )
        
        f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description='PayBuddy Port Scanner')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-p', '--ports', default='common', 
                       help='Ports to scan (e.g., "80,443,8080" or "1-1000" or "common")')
    parser.add_argument('-t', '--threads', type=int, default=50,
                       help='Maximum number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=3,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--format', choices=['json', 'html'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Verify identity without performing scan')
    
    args = parser.parse_args()
    
    # Verify identity first
    verifier = IdentityVerifier()
    if not verifier.verify_identity(dry_run=args.dry_run):
        return 1
    
    if args.dry_run:
        print("✅ Dry run completed - no actual scanning performed")
        return 0
    
    # Validate host
    try:
        ipaddress.ip_address(args.host)
    except ValueError:
        # Try to resolve hostname
        try:
            import socket
            args.host = socket.gethostbyname(args.host)
        except socket.gaierror:
            print(f"❌ Invalid host: {args.host}")
            return 1
    
    # Initialize scanner
    scanner = PortScanner(max_threads=args.threads, timeout=args.timeout)
    
    # Parse ports
    if args.ports.lower() == 'common':
        ports = scanner.get_common_ports()
    else:
        try:
            ports = scanner.parse_ports(args.ports)
        except ValueError as e:
            print(f"❌ Invalid port specification: {e}")
            return 1
    
    print(f"🎯 Starting port scan on {args.host}")
    print(f"📋 Ports to scan: {len(ports)}")
    
    start_time = time.time()
    
    # Perform scan
    try:
        results = scanner.scan_host(args.host, ports)
        end_time = time.time()
        
        print(f"\n✅ Scan completed in {end_time - start_time:.2f} seconds")
        print(f"📊 Found {len(results)} open ports")
        
        # Export results if requested
        if args.output:
            team_info = verifier.get_team_info()
            # Include registration number in filename
            if team_info['members']:
                reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                name = team_info['members'][0]['name'].replace(' ', '')
                base_name = f"scan_{reg_num}_{name}"
            else:
                base_name = "scan_000_Unknown"
            
            output_path = Path(args.output).parent / f"{base_name}.{args.format}"
            scanner.export_results(output_path, args.format)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())