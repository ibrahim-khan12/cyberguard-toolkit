#!/usr/bin/env python3
"""
Packet Capture & Analysis Module for PayBuddy Cybersecurity Testing Toolkit
Capture and analyze local lab traffic using Scapy with pcap saving and summary parsing
"""

import argparse
import json
import sys
import os
import time
import threading
import signal
from datetime import datetime
from pathlib import Path
from collections import defaultdict, Counter

# Import scapy components
try:
    from scapy.all import (
        sniff, wrpcap, rdpcap, get_if_list, get_if_addr,
        IP, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR, DNSRR,
        Raw, Padding
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from identity_verifier import IdentityVerifier

class PacketCapture:
    def __init__(self, interface=None, capture_filter=None):
        self.interface = interface
        self.capture_filter = capture_filter
        self.captured_packets = []
        self.capture_active = False
        self.capture_thread = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'protocols': Counter(),
            'ip_addresses': Counter(),
            'ports': Counter(),
            'dns_queries': [],
            'suspicious_activity': []
        }
        
    def list_interfaces(self):
        """List available network interfaces"""
        if not SCAPY_AVAILABLE:
            print("[ERROR] Scapy not available. Install with: pip install scapy")
            return []
        
        try:
            interfaces = get_if_list()
            print("[INFO] Available Network Interfaces:")
            for i, iface in enumerate(interfaces):
                try:
                    ip = get_if_addr(iface)
                    print(f"  {i}: {iface} ({ip})")
                except:
                    print(f"  {i}: {iface} (no IP)")
            return interfaces
        except Exception as e:
            print(f"[ERROR] Error listing interfaces: {e}")
            return []
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        try:
            self.captured_packets.append(packet)
            self.stats['total_packets'] += 1
            
            # Basic protocol analysis
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                self.stats['ip_addresses'][ip_layer.src] += 1
                self.stats['ip_addresses'][ip_layer.dst] += 1
                
                # TCP analysis
                if packet.haslayer(TCP):
                    self.stats['protocols']['TCP'] += 1
                    tcp_layer = packet[TCP]
                    self.stats['ports'][tcp_layer.sport] += 1
                    self.stats['ports'][tcp_layer.dport] += 1
                    
                    # Check for suspicious ports
                    if tcp_layer.dport in [4444, 5555, 6666, 31337]:  # Common backdoor ports
                        self.stats['suspicious_activity'].append({
                            'type': 'suspicious_port',
                            'src': ip_layer.src,
                            'dst': ip_layer.dst,
                            'port': tcp_layer.dport,
                            'timestamp': time.time()
                        })
                
                # UDP analysis
                elif packet.haslayer(UDP):
                    self.stats['protocols']['UDP'] += 1
                    udp_layer = packet[UDP]
                    self.stats['ports'][udp_layer.sport] += 1
                    self.stats['ports'][udp_layer.dport] += 1
                
                # ICMP analysis
                elif packet.haslayer(ICMP):
                    self.stats['protocols']['ICMP'] += 1
            
            # ARP analysis
            elif packet.haslayer(ARP):
                self.stats['protocols']['ARP'] += 1
                arp_layer = packet[ARP]
                
                # ARP spoofing detection (basic)
                if arp_layer.op == 2:  # ARP reply
                    self.stats['suspicious_activity'].append({
                        'type': 'arp_reply',
                        'src_ip': arp_layer.psrc,
                        'src_mac': arp_layer.hwsrc,
                        'timestamp': time.time()
                    })
            
            # DNS analysis
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns_layer = packet[DNS]
                query_layer = packet[DNSQR]
                
                self.stats['dns_queries'].append({
                    'query': query_layer.qname.decode('utf-8'),
                    'type': query_layer.qtype,
                    'timestamp': time.time()
                })
            
            # Real-time display for interesting packets
            if self.stats['total_packets'] % 100 == 0:
                print(f"[INFO] Captured {self.stats['total_packets']} packets...")
            
        except Exception as e:
            # Silently handle packet parsing errors
            pass
    
    def start_capture(self, count=0, timeout=None):
        """Start packet capture"""
        if not SCAPY_AVAILABLE:
            print("[ERROR] Scapy not available")
            return False
        
        print(f"[START] Starting packet capture...")
        print(f"   Interface: {self.interface or 'default'}")
        print(f"   Filter: {self.capture_filter or 'none'}")
        print(f"   Count: {'unlimited' if count == 0 else count}")
        print(f"   Timeout: {timeout or 'none'} seconds")
        print("   Press Ctrl+C to stop...")
        
        self.capture_active = True
        
        try:
            # Start capture
            packets = sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                store=1
            )
            
            self.capture_active = False
            print(f"\n[SUCCESS] Capture completed: {len(packets)} packets")
            return True
            
        except KeyboardInterrupt:
            self.capture_active = False
            print(f"\n[WARNING] Capture stopped by user")
            return True
        except Exception as e:
            self.capture_active = False
            print(f"[ERROR] Capture failed: {e}")
            return False
    
    def save_pcap(self, filename):
        """Save captured packets to PCAP file"""
        if not self.captured_packets:
            print("[WARNING] No packets to save")
            return False
        
        try:
            wrpcap(filename, self.captured_packets)
            print(f"[SAVED] Saved {len(self.captured_packets)} packets to {filename}")
            return True
        except Exception as e:
            print(f"[ERROR] Error saving PCAP: {e}")
            return False
    
    def load_pcap(self, filename):
        """Load packets from PCAP file for analysis"""
        try:
            packets = rdpcap(filename)
            print(f"[LOADED] Loaded {len(packets)} packets from {filename}")
            
            # Analyze loaded packets
            for packet in packets:
                self.packet_callback(packet)
            
            return True
        except Exception as e:
            print(f"[ERROR] Error loading PCAP: {e}")
            return False
    
    def analyze_packets(self):
        """Perform detailed analysis of captured packets"""
        if not self.captured_packets:
            print("[WARNING] No packets to analyze")
            return None
        
        analysis = {
            'summary': {
                'total_packets': self.stats['total_packets'],
                'capture_duration': 'unknown',
                'protocols': dict(self.stats['protocols']),
                'unique_ips': len(self.stats['ip_addresses']),
                'unique_ports': len(self.stats['ports'])
            },
            'top_sources': [],
            'top_destinations': [],
            'top_ports': [],
            'dns_analysis': {
                'total_queries': len(self.stats['dns_queries']),
                'unique_domains': [],
                'suspicious_domains': []
            },
            'security_analysis': {
                'suspicious_activity': self.stats['suspicious_activity'],
                'port_scan_detection': [],
                'unusual_traffic': []
            }
        }
        
        # Top IP addresses
        ip_counter = self.stats['ip_addresses']
        analysis['top_sources'] = ip_counter.most_common(10)
        
        # Top ports
        port_counter = self.stats['ports']
        analysis['top_ports'] = port_counter.most_common(10)
        
        # DNS analysis
        if self.stats['dns_queries']:
            domains = [q['query'] for q in self.stats['dns_queries']]
            domain_counter = Counter(domains)
            analysis['dns_analysis']['unique_domains'] = list(domain_counter.keys())
            
            # Check for suspicious domains
            suspicious_keywords = ['malware', 'phishing', 'botnet', 'c2', 'evil']
            for domain in domains:
                if any(keyword in domain.lower() for keyword in suspicious_keywords):
                    analysis['dns_analysis']['suspicious_domains'].append(domain)
        
        # Port scan detection (basic heuristic)
        src_port_counts = defaultdict(set)
        for packet in self.captured_packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                src_port_counts[src_ip].add(dst_port)
        
        # Flag IPs that accessed many different ports
        for src_ip, ports in src_port_counts.items():
            if len(ports) > 20:  # Threshold for port scan
                analysis['security_analysis']['port_scan_detection'].append({
                    'source_ip': src_ip,
                    'ports_accessed': len(ports),
                    'severity': 'high' if len(ports) > 100 else 'medium'
                })
        
        return analysis
    
    def generate_summary(self, analysis):
        """Generate human-readable summary"""
        if not analysis:
            return "No analysis data available"
        
        summary = []
        summary.append("[ANALYSIS] PACKET ANALYSIS SUMMARY")
        summary.append("=" * 40)
        
        # Basic stats
        stats = analysis['summary']
        summary.append(f"Total Packets: {stats['total_packets']}")
        summary.append(f"Unique IP Addresses: {stats['unique_ips']}")
        summary.append(f"Unique Ports: {stats['unique_ports']}")
        
        # Protocol breakdown
        summary.append("\n[PROTOCOLS] Protocol Distribution:")
        for protocol, count in stats['protocols'].items():
            percentage = (count / stats['total_packets']) * 100
            summary.append(f"  {protocol}: {count} ({percentage:.1f}%)")
        
        # Top communicating IPs
        if analysis['top_sources']:
            summary.append("\n[IPS] Top IP Addresses:")
            for ip, count in analysis['top_sources'][:5]:
                summary.append(f"  {ip}: {count} packets")
        
        # Top ports
        if analysis['top_ports']:
            summary.append("\n[PORTS] Top Ports:")
            for port, count in analysis['top_ports'][:5]:
                service = self.get_service_name(port)
                summary.append(f"  {port} ({service}): {count} packets")
        
        # DNS analysis
        dns = analysis['dns_analysis']
        if dns['total_queries'] > 0:
            summary.append(f"\n[DNS] DNS Queries: {dns['total_queries']}")
            summary.append(f"  Unique Domains: {len(dns['unique_domains'])}")
            
            if dns['suspicious_domains']:
                summary.append(f"  [WARNING] Suspicious Domains: {len(dns['suspicious_domains'])}")
        
        # Security analysis
        security = analysis['security_analysis']
        if security['port_scan_detection']:
            summary.append(f"\n[ALERTS] Security Alerts:")
            summary.append(f"  Potential Port Scans: {len(security['port_scan_detection'])}")
        
        if security['suspicious_activity']:
            summary.append(f"  Suspicious Activities: {len(security['suspicious_activity'])}")
        
        return "\n".join(summary)
    
    def get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL'
        }
        return services.get(port, 'Unknown')

def main():
    # Set up signal handler for graceful shutdown
    def signal_handler(signum, frame):
        print("\n[WARNING] Packet capture interrupted by user (Ctrl+C)")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(description='PayBuddy Packet Capture Tool')
    parser.add_argument('-i', '--interface', help='Network interface to capture on')
    parser.add_argument('-f', '--filter', help='BPF capture filter (e.g., "tcp port 80")')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('-t', '--timeout', type=int, help='Capture timeout in seconds')
    parser.add_argument('-o', '--output', help='Output PCAP filename')
    parser.add_argument('--analyze', help='Analyze existing PCAP file')
    parser.add_argument('--list-interfaces', action='store_true', help='List available interfaces')
    parser.add_argument('--dry-run', action='store_true', help='Verify identity without capturing')
    
    args = parser.parse_args()
    
    # Check if Scapy is available
    if not SCAPY_AVAILABLE:
        print("[ERROR] Scapy is not installed")
        print("   Install with: pip install scapy")
        print("   Note: May require administrator privileges")
        return 1
    
    # Verify identity first
    verifier = IdentityVerifier()
    if not verifier.verify_identity(dry_run=args.dry_run):
        return 1
    
    if args.dry_run:
        print("[SUCCESS] Dry run completed - no actual packet capture performed")
        return 0
    
    # Initialize packet capture
    capturer = PacketCapture(interface=args.interface, capture_filter=args.filter)
    
    print("[PCAP] PayBuddy Packet Capture Tool")
    print("=" * 50)
    
    # List interfaces if requested
    if args.list_interfaces:
        capturer.list_interfaces()
        return 0
    
    # Analyze existing PCAP file
    if args.analyze:
        if not Path(args.analyze).exists():
            print(f"[ERROR] PCAP file not found: {args.analyze}")
            return 1
        
        print(f"[ANALYZING] Analyzing PCAP file: {args.analyze}")
        capturer.load_pcap(args.analyze)
        
        analysis = capturer.analyze_packets()
        if analysis:
            summary = capturer.generate_summary(analysis)
            print("\n" + summary)
            
            # Save analysis results
            if args.output:
                team_info = verifier.get_team_info()
                
                # Include registration number in filename
                if team_info['members']:
                    reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                    name = team_info['members'][0]['name'].replace(' ', '')
                    analysis_file = Path(args.output).parent / f"pcap_analysis_{reg_num}_{name}.json"
                else:
                    analysis_file = Path(args.output).with_suffix('.json')
                
                export_data = {
                    'capture_info': {
                        'timestamp': datetime.now().isoformat(),
                        'tool_version': 'PayBuddy PacketCapture v1.0',
                        'source_file': args.analyze,
                        'team_info': team_info
                    },
                    'analysis': analysis,
                    'summary_text': summary
                }
                
                with open(analysis_file, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                print(f"[SAVED] Analysis saved to: {analysis_file}")
        
        return 0
    
    # Perform live capture
    print("[WARNING] Warning: Packet capture may require administrator privileges")
    print("[SECURITY] Only capturing on authorized lab networks")
    
    # Safety check
    if not args.interface:
        interfaces = capturer.list_interfaces()
        if interfaces:
            print("\n[INFO] Tip: Use -i <interface> to specify an interface")
    
    try:
        success = capturer.start_capture(count=args.count, timeout=args.timeout)
        
        if success and capturer.captured_packets:
            print(f"\n[STATS] Capture Statistics:")
            print(f"  Total packets: {len(capturer.captured_packets)}")
            print(f"  Protocols: {dict(capturer.stats['protocols'])}")
            
            # Save PCAP file
            if args.output:
                team_info = verifier.get_team_info()
                
                # Include registration number in filename
                if team_info['members']:
                    reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                    name = team_info['members'][0]['name'].replace(' ', '')
                    pcap_file = Path(args.output).parent / f"capture_{reg_num}_{name}.pcap"
                else:
                    pcap_file = Path(args.output).with_suffix('.pcap')
                
                capturer.save_pcap(pcap_file)
                
                # Analyze and save results
                analysis = capturer.analyze_packets()
                if analysis:
                    summary = capturer.generate_summary(analysis)
                    print("\n" + summary)
                    
                    # Save analysis
                    analysis_file = pcap_file.with_suffix('.json')
                    export_data = {
                        'capture_info': {
                            'timestamp': datetime.now().isoformat(),
                            'tool_version': 'PayBuddy PacketCapture v1.0',
                            'interface': args.interface,
                            'filter': args.filter,
                            'duration': args.timeout,
                            'team_info': team_info
                        },
                        'analysis': analysis,
                        'summary_text': summary
                    }
                    
                    with open(analysis_file, 'w') as f:
                        json.dump(export_data, f, indent=2)
                    
                    print(f"[SAVED] Analysis saved to: {analysis_file}")
        
        return 0
        
    except PermissionError:
        print("[ERROR] Permission denied. Try running as administrator/root")
        return 1
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())