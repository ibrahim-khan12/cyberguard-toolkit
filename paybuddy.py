#!/usr/bin/env python3
"""
PayBuddy Cybersecurity Testing Toolkit - Main CLI Interface
Central command-line interface that coordinates all security testing modules with safety checks
"""

import argparse
import sys
import os
import time
import signal
from pathlib import Path
from datetime import datetime
import subprocess
import json

# Add src directory to path for imports
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
sys.path.append(src_path)

from identity_verifier import IdentityVerifier
from logger import SecurityLogger

class PayBuddyToolkit:
    def __init__(self):
        self.verifier = IdentityVerifier()
        self.logger = SecurityLogger()
        self.src_dir = Path(__file__).parent / "src"
        
        # Available modules
        self.modules = {
            'scan': {
                'file': 'port_scanner.py',
                'description': 'TCP port scanning with banner grabbing',
                'example': 'paybuddy.py scan 127.0.0.1 -p common'
            },
            'auth-test': {
                'file': 'auth_test.py',
                'description': 'Password policy checking and hash testing',
                'example': 'paybuddy.py auth-test --check "mypassword123"'
            },
            'stress': {
                'file': 'stress_test.py',
                'description': 'Load testing with auto-throttling',
                'example': 'paybuddy.py stress http://127.0.0.1 -c 50'
            },
            'footprint': {
                'file': 'web_discovery.py',
                'description': 'Directory and subdomain discovery',
                'example': 'paybuddy.py footprint 127.0.0.1 --directories'
            },
            'pcap': {
                'file': 'packet_capture.py',
                'description': 'Packet capture and analysis',
                'example': 'paybuddy.py pcap -c 100 -o capture.pcap'
            },
            'report': {
                'file': 'logger.py',
                'description': 'Generate security reports',
                'example': 'paybuddy.py report --generate-report docx'
            }
        }
    
    def print_banner(self):
        """Print the PayBuddy toolkit banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                     PayBuddy Cybersecurity Testing Toolkit                   ║
║                        Educational Security Assessment Suite                  ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║  Modules: Port Scan | Auth Test | Stress Test | Web Discovery | Packet Cap   ║
║  Safety:  Identity Verification | Consent Checks | Rate Limiting | Logging   ║
╚═══════════════════════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def list_modules(self):
        """List all available modules"""
        print("🛠️  Available Security Testing Modules:")
        print("=" * 60)
        
        for module_name, module_info in self.modules.items():
            print(f"📦 {module_name.upper()}")
            print(f"   Description: {module_info['description']}")
            print(f"   Example: {module_info['example']}")
            print()
        
        print("🔒 All modules include automatic identity verification and safety checks")
        print("📋 Use 'paybuddy.py <module> --help' for detailed options")
    
    def run_module(self, module_name, args):
        """Run a specific security module"""
        if module_name not in self.modules:
            print(f"❌ Unknown module: {module_name}")
            print("💡 Use 'paybuddy.py --list' to see available modules")
            return 1
        
        module_info = self.modules[module_name]
        module_file = self.src_dir / module_info['file']
        
        if not module_file.exists():
            print(f"❌ Module file not found: {module_file}")
            return 1
        
        # Log test start
        self.logger.log_test_start(
            f"{module_name.upper()} Module",
            args[0] if args else "unknown",
            config={'args': args}
        )
        
        start_time = time.time()
        
        try:
            # Execute module with arguments
            cmd = [sys.executable, str(module_file)] + args
            
            print(f"🚀 Executing {module_name.upper()} module...")
            print(f"⚡ Command: {' '.join(cmd[1:])}")
            print("-" * 60)
            
            # Run the module with proper signal handling
            try:
                result = subprocess.run(
                    cmd, 
                    cwd=self.src_dir,
                    timeout=300  # 5 minute timeout to prevent hanging
                )
            except subprocess.TimeoutExpired:
                print(f"\n⚠️  {module_name.upper()} module timed out after 5 minutes")
                return 1
            except KeyboardInterrupt:
                print(f"\n⚠️  {module_name.upper()} module interrupted by user (Ctrl+C)")
                return 1
            
            end_time = time.time()
            duration = end_time - start_time
            
            # Log test end
            self.logger.log_test_end(
                f"{module_name.upper()} Module",
                args[0] if args else "unknown",
                results={'exit_code': result.returncode},
                duration=duration
            )
            
            if result.returncode == 0:
                print("-" * 60)
                print(f"✅ {module_name.upper()} module completed successfully in {duration:.2f}s")
            else:
                print("-" * 60)
                print(f"❌ {module_name.upper()} module failed with exit code {result.returncode}")
                self.logger.log_error(
                    f"{module_name.upper()} module failed",
                    module=module_name,
                    details={'exit_code': result.returncode, 'args': args}
                )
            
            return result.returncode
            
        except KeyboardInterrupt:
            print(f"\n⚠️  {module_name.upper()} module interrupted by user")
            self.logger.log_error(
                f"{module_name.upper()} module interrupted",
                module=module_name
            )
            return 1
        except Exception as e:
            print(f"❌ Error running {module_name.upper()} module: {e}")
            self.logger.log_error(
                f"Failed to execute {module_name.upper()} module: {e}",
                module=module_name
            )
            return 1
    
    def run_comprehensive_scan(self, target, output_dir=None):
        """Run a comprehensive security scan using multiple modules"""
        if not output_dir:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_dir = Path(f"comprehensive_scan_{timestamp}")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        print(f"🎯 Starting comprehensive security assessment of {target}")
        print(f"📁 Results will be saved to: {output_dir}")
        print("=" * 80)
        
        # Log comprehensive scan start
        self.logger.log_test_start(
            "Comprehensive Security Scan",
            target,
            config={'output_dir': str(output_dir)}
        )
        
        overall_start_time = time.time()
        results = {}
        
        # Phase 1: Port Scanning
        print("🔍 Phase 1: Port Scanning")
        scan_result = self.run_module('scan', [
            target, 
            '-p', 'common',
            '-o', str(output_dir / 'port_scan_results.json'),
            '--format', 'json'
        ])
        results['port_scan'] = {'exit_code': scan_result, 'completed': scan_result == 0}
        
        if scan_result != 0:
            print("⚠️  Port scan failed, continuing with other tests...")
        
        print()
        
        # Phase 2: Web Discovery (if HTTP ports found or web target)
        if any(port in str(target).lower() for port in ['http', '80', '443', '8080']):
            print("🕸️ Phase 2: Web Discovery")
            web_result = self.run_module('footprint', [
                target,
                '--directories',
                '--subdomains',
                '-o', str(output_dir / 'web_discovery_results.json')
            ])
            results['web_discovery'] = {'exit_code': web_result, 'completed': web_result == 0}
            print()
        
        # Phase 3: Light Stress Testing (only for local targets)
        if any(local in target for local in ['127.', '10.', '192.168.', 'localhost', 'local']):
            print("⚡ Phase 3: Light Load Testing")
            if target.startswith('http'):
                stress_target = target
            else:
                stress_target = f"http://{target}"
            
            stress_result = self.run_module('stress', [
                stress_target,
                '-c', '10',  # Light load for safety
                '-d', '15',  # Short duration
                '-o', str(output_dir / 'stress_test_results.json')
            ])
            results['stress_test'] = {'exit_code': stress_result, 'completed': stress_result == 0}
            print()
        
        # Phase 4: Generate Comprehensive Report
        print("📄 Phase 4: Generating Comprehensive Report")
        report_result = self.run_module('report', [
            '--generate-report', 'txt',
            '-o', str(output_dir / 'comprehensive_report.txt')
        ])
        results['report'] = {'exit_code': report_result, 'completed': report_result == 0}
        
        # Calculate overall duration
        overall_duration = time.time() - overall_start_time
        
        # Log comprehensive scan end
        self.logger.log_test_end(
            "Comprehensive Security Scan",
            target,
            results=results,
            duration=overall_duration
        )
        
        # Summary
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE SCAN SUMMARY")
        print("=" * 80)
        
        successful_phases = sum(1 for r in results.values() if r['completed'])
        total_phases = len(results)
        
        print(f"🎯 Target: {target}")
        print(f"⏱️  Duration: {overall_duration:.2f} seconds")
        print(f"✅ Successful Phases: {successful_phases}/{total_phases}")
        print(f"📁 Results Directory: {output_dir.absolute()}")
        
        print(f"\n📋 Phase Results:")
        for phase, result in results.items():
            status = "✅ PASS" if result['completed'] else "❌ FAIL"
            print(f"  {phase.replace('_', ' ').title()}: {status}")
        
        # List output files
        print(f"\n📄 Generated Files:")
        for file in output_dir.glob('*'):
            if file.is_file():
                size = file.stat().st_size
                print(f"  {file.name} ({size} bytes)")
        
        return 0 if successful_phases > 0 else 1
    
    def show_status(self):
        """Show toolkit status and recent activity"""
        print("📊 PayBuddy Toolkit Status")
        print("=" * 40)
        
        # Check identity files
        identity_valid = self.verifier.identity_file.exists() and self.verifier.consent_file.exists()
        print(f"🔐 Identity Files: {'✅ Valid' if identity_valid else '❌ Missing'}")
        
        # Check log integrity
        try:
            current_hash = self.logger.calculate_file_hash(self.logger.log_file)
            with open(self.logger.integrity_file, 'r') as f:
                stored_hash = f.read().strip()
            
            integrity_valid = current_hash == stored_hash
            print(f"📝 Log Integrity: {'✅ Valid' if integrity_valid else '❌ Compromised'}")
        except:
            print(f"📝 Log Integrity: ⚠️ Unknown")
        
        # Recent log entries
        recent_logs = self.logger.get_log_entries()
        if recent_logs:
            print(f"📋 Recent Activity: {len(recent_logs)} log entries")
            print(f"🕒 Last Activity: {recent_logs[-1]['timestamp'] if recent_logs else 'None'}")
        else:
            print(f"📋 Recent Activity: No activity logged")
        
        # Check module availability
        print(f"🛠️  Available Modules: {len(self.modules)}")
        
        print("\n💡 Use 'paybuddy.py --help' for usage instructions")

def main():
    # Set up signal handler for graceful shutdown
    def signal_handler(signum, frame):
        print("\n⚠️  PayBuddy interrupted by user (Ctrl+C)")
        sys.exit(1)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description='PayBuddy Cybersecurity Testing Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  paybuddy.py scan 127.0.0.1 -p common                    # Port scan localhost
  paybuddy.py auth-test --check "password123"             # Check password strength
  paybuddy.py stress http://127.0.0.1 -c 50               # Stress test web server
  paybuddy.py footprint example.local --directories       # Web discovery
  paybuddy.py pcap -c 100 -o capture.pcap                # Packet capture
  paybuddy.py report --generate-report docx               # Generate report
  paybuddy.py --comprehensive 127.0.0.1                  # Run all tests
  paybuddy.py --status                                    # Show toolkit status

Safety Features:
  • Automatic identity and consent verification
  • Rate limiting and auto-throttling
  • Comprehensive logging with integrity checks
  • Built-in safety limits and warnings
        """
    )
    
    # Global options
    parser.add_argument('--list', action='store_true', help='List available modules')
    parser.add_argument('--status', action='store_true', help='Show toolkit status')
    parser.add_argument('--comprehensive', metavar='TARGET', help='Run comprehensive scan on target')
    parser.add_argument('--output-dir', help='Output directory for comprehensive scan')
    parser.add_argument('--identity', action='store_true', help='Verify identity only')
    parser.add_argument('--dry-run', action='store_true', help='Perform dry run (no actual testing)')
    
    # Module selection
    parser.add_argument('module', nargs='?', help='Module to run (scan, auth-test, stress, footprint, pcap, report)')
    parser.add_argument('args', nargs='*', help='Arguments to pass to the module')
    
    args, unknown_args = parser.parse_known_args()
    
    # Initialize toolkit
    toolkit = PayBuddyToolkit()
    
    # Show banner
    toolkit.print_banner()
    
    # Handle special commands
    if args.list:
        toolkit.list_modules()
        return 0
    
    if args.status:
        toolkit.show_status()
        return 0
    
    if args.identity:
        success = toolkit.verifier.verify_identity(dry_run=args.dry_run)
        return 0 if success else 1
    
    if args.comprehensive:
        return toolkit.run_comprehensive_scan(args.comprehensive, args.output_dir)
    
    # Run specific module
    if args.module:
        # Combine unknown args first (which contain flags like --check), then known positional args
        module_args = unknown_args + args.args[:]
        if args.dry_run:
            module_args.append('--dry-run')
        
        return toolkit.run_module(args.module, module_args)
    
    # No arguments provided - show help
    print("💡 PayBuddy Cybersecurity Testing Toolkit")
    print("   Use --help for detailed usage instructions")
    print("   Use --list to see available modules")
    print("   Use --status to check toolkit status")
    print("\n🚀 Quick Start:")
    print("   paybuddy.py scan 127.0.0.1")
    print("   paybuddy.py --comprehensive 127.0.0.1")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())