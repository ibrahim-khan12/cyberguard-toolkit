#!/usr/bin/env python3
"""
Web Discovery/Footprinting Module for PayBuddy Cybersecurity Testing Toolkit
Directory and subdomain finder with rate limiting and safe testing
"""

import asyncio
import aiohttp
import argparse
import json
import sys
import os
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse
import dns.resolver
import socket
import threading

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from identity_verifier import IdentityVerifier

class WebDiscovery:
    def __init__(self, rate_limit=2, timeout=10):
        self.rate_limit = rate_limit  # Requests per second
        self.timeout = timeout
        self.results = []
        self.discovered_paths = []
        self.discovered_subdomains = []
        
        # Common directories and files to check
        self.common_paths = [
            # Administrative directories
            '/admin', '/administrator', '/admin.php', '/admin.html',
            '/wp-admin', '/phpmyadmin', '/cpanel',
            
            # Configuration files
            '/config', '/config.php', '/configuration.php', '/settings.php',
            '/wp-config.php', '/.env', '/web.config',
            
            # Common directories
            '/api', '/assets', '/css', '/js', '/img', '/images',
            '/uploads', '/files', '/download', '/docs', '/documentation',
            '/backup', '/backups', '/tmp', '/temp',
            
            # Development/Debug
            '/test', '/testing', '/dev', '/development', '/debug',
            '/phpinfo.php', '/info.php', '/test.php',
            
            # Login pages
            '/login', '/signin', '/login.php', '/login.html',
            '/auth', '/authentication',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/favicon.ico',
            '/readme.txt', '/README.md', '/changelog.txt',
            
            # API endpoints
            '/api/v1', '/api/v2', '/rest', '/graphql',
            '/swagger', '/api-docs',
            
            # Payment specific (for FinTech)
            '/payment', '/wallet', '/transaction', '/balance',
            '/paypal', '/stripe', '/billing'
        ]
        
        # Common subdomain patterns
        self.subdomain_patterns = [
            'www', 'mail', 'ftp', 'admin', 'api', 'test', 'staging',
            'dev', 'beta', 'demo', 'app', 'mobile', 'secure',
            'payment', 'wallet', 'dashboard', 'panel', 'portal',
            'support', 'help', 'docs', 'blog', 'shop', 'store'
        ]
        
    async def check_directory(self, session, base_url, path):
        """Check if a directory/file exists"""
        url = urljoin(base_url, path)
        
        try:
            async with session.get(url, allow_redirects=False) as response:
                result = {
                    'url': url,
                    'path': path,
                    'status_code': response.status,
                    'content_length': response.headers.get('content-length', 0),
                    'content_type': response.headers.get('content-type', ''),
                    'server': response.headers.get('server', ''),
                    'redirect_location': response.headers.get('location', ''),
                    'timestamp': time.time()
                }
                
                # Classify the finding
                if response.status == 200:
                    result['status'] = 'found'
                    self.discovered_paths.append(path)
                elif response.status in [301, 302, 307, 308]:
                    result['status'] = 'redirect'
                    self.discovered_paths.append(path)
                elif response.status == 403:
                    result['status'] = 'forbidden'
                    self.discovered_paths.append(path)
                elif response.status == 401:
                    result['status'] = 'unauthorized'
                    self.discovered_paths.append(path)
                else:
                    result['status'] = 'not_found'
                
                return result
                
        except Exception as e:
            return {
                'url': url,
                'path': path,
                'status_code': 0,
                'status': 'error',
                'error': str(e),
                'timestamp': time.time()
            }
    
    async def directory_scan(self, base_url, custom_paths=None):
        """Scan for common directories and files"""
        paths_to_check = custom_paths if custom_paths else self.common_paths
        
        print(f"🔍 Scanning {len(paths_to_check)} paths on {base_url}")
        print(f"⚡ Rate limit: {self.rate_limit} requests/second")
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=10)
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            semaphore = asyncio.Semaphore(5)  # Limit concurrent requests
            
            async def check_with_limit(path):
                async with semaphore:
                    result = await self.check_directory(session, base_url, path)
                    
                    # Rate limiting
                    await asyncio.sleep(1.0 / self.rate_limit)
                    
                    if result['status'] in ['found', 'redirect', 'forbidden', 'unauthorized']:
                        status_icon = {
                            'found': '✅',
                            'redirect': '↩️',
                            'forbidden': '🔒',
                            'unauthorized': '🔑'
                        }
                        print(f"  {status_icon[result['status']]} {result['url']} ({result['status_code']})")
                    
                    return result
            
            # Execute all checks
            tasks = [check_with_limit(path) for path in paths_to_check]
            results = await asyncio.gather(*tasks)
            
            # Filter and store interesting results
            self.results.extend([r for r in results if r['status'] != 'not_found'])
            
            return [r for r in results if r['status'] in ['found', 'redirect', 'forbidden', 'unauthorized']]
    
    async def subdomain_scan(self, domain, custom_subdomains=None):
        """Scan for subdomains using DNS queries"""
        subdomains_to_check = custom_subdomains if custom_subdomains else self.subdomain_patterns
        
        print(f"🔍 Scanning {len(subdomains_to_check)} subdomains for {domain}")
        
        async def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{domain}"
            
            try:
                # DNS lookup
                answers = dns.resolver.resolve(full_domain, 'A')
                ip_addresses = [str(answer) for answer in answers]
                
                result = {
                    'subdomain': subdomain,
                    'domain': full_domain,
                    'ip_addresses': ip_addresses,
                    'status': 'found',
                    'timestamp': time.time()
                }
                
                self.discovered_subdomains.append(full_domain)
                print(f"  ✅ {full_domain} -> {', '.join(ip_addresses)}")
                
                return result
                
            except dns.resolver.NXDOMAIN:
                return {
                    'subdomain': subdomain,
                    'domain': full_domain,
                    'status': 'not_found',
                    'timestamp': time.time()
                }
            except Exception as e:
                return {
                    'subdomain': subdomain,
                    'domain': full_domain,
                    'status': 'error',
                    'error': str(e),
                    'timestamp': time.time()
                }
        
        # Check subdomains with rate limiting
        subdomain_results = []
        for subdomain in subdomains_to_check:
            result = await check_subdomain(subdomain)
            if result['status'] == 'found':
                subdomain_results.append(result)
            
            # Rate limiting for DNS queries
            await asyncio.sleep(0.5)  # 2 requests per second
        
        return subdomain_results
    
    def check_robots_txt(self, base_url):
        """Check robots.txt for additional paths"""
        robots_url = urljoin(base_url, '/robots.txt')
        additional_paths = []
        
        try:
            import requests
            response = requests.get(robots_url, timeout=self.timeout)
            
            if response.status_code == 200:
                print(f"📄 Found robots.txt")
                
                # Parse robots.txt for Disallow entries
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path not in self.common_paths:
                            additional_paths.append(path)
                    elif line.startswith('Sitemap:'):
                        sitemap_url = line.split(':', 1)[1].strip()
                        print(f"📍 Sitemap found: {sitemap_url}")
                
                if additional_paths:
                    print(f"📋 Found {len(additional_paths)} additional paths in robots.txt")
                
        except Exception as e:
            pass
        
        return additional_paths
    
    def analyze_findings(self):
        """Analyze discovered paths and subdomains"""
        analysis = {
            'summary': {
                'total_paths_checked': len(self.common_paths),
                'interesting_paths_found': len(self.discovered_paths),
                'subdomains_found': len(self.discovered_subdomains),
                'total_requests': len(self.results)
            },
            'findings': {
                'paths': self.discovered_paths,
                'subdomains': self.discovered_subdomains
            },
            'security_notes': []
        }
        
        # Security analysis
        risky_paths = [p for p in self.discovered_paths if any(risk in p.lower() for risk in 
                      ['admin', 'config', 'backup', 'debug', 'test', 'phpinfo', '.env'])]
        
        if risky_paths:
            analysis['security_notes'].append(f"Found {len(risky_paths)} potentially sensitive paths")
        
        sensitive_files = [p for p in self.discovered_paths if any(ext in p for ext in 
                          ['.env', '.config', '.bak', '.sql', '.log'])]
        
        if sensitive_files:
            analysis['security_notes'].append(f"Found {len(sensitive_files)} sensitive file types")
        
        return analysis

async def main():
    parser = argparse.ArgumentParser(description='PayBuddy Web Discovery Tool')
    parser.add_argument('target', help='Target domain or URL to scan')
    parser.add_argument('-d', '--directories', action='store_true', 
                       help='Perform directory/file discovery')
    parser.add_argument('-s', '--subdomains', action='store_true',
                       help='Perform subdomain discovery')
    parser.add_argument('--custom-paths', help='File containing custom paths to check')
    parser.add_argument('--custom-subdomains', help='File containing custom subdomains to check')
    parser.add_argument('-r', '--rate-limit', type=float, default=2.0,
                       help='Requests per second (default: 2)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds')
    parser.add_argument('--dry-run', action='store_true',
                       help='Verify identity without performing scan')
    parser.add_argument('-o', '--output', help='Output file for results (JSON format)')
    
    args = parser.parse_args()
    
    # Verify identity first
    verifier = IdentityVerifier()
    if not verifier.verify_identity(dry_run=args.dry_run):
        return 1
    
    if args.dry_run:
        print("✅ Dry run completed - no actual discovery performed")
        return 0
    
    # Parse target
    if not args.target.startswith(('http://', 'https://')):
        base_url = f"http://{args.target}"
        domain = args.target
    else:
        base_url = args.target
        domain = urlparse(args.target).netloc
    
    # Safety check for external targets
    try:
        ip = socket.gethostbyname(domain)
        if not ip.startswith(('127.', '10.', '192.168.')):
            if 'localhost' not in domain and 'local' not in domain:
                print("⚠️  Warning: External target detected")
                confirm = input("Are you authorized to scan this external target? (yes/no): ").lower().strip()
                if confirm not in ['yes', 'y']:
                    print("❌ Scan cancelled for safety")
                    return 1
    except:
        pass
    
    # Load custom paths/subdomains if provided
    custom_paths = None
    custom_subdomains = None
    
    if args.custom_paths:
        try:
            with open(args.custom_paths, 'r') as f:
                custom_paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Custom paths file not found: {args.custom_paths}")
            return 1
    
    if args.custom_subdomains:
        try:
            with open(args.custom_subdomains, 'r') as f:
                custom_subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"❌ Custom subdomains file not found: {args.custom_subdomains}")
            return 1
    
    # Initialize scanner
    scanner = WebDiscovery(rate_limit=args.rate_limit, timeout=args.timeout)
    
    print("🕸️ PayBuddy Web Discovery Tool")
    print("=" * 50)
    print(f"🎯 Target: {domain}")
    
    try:
        # Directory/file discovery
        if args.directories or (not args.directories and not args.subdomains):
            print(f"\n📁 Starting directory discovery...")
            
            # Check robots.txt first
            additional_paths = scanner.check_robots_txt(base_url)
            if additional_paths and custom_paths:
                custom_paths.extend(additional_paths)
            elif additional_paths:
                custom_paths = scanner.common_paths + additional_paths
            
            directory_results = await scanner.directory_scan(base_url, custom_paths)
            
            print(f"\n✅ Directory scan completed")
            print(f"📊 Found {len(directory_results)} interesting paths")
        
        # Subdomain discovery
        if args.subdomains:
            print(f"\n🌐 Starting subdomain discovery...")
            subdomain_results = await scanner.subdomain_scan(domain, custom_subdomains)
            
            print(f"\n✅ Subdomain scan completed")
            print(f"📊 Found {len(subdomain_results)} subdomains")
        
        # Analyze findings
        analysis = scanner.analyze_findings()
        
        print(f"\n📋 Discovery Summary:")
        print(f"  Paths found: {analysis['summary']['interesting_paths_found']}")
        print(f"  Subdomains found: {analysis['summary']['subdomains_found']}")
        
        if analysis['security_notes']:
            print(f"\n⚠️  Security Notes:")
            for note in analysis['security_notes']:
                print(f"  - {note}")
        
        # Export results if requested
        if args.output:
            team_info = verifier.get_team_info()
            
            # Include registration number in filename
            if team_info['members']:
                reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                name = team_info['members'][0]['name'].replace(' ', '')
                output_path = Path(args.output).parent / f"footprint_{reg_num}_{name}.json"
            else:
                output_path = Path(args.output)
            
            export_data = {
                'discovery_info': {
                    'timestamp': datetime.now().isoformat(),
                    'tool_version': 'PayBuddy WebDiscovery v1.0',
                    'target': domain,
                    'base_url': base_url,
                    'scan_config': {
                        'directories': args.directories,
                        'subdomains': args.subdomains,
                        'rate_limit': args.rate_limit,
                        'timeout': args.timeout
                    },
                    'team_info': team_info
                },
                'results': {
                    'analysis': analysis,
                    'detailed_results': scanner.results
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"📄 Results saved to: {output_path}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"❌ Discovery failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))