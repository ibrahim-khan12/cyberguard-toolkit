#!/usr/bin/env python3
"""
Load/Stress Testing Module for PayBuddy Cybersecurity Testing Toolkit
Safe, limited client load testing with auto-throttling and latency recording
"""

import asyncio
import aiohttp
import time
import json
import argparse
import sys
import os
from datetime import datetime
from pathlib import Path
import statistics
import matplotlib.pyplot as plt
from urllib.parse import urlparse
import threading
import signal

# Add src directory to path for imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from identity_verifier import IdentityVerifier

class LoadTester:
    def __init__(self, max_clients=200, duration=30):
        self.max_clients = max_clients
        self.duration = duration
        self.results = []
        self.start_time = None
        self.stop_testing = False
        self.active_sessions = 0
        self.total_requests = 0
        self.total_errors = 0
        
        # Safety limits
        self.MIN_DELAY = 0.1  # Minimum delay between requests (100ms)
        self.MAX_RPS = 10     # Maximum requests per second per client
        self.AUTO_THROTTLE_THRESHOLD = 0.5  # Error rate threshold for auto-throttling
        
        # Results tracking
        self.response_times = []
        self.status_codes = []
        self.error_details = []
        self.throughput_data = []
        
    async def make_request(self, session, url, method='GET', headers=None, data=None):
        """Make a single HTTP request"""
        start_time = time.time()
        
        try:
            async with session.request(method, url, headers=headers, data=data) as response:
                end_time = time.time()
                response_time = (end_time - start_time) * 1000  # Convert to milliseconds
                
                # Read response content (limited to prevent memory issues)
                content_length = response.headers.get('content-length', 0)
                try:
                    content_length = int(content_length)
                except:
                    content_length = 0
                
                # Only read small responses to avoid memory issues
                if content_length < 10000:  # 10KB limit
                    try:
                        await response.read()
                    except:
                        pass
                
                result = {
                    'timestamp': start_time,
                    'response_time': response_time,
                    'status_code': response.status,
                    'content_length': content_length,
                    'error': None
                }
                
                self.response_times.append(response_time)
                self.status_codes.append(response.status)
                
                return result
                
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            
            error_result = {
                'timestamp': start_time,
                'response_time': response_time,
                'status_code': 0,
                'content_length': 0,
                'error': str(e)
            }
            
            self.error_details.append(str(e))
            self.total_errors += 1
            
            return error_result
    
    async def client_worker(self, client_id, url, requests_per_client, method='GET', headers=None, data=None):
        """Worker function for each client"""
        timeout = aiohttp.ClientTimeout(total=30)  # 30 second timeout
        connector = aiohttp.TCPConnector(limit=10)  # Limit connections per client
        
        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            self.active_sessions += 1
            
            for request_num in range(requests_per_client):
                if self.stop_testing:
                    break
                
                # Auto-throttling based on error rate
                if self.total_requests > 0:
                    error_rate = self.total_errors / self.total_requests
                    if error_rate > self.AUTO_THROTTLE_THRESHOLD:
                        await asyncio.sleep(self.MIN_DELAY * 2)  # Double the delay
                
                # Rate limiting
                await asyncio.sleep(self.MIN_DELAY)
                
                # Make request
                result = await self.make_request(session, url, method, headers, data)
                self.results.append(result)
                self.total_requests += 1
                
                # Periodic throughput tracking
                if self.total_requests % 50 == 0:
                    current_time = time.time()
                    elapsed = current_time - self.start_time
                    rps = self.total_requests / elapsed if elapsed > 0 else 0
                    self.throughput_data.append({
                        'timestamp': current_time,
                        'requests': self.total_requests,
                        'rps': rps,
                        'errors': self.total_errors,
                        'active_clients': self.active_sessions
                    })
            
            self.active_sessions -= 1
    
    async def run_load_test(self, url, num_clients=None, method='GET', headers=None, data=None):
        """Run the load test"""
        if num_clients is None:
            num_clients = min(self.max_clients, 50)  # Default to 50 clients
        
        # Safety check - enforce maximum clients
        if num_clients > self.max_clients:
            print(f"⚠️  Client count limited to {self.max_clients} for safety")
            num_clients = self.max_clients
        
        print(f"🚀 Starting load test against {url}")
        print(f"📊 Configuration:")
        print(f"   Clients: {num_clients}")
        print(f"   Duration: {self.duration} seconds")
        print(f"   Method: {method}")
        print(f"   Auto-throttling: Enabled")
        print(f"   Safety limits: Max {self.max_clients} clients, Min {self.MIN_DELAY}s delay")
        
        # Calculate requests per client
        total_requests = num_clients * (self.duration // 2)  # Conservative estimate
        requests_per_client = max(1, total_requests // num_clients)
        
        self.start_time = time.time()
        
        # Create client tasks
        tasks = []
        for client_id in range(num_clients):
            task = asyncio.create_task(
                self.client_worker(client_id, url, requests_per_client, method, headers, data)
            )
            tasks.append(task)
        
        # Run test with timeout
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=self.duration + 10)
        except asyncio.TimeoutError:
            print("⏰ Test duration reached, stopping...")
            self.stop_testing = True
            
            # Wait a bit for graceful shutdown
            await asyncio.sleep(2)
        
        end_time = time.time()
        total_duration = end_time - self.start_time
        
        print(f"✅ Load test completed in {total_duration:.2f} seconds")
        
        return self.analyze_results(total_duration)
    
    def analyze_results(self, duration):
        """Analyze test results and generate statistics"""
        if not self.results:
            return {'error': 'No results to analyze'}
        
        # Basic statistics
        successful_requests = [r for r in self.results if r['error'] is None and r['status_code'] < 400]
        error_requests = [r for r in self.results if r['error'] is not None or r['status_code'] >= 400]
        
        analysis = {
            'test_summary': {
                'total_requests': len(self.results),
                'successful_requests': len(successful_requests),
                'failed_requests': len(error_requests),
                'success_rate': (len(successful_requests) / len(self.results)) * 100 if self.results else 0,
                'duration': duration,
                'requests_per_second': len(self.results) / duration if duration > 0 else 0
            },
            'response_times': {},
            'status_codes': {},
            'errors': self.error_details[:10],  # Limit error details
            'throughput': self.throughput_data[-10:]  # Last 10 throughput measurements
        }
        
        # Response time statistics
        if self.response_times:
            analysis['response_times'] = {
                'min': min(self.response_times),
                'max': max(self.response_times),
                'mean': statistics.mean(self.response_times),
                'median': statistics.median(self.response_times),
                'p90': self.percentile(self.response_times, 0.90),
                'p95': self.percentile(self.response_times, 0.95),
                'p99': self.percentile(self.response_times, 0.99)
            }
        
        # Status code distribution
        status_count = {}
        for code in self.status_codes:
            status_count[code] = status_count.get(code, 0) + 1
        analysis['status_codes'] = status_count
        
        return analysis
    
    def percentile(self, data, p):
        """Calculate percentile of a dataset"""
        if not data:
            return 0
        sorted_data = sorted(data)
        index = int(len(sorted_data) * p)
        if index >= len(sorted_data):
            index = len(sorted_data) - 1
        return sorted_data[index]
    
    def generate_plots(self, analysis, output_dir):
        """Generate performance plots"""
        try:
            import matplotlib
            matplotlib.use('Agg')  # Use non-interactive backend
            
            # Response time distribution
            if self.response_times:
                plt.figure(figsize=(12, 8))
                
                # Subplot 1: Response time histogram
                plt.subplot(2, 2, 1)
                plt.hist(self.response_times, bins=30, alpha=0.7, color='blue')
                plt.title('Response Time Distribution')
                plt.xlabel('Response Time (ms)')
                plt.ylabel('Frequency')
                
                # Subplot 2: Response time over time
                plt.subplot(2, 2, 2)
                timestamps = [r['timestamp'] - self.start_time for r in self.results if r['error'] is None]
                response_times = [r['response_time'] for r in self.results if r['error'] is None]
                plt.scatter(timestamps, response_times, alpha=0.6, s=1)
                plt.title('Response Time Over Time')
                plt.xlabel('Time (seconds)')
                plt.ylabel('Response Time (ms)')
                
                # Subplot 3: Throughput over time
                if self.throughput_data:
                    plt.subplot(2, 2, 3)
                    timestamps = [t['timestamp'] - self.start_time for t in self.throughput_data]
                    rps_values = [t['rps'] for t in self.throughput_data]
                    plt.plot(timestamps, rps_values, 'g-', linewidth=2)
                    plt.title('Throughput Over Time')
                    plt.xlabel('Time (seconds)')
                    plt.ylabel('Requests per Second')
                
                # Subplot 4: Status code distribution
                plt.subplot(2, 2, 4)
                status_codes = list(analysis['status_codes'].keys())
                counts = list(analysis['status_codes'].values())
                colors = ['green' if code < 400 else 'red' for code in status_codes]
                plt.bar(status_codes, counts, color=colors, alpha=0.7)
                plt.title('Status Code Distribution')
                plt.xlabel('HTTP Status Code')
                plt.ylabel('Count')
                
                plt.tight_layout()
                plot_file = output_dir / 'load_test_results.png'
                plt.savefig(plot_file, dpi=300, bbox_inches='tight')
                plt.close()
                
                print(f"📊 Performance plots saved to: {plot_file}")
                
        except ImportError:
            print("⚠️  matplotlib not available, skipping plot generation")
        except Exception as e:
            print(f"❌ Error generating plots: {e}")

async def main():
    parser = argparse.ArgumentParser(description='PayBuddy Load/Stress Testing Tool')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-c', '--clients', type=int, default=50,
                       help='Number of concurrent clients (max 200)')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Test duration in seconds')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST', 'PUT', 'HEAD'],
                       help='HTTP method to use')
    parser.add_argument('--headers', help='Custom headers (JSON format)')
    parser.add_argument('--data', help='Request data for POST/PUT requests')
    parser.add_argument('--dry-run', action='store_true',
                       help='Verify identity without performing test')
    parser.add_argument('-o', '--output', help='Output directory for results')
    
    args = parser.parse_args()
    
    # Verify identity first
    verifier = IdentityVerifier()
    if not verifier.verify_identity(dry_run=args.dry_run):
        return 1
    
    if args.dry_run:
        print("✅ Dry run completed - no actual load testing performed")
        return 0
    
    # Validate URL
    parsed_url = urlparse(args.url)
    if not parsed_url.scheme or not parsed_url.netloc:
        print(f"❌ Invalid URL: {args.url}")
        return 1
    
    # Safety checks
    if parsed_url.hostname and not parsed_url.hostname.startswith(('127.', '10.', '192.168.')):
        if 'localhost' not in parsed_url.hostname and 'local' not in parsed_url.hostname:
            print("⚠️  Warning: Testing external host detected")
            confirm = input("Are you authorized to test this external host? (yes/no): ").lower().strip()
            if confirm not in ['yes', 'y']:
                print("❌ Testing cancelled for safety")
                return 1
    
    # Parse custom headers
    headers = None
    if args.headers:
        try:
            headers = json.loads(args.headers)
        except json.JSONDecodeError:
            print("❌ Invalid JSON format for headers")
            return 1
    
    # Initialize load tester
    tester = LoadTester(max_clients=200, duration=args.duration)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print("\n⚠️  Stopping test...")
        tester.stop_testing = True
    
    signal.signal(signal.SIGINT, signal_handler)
    
    print("🔥 PayBuddy Load Testing Tool")
    print("=" * 50)
    print(f"🎯 Target: {args.url}")
    print(f"⚡ Safety Mode: Enabled (Max 200 clients, auto-throttling)")
    
    try:
        # Run the load test
        analysis = await tester.run_load_test(
            args.url,
            num_clients=args.clients,
            method=args.method,
            headers=headers,
            data=args.data
        )
        
        # Display results
        print("\n📊 Test Results:")
        print("=" * 30)
        summary = analysis['test_summary']
        print(f"Total Requests: {summary['total_requests']}")
        print(f"Successful: {summary['successful_requests']} ({summary['success_rate']:.1f}%)")
        print(f"Failed: {summary['failed_requests']}")
        print(f"Duration: {summary['duration']:.2f} seconds")
        print(f"Throughput: {summary['requests_per_second']:.2f} req/sec")
        
        if 'response_times' in analysis and analysis['response_times']:
            rt = analysis['response_times']
            print(f"\n⏱️  Response Times (ms):")
            print(f"  Min: {rt['min']:.2f}")
            print(f"  Max: {rt['max']:.2f}")
            print(f"  Mean: {rt['mean']:.2f}")
            print(f"  Median: {rt['median']:.2f}")
            print(f"  90th percentile: {rt['p90']:.2f}")
            print(f"  95th percentile: {rt['p95']:.2f}")
        
        # Export results if requested
        if args.output:
            team_info = verifier.get_team_info()
            
            # Handle both file paths and directory paths
            output_path = Path(args.output)
            if output_path.suffix == '.json':
                # It's a full file path
                results_file = output_path
                results_file.parent.mkdir(parents=True, exist_ok=True)
            else:
                # It's a directory path
                output_dir = output_path
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Include registration number in filename
                if team_info['members']:
                    reg_num = team_info['members'][0]['reg'].split('-')[1] if '-' in team_info['members'][0]['reg'] else '000'
                    name = team_info['members'][0]['name'].replace(' ', '')
                    results_file = output_dir / f"stress_{reg_num}_{name}.json"
                else:
                    results_file = output_dir / "stress_000_Unknown.json"
            
            # Prepare export data
            export_data = {
                'test_info': {
                    'timestamp': datetime.now().isoformat(),
                    'tool_version': 'PayBuddy LoadTester v1.0',
                    'target_url': args.url,
                    'test_config': {
                        'clients': args.clients,
                        'duration': args.duration,
                        'method': args.method
                    },
                    'team_info': team_info
                },
                'results': analysis
            }
            
            # Save JSON results
            with open(results_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            print(f"📄 Results saved to: {results_file}")
            
            # Generate plots - use the results_file directory
            plot_dir = results_file.parent if hasattr(results_file, 'parent') else Path(results_file).parent
            tester.generate_plots(analysis, plot_dir)
        
        return 0
        
    except Exception as e:
        print(f"❌ Load test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))