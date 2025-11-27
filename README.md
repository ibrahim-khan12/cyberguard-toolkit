# PayBuddy Cybersecurity Testing Toolkit

**Educational Cybersecurity Assessment Suite for CY4053 Final Project**

A modular, all-in-one Python-based security testing toolkit designed for PayBuddy FinTech startup to test APIs and wallet services safely in authorized lab environments.

## 🛡️ Project Overview

This toolkit provides comprehensive security testing capabilities including:
- **Port & Service Scanning** with banner grabbing
- **Password Policy & Strength Testing** with hash simulation
- **Load/DOS Testing** with auto-throttling and safety limits
- **Web Discovery & Footprinting** for directory and subdomain enumeration
- **Packet Capture & Analysis** using Scapy
- **Centralized Logging & Reporting** with integrity checks

## 🔒 Safety Features

- **Identity Verification**: Mandatory identity.txt and consent.txt verification
- **Consent Checks**: Approved target validation before testing
- **Rate Limiting**: Built-in delays and throttling to prevent damage
- **Auto-Throttling**: Automatic slowdown on high error rates
- **Logging Integrity**: SHA-256 hash verification for tamper detection
- **Safety Limits**: Maximum client limits and timeout protections

## 📁 Project Structure

```
CY4053_FinalProject_CyberGuard/
├── identity.txt                    # Team identity information
├── consent.txt                     # Authorized target list
├── paybuddy.py                     # Main CLI interface
├── src/                           # Source code modules
│   ├── identity_verifier.py       # Identity & consent verification
│   ├── port_scanner.py            # TCP port scanning module
│   ├── auth_test.py               # Password assessment module
│   ├── stress_test.py             # Load/DOS testing module
│   ├── web_discovery.py           # Web footprinting module
│   ├── packet_capture.py          # Packet capture & analysis
│   └── logger.py                  # Logging & reporting system
├── evidence/                      # Test outputs and evidence
│   ├── security_audit.log         # Main log file
│   ├── integrity.sha256           # Log integrity hash
│   └── [test_results...]          # Scan results and reports
├── README.md                      # This documentation
└── requirements.txt               # Python dependencies
```

## 🚀 Quick Start

### Prerequisites

```bash
# Install Python 3.8+
python --version

# Install required packages
pip install -r requirements.txt
```

### Basic Usage

```bash
# Check toolkit status
python paybuddy.py --status

# List available modules
python paybuddy.py --list

# Run comprehensive scan (all modules)
python paybuddy.py --comprehensive 127.0.0.1

# Run specific modules
python paybuddy.py scan 127.0.0.1 -p common
python paybuddy.py auth-test --check "password123"
python paybuddy.py stress http://127.0.0.1 -c 50
```

## 📦 Module Documentation

### 1. Identity Verification (`identity_verifier.py`)

**Purpose**: Verify team identity and consent before any testing

**Features**:
- Reads identity.txt and consent.txt files
- Validates team information
- Supports dry-run mode
- Generates identity hash for logging

**Usage**:
```bash
python paybuddy.py --identity
python paybuddy.py --identity --dry-run
```

### 2. Port Scanner (`port_scanner.py`)

**Purpose**: TCP port scanning with banner grabbing

**Features**:
- Threaded scanning (max 50 threads)
- Banner grabbing for open services
- Common port presets
- JSON and HTML output formats
- Response time measurement

**Usage**:
```bash
# Scan common ports
python paybuddy.py scan 127.0.0.1 -p common

# Scan specific ports
python paybuddy.py scan 127.0.0.1 -p "80,443,8080"

# Scan port range with custom threads
python paybuddy.py scan 127.0.0.1 -p "1-1000" -t 25

# Export results
python paybuddy.py scan 127.0.0.1 -o results.json --format json
```

### 3. Password Assessment (`auth_test.py`)

**Purpose**: Password policy checking and offline hash testing

**Features**:
- Policy compliance checking
- Entropy calculation
- Hash cracking simulation (educational)
- Secure password generation
- No online brute-force attacks

**Usage**:
```bash
# Check password strength
python paybuddy.py auth-test --check "MyPassword123!"

# Generate secure password
python paybuddy.py auth-test --generate --length 16

# Simulate hash cracking (educational)
python paybuddy.py auth-test --crack "e10adc3949ba59abbe56e057f20f883e" --hash-type MD5

# Export assessment results
python paybuddy.py auth-test --check "password" -o assessment.json
```

### 4. Stress Testing (`stress_test.py`)

**Purpose**: Safe load testing with auto-throttling

**Features**:
- Maximum 200 concurrent clients (safety limit)
- Auto-throttling on high error rates
- Latency recording and statistics
- Performance graph generation
- External host warnings

**Usage**:
```bash
# Basic load test
python paybuddy.py stress http://127.0.0.1 -c 50 -d 30

# Light test with custom settings
python paybuddy.py stress http://localhost:8080 -c 10 -d 15

# Export results with graphs
python paybuddy.py stress http://127.0.0.1 -o ./evidence/
```

### 5. Web Discovery (`web_discovery.py`)

**Purpose**: Directory and subdomain discovery

**Features**:
- Common directory scanning
- Subdomain enumeration
- robots.txt parsing
- Rate limiting (2 req/sec default)
- External target warnings

**Usage**:
```bash
# Directory discovery
python paybuddy.py footprint 127.0.0.1 --directories

# Subdomain discovery
python paybuddy.py footprint example.local --subdomains

# Combined discovery
python paybuddy.py footprint 127.0.0.1 --directories --subdomains

# Custom wordlists
python paybuddy.py footprint 127.0.0.1 --custom-paths wordlist.txt
```

### 6. Packet Capture (`packet_capture.py`)

**Purpose**: Network packet capture and analysis

**Features**:
- Live packet capture with Scapy
- PCAP file analysis
- Protocol statistics
- Suspicious activity detection
- DNS query analysis

**Usage**:
```bash
# List network interfaces
python paybuddy.py pcap --list-interfaces

# Live capture (requires admin privileges)
python paybuddy.py pcap -c 100 -o capture.pcap

# Analyze existing PCAP
python paybuddy.py pcap --analyze capture.pcap -o analysis.json

# Filtered capture
python paybuddy.py pcap -f "tcp port 80" -c 50
```

### 7. Logging & Reporting (`logger.py`)

**Purpose**: Centralized logging with integrity and report generation

**Features**:
- Append-only logging
- SHA-256 integrity verification
- Word/PDF report generation
- JSON export
- Event filtering

**Usage**:
```bash
# View recent logs
python paybuddy.py report --view-logs

# Generate Word report
python paybuddy.py report --generate-report docx -o security_report.docx

# Generate PDF report
python paybuddy.py report --generate-report pdf -o report.pdf

# Check log integrity
python paybuddy.py report --check-integrity
```

## 🎯 Usage Examples

### Example 1: Quick Security Assessment

```bash
# Step 1: Verify identity
python paybuddy.py --identity

# Step 2: Port scan
python paybuddy.py scan 127.0.0.1 -p common -o ./evidence/

# Step 3: Generate report
python paybuddy.py report --generate-report docx
```

### Example 2: Web Application Testing

```bash
# Directory discovery
python paybuddy.py footprint webapp.local --directories -o ./evidence/

# Light load testing
python paybuddy.py stress http://webapp.local -c 10 -d 15

# Password policy testing
python paybuddy.py auth-test --check "webapp123" -o ./evidence/
```

### Example 3: Comprehensive Assessment

```bash
# Run all tests automatically
python paybuddy.py --comprehensive 127.0.0.1 --output-dir ./evidence/comprehensive_scan/
```

## 🔧 Configuration

### Identity Configuration (`identity.txt`)

```
Team: CyberGuard
Members: 
- Ali Raza | BSFT07-020
- Fatima Noor | BSFT07-040 
- Ahmed Khan | BSFT07-008
```

### Consent Configuration (`consent.txt`)

```
Approved Targets:
- 127.0.0.1 (localhost testing)
- 10.0.2.* (VirtualBox NAT network)
- 192.168.1.* (Local lab network)
- mock-api.paybuddy.local (Test environment)
- TryHackMe Search Skills room

Approved By: Dr. Cybersecurity Instructor
Date: November 21, 2025
Purpose: Educational penetration testing for CY4053 Final Project
```

## 📊 Output Formats

### File Naming Convention
All output files include registration numbers: `{module}_{reg_num}_{name}.{ext}`

Examples:
- `scan_020_AliRaza.json`
- `auth_test_020_AliRaza.json`
- `stress_020_AliRaza.json`

### Report Formats

1. **JSON**: Machine-readable detailed results
2. **HTML**: Human-readable web reports (port scanner)
3. **Word**: Professional assessment reports
4. **PDF**: Portable document reports
5. **PCAP**: Network capture files

## ⚡ Safety Guidelines

### Authorized Targets Only
- ✅ localhost (127.0.0.1)
- ✅ Local lab networks (10.x.x.x, 192.168.x.x)
- ✅ VirtualBox/VMware test environments
- ✅ Personal test servers
- ❌ Production systems
- ❌ External websites without permission

### Best Practices
1. Always verify identity before testing
2. Use dry-run mode for verification
3. Start with minimal settings
4. Monitor system resources
5. Review logs for anomalies
6. Keep evidence organized

## 🐛 Troubleshooting

### Common Issues

**Identity Verification Fails**
```bash
# Check files exist
ls identity.txt consent.txt

# Verify content format
cat identity.txt
```

**Permission Denied (Packet Capture)**
```bash
# Windows: Run as Administrator
# Linux: Use sudo or add user to pcap group
sudo usermod -a -G pcap $USER
```

**Module Not Found**
```bash
# Ensure you're in the project directory
cd CY4053_FinalProject_CyberGuard/
python paybuddy.py --status
```

**Dependencies Missing**
```bash
# Install requirements
pip install -r requirements.txt

# Manual installation
pip install scapy aiohttp python-docx reportlab matplotlib dnspython bcrypt
```

### Getting Help

```bash
# General help
python paybuddy.py --help

# Module-specific help
python paybuddy.py scan --help
python paybuddy.py auth-test --help
python paybuddy.py stress --help
```

## 📝 Dependencies

```txt
# Core dependencies
aiohttp>=3.8.0          # Async HTTP client
scapy>=2.4.5           # Packet manipulation
dnspython>=2.2.0       # DNS operations
bcrypt>=4.0.0          # Password hashing

# Reporting dependencies
python-docx>=0.8.11    # Word document generation
reportlab>=3.6.0       # PDF generation
matplotlib>=3.6.0      # Graph generation

# Optional dependencies
requests>=2.28.0       # HTTP requests (fallback)
```

## 🎓 Educational Use Only

This toolkit is designed for **educational purposes** and **authorized security testing** only. Users are responsible for:

- Obtaining proper authorization before testing any systems
- Following responsible disclosure practices
- Complying with applicable laws and regulations
- Using the toolkit only in controlled lab environments

## 📞 Support

For questions about this toolkit:

1. Review this README.md
2. Check the module help: `python paybuddy.py <module> --help`
3. Examine log files: `python paybuddy.py report --view-logs`
4. Verify toolkit status: `python paybuddy.py --status`

## 🏆 Project Team

**Team**: CyberGuard  
**Members**: 
- ibrahim khan 

**Course**: CY4053 - Advanced Cybersecurity  


---

**⚠️ IMPORTANT**: This toolkit is for educational and authorized testing purposes only. Always ensure you have explicit permission before testing any system.
