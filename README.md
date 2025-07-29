# IRIS - Incident Response Integration Suite

**Cross-Platform Incident Response Toolkit**

IRIS is a defensive security tool designed for rapid incident response. It provides essential capabilities for evidence collection, network isolation, forensic analysis, and reporting through a clean GUI interface.

## Quick Start

Run this single command to auto-setup and launch IRIS:

```bash
python main.py
```

This automatically creates a virtual environment, installs dependencies, and launches the application.

## Core Features

**System Evidence Collector**
- Process enumeration with detailed information
- Network connections and active ports
- System information (OS, IP addresses, uptime)
- User accounts and login history
- File hashing (MD5/SHA256) for suspicious files

**Network Isolation**
- Emergency isolation blocking all outbound connections
- IP whitelist management for investigation
- Connection termination for suspicious processes
- DNS blocking to prevent data exfiltration

**Forensic Collection**
- Memory snapshot capture
- System, security, and application log collection
- Browser artifacts and cached files
- Recent file modifications
- Desktop screenshots for documentation

**Report Generation**
- Complete evidence inventory
- Chronological incident timeline
- System summary reports
- Multiple export formats (text/HTML)
- Hash verification for evidence integrity

## Supported Platforms

- Kali Linux (full functionality)
- Ubuntu/Debian (full functionality)
- Windows 10/11 (full functionality)
- Other Linux distributions (most features)

## System Requirements

- Python 3.7+ (Python 3.13+ recommended)
- Administrator/root privileges for full functionality
- GUI support (tkinter - usually built-in)
- Network tools (netstat, iptables/firewall)

## Interface Design

IRIS uses a brutalist design philosophy with white backgrounds, thick black borders, monospace fonts, terminal-style output, and large functional buttons with real-time status updates.

## Security Features

- Cryptographic hash verification for evidence integrity
- Network isolation capabilities
- Complete operation audit trail
- Minimal external dependencies
- Consistent cross-platform behavior

## Important Notes

**Administrator/Root Privileges Required For:**
- Network isolation (iptables/firewall rules)
- Process termination
- System file access
- Memory analysis

**Defensive Security Use Only**
IRIS is designed exclusively for incident response, digital forensics, security analysis, and threat hunting by authorized personnel.

## License

This is a defensive security tool for incident response teams, SOCs, and digital forensics investigators.