# Linux Hardening Audit Tool (LHAT)

![Security](https://img.shields.io/badge/Security-Audit-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)

A comprehensive security auditing tool for Linux systems that checks compliance with CIS, STIG, and custom benchmarks.

## Features

- ✅ CIS Benchmark compliance checking (Level 1 & 2)
- 🔍 STIG configuration auditing
- 🛡️ Vulnerability detection
- 📊 Multiple report formats (JSON, HTML, Terminal)
- 🚀 Quick scan mode for critical vulnerabilities
- 📦 Modular architecture for easy expansion

## Installation

### Prerequisites
- Python 3.8+
- pip
- git

### Quick Start
```bash
git clone https://github.com/Thilak098/linux-hardening-audit-tool.git
cd linux-hardening-audit-tool

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -e .

Usage
Basic Commands

# Run full audit (terminal output)
lh-audit

# Check CIS Level 1 compliance
lh-audit --benchmark cis_level1 --format html --output cis_report.html

# Quick scan (critical checks only)
lh-audit --quick --format json

Sample Reports
Terminal Output:

[CRITICAL] password_max_days: FAIL (Value: 120)
[HIGH] ssh_root_login: PASS
[MEDIUM] ufw_status: FAIL

JSON Report:

{
  "timestamp": "2023-11-21T10:00:00Z",
  "findings": [
    {
      "id": "password_max_days",
      "status": "FAIL",
      "severity": "CRITICAL"
    }
  ]
}

License
MIT License - See LICENSE for details
