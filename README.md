# 🔍 NULL200OK - Advanced Subdomain Scanner
Professional subdomain discovery tool with passive/active reconnaissance.
=========================================================================
## Features
- Passive enumeration (SSL certificates, DNS records)
- Active scanning with smart permutations
- DNS brute-forcing
- Multi-threaded scanning
- Results export to TXT
========================================================================
## Installation
```bash
git clone https://github.com/IBO-ATTACKS/NULL200OK.git
cd NULL200OK
pip install -r requirements.txt
=========================================================================
## Usage
# Basic scan
python NULL200OK.py -d example.com

# Full scan with custom output
python NULL200OK.py -d company.com -o results.txt -t 20

# Scan with custom wordlist
python NULL200OK.py -d org.net -w subdomains.txt
