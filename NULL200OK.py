import re
import requests
import tldextract
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import argparse
import dns.resolver
import socket
import os
from urllib.parse import urlparse  # Added missing import

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
REQUEST_TIMEOUT = 15
MAX_WORKERS = 12
THROTTLE_DELAY = 0.3

# Enhanced wordlist for DNS brute forcing
COMMON_SUBS = [
    'www', 'api', 'blog', 'dev', 'test', 'staging', 'mail', 'web', 'app', 
    'admin', 'secure', 'vpn', 'docs', 'news', 'forum', 'support', 'shop',
    'cdn', 'static', 'assets', 'media', 'm', 'mobile', 'backup', 'old',
    'beta', 'alpha', 'prod', 'production', 'demo', 'stage', 'portal',
    'internal', 'external', 'git', 'svn', 'jenkins', 'ns1', 'ns2', 'dns',
    'ftp', 'smtp', 'mx', 'owa', 'vpn', 'crm', 'erp', 'db', 'sql', 'nosql',
    'redis', 'elastic', 'kibana', 'grafana', 'prometheus', 'jenkins', 'gitlab',
    'confluence', 'jira', 'atlassian', 'wiki', 'status', 'monitor', 'logging',
    'auth', 'sso', 'login', 'signin', 'register', 'account', 'billing', 'payment',
    'store', 'shop', 'cart', 'checkout', 'search', 'query', 'engine', 'cdn', 'cloudfront',
    'aws', 'gcp', 'azure', 'cloud', 'storage', 'bucket', 's3', 'blob', 'file', 'content'
]

def generate_sources(target_domain):
    """Generate enhanced scanning sources"""
    sources = []
    
    # Protocol variations
    protocols = ['http://', 'https://']
    
    # Base domain and common paths
    common_paths = ['', '/robots.txt', '/sitemap.xml', '/.well-known/security.txt']
    
    # Generate base sources
    for protocol in protocols:
        sources.append(f"{protocol}{target_domain}")
        for path in common_paths:
            sources.append(f"{protocol}{target_domain}{path}")
    
    # Third-party sources (free only)
    third_party = [
        f"https://crt.sh/?q=%.{target_domain}&output=json",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{target_domain}/passive_dns",
        f"https://web.archive.org/cdx/search/cdx?url=*.{target_domain}/*&output=json",
        f"https://urlscan.io/api/v1/search/?q=domain:{target_domain}",
        f"https://api.hackertarget.com/hostsearch/?q={target_domain}",
        f"https://dns.bufferover.run/dns?q=.{target_domain}",
        f"https://rapiddns.io/subdomain/{target_domain}",
        f"https://dnsrepo.noc.org/?domain={target_domain}"
    ]
    
    # Add brute-force permutations
    for sub in COMMON_SUBS:
        sources.append(f"https://{sub}.{target_domain}")
        sources.append(f"http://{sub}.{target_domain}")
    
    return sources + third_party

def passive_enumeration(domain):
    """Enhanced passive reconnaissance without API keys"""
    passive_subs = set()
    
    try:
        # 1. SSL Certificate Transparency (crt.sh)
        crt_url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(crt_url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            for cert in response.json():
                name_value = cert.get('name_value', '')
                if name_value and domain in name_value:
                    for name in name_value.split('\n'):
                        name = name.strip().lower()
                        if name.startswith('*.'):
                            passive_subs.add(name[2:])
                        else:
                            passive_subs.add(name)
    except Exception:
        pass
    
    try:
        # 2. AlienVault OTX
        otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        response = requests.get(otx_url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            for record in data.get('passive_dns', []):
                hostname = record.get('hostname', '')
                if hostname and hostname.endswith(domain):
                    passive_subs.add(hostname)
    except Exception:
        pass
    
    try:
        # 3. DNS Dumpster
        dd_url = "https://dnsdumpster.com/"
        session = requests.Session()
        response = session.get(dd_url, timeout=REQUEST_TIMEOUT)
        csrf_token = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", response.text).group(1)
        
        response = session.post(
            dd_url, 
            data={"csrfmiddlewaretoken": csrf_token, "targetip": domain},
            headers={"Referer": dd_url},
            timeout=REQUEST_TIMEOUT
        )
        
        if response.status_code == 200:
            pattern = rf"\b[a-z0-9-]+\.{re.escape(domain)}\b"
            matches = set(re.findall(pattern, response.text, re.IGNORECASE))
            passive_subs.update(matches)
    except Exception:
        pass
    
    try:
        # 4. URLScan.io
        us_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
        response = requests.get(us_url, timeout=REQUEST_TIMEOUT)
        if response.status_code == 200:
            data = response.json()
            for result in data.get('results', []):
                page_url = result.get('page', {}).get('url', '')
                if page_url and domain in page_url:
                    parsed = urlparse(page_url)
                    if parsed.hostname and parsed.hostname.endswith(domain):
                        passive_subs.add(parsed.hostname)
    except Exception:
        pass
    
    # 5. DNS Brute Forcing
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    
    for sub in COMMON_SUBS:
        try:
            target = f"{sub}.{domain}"
            answers = resolver.resolve(target, 'A')
            if answers:
                passive_subs.add(target)
        except:
            pass
    
    # 6. Zone Transfer Attempt
    try:
        ns_servers = resolver.resolve(domain, 'NS')
        for ns in ns_servers:
            try:
                axfr = dns.query.xfr(str(ns).rstrip('.'), domain, timeout=5)
                zone = []
                for m in axfr:
                    zone.extend(m.answer)
                for record in zone:
                    if record.rdtype == dns.rdatatype.A:
                        passive_subs.add(str(record.name).rstrip('.'))
            except:
                pass
    except:
        pass
    
    return passive_subs

def find_subdomains(domain, url):
    try:
        headers = {"User-Agent": USER_AGENT}
        
        # Handle API URLs differently
        if "api." in url or "crt.sh" in url or "otx.alienvault" in url:
            response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            if response.status_code != 200:
                return set()
                
            # Parse JSON responses
            if "application/json" in response.headers.get('Content-Type', ''):
                data = response.json()
                subs = set()
                
                # Parse different API formats
                if "crt.sh" in url:
                    for item in data:
                        name = item.get('name_value', '')
                        if name and domain in name:
                            subs.add(name)
                elif "alienvault" in url:
                    for item in data.get('passive_dns', []):
                        hostname = item.get('hostname', '')
                        if hostname and hostname.endswith(domain):
                            subs.add(hostname)
                return subs
                
        # Standard HTTP requests
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code != 200:
            return set()
        
        # Enhanced regex with TLD awareness
        pattern = rf'\b(?:[a-z0-9-]+\.)+{re.escape(domain)}\b'
        matches = set(re.findall(pattern, response.text, re.IGNORECASE))
        
        # Extract valid subdomains
        valid_subs = set()
        for match in matches:
            extracted = tldextract.extract(match)
            if extracted.registered_domain == domain:
                valid_subs.add(match)
        
        return valid_subs
    
    except Exception as e:
        return set()

def permutation_engine(discovered_subs):
    """Generate intelligent permutations of found subdomains"""
    permutations = set()
    prefixes = ['dev', 'staging', 'test', 'qa', 'prod', 'beta', 'alpha', 'uat']
    suffixes = ['-old', '-new', '-backup', '-legacy', '-2023', '-2024']
    
    for sub in discovered_subs:
        # Skip base domain
        if '.' not in sub or sub.count('.') < 2:
            continue
            
        # Split subdomain parts
        parts = sub.split('.')
        sub_part = parts[0]
        
        # Prefix variations
        for prefix in prefixes:
            permutations.add(f"{prefix}-{sub_part}.{'.'.join(parts[1:])}")
            permutations.add(f"{prefix}{sub_part}.{'.'.join(parts[1:])}")
        
        # Suffix variations
        for suffix in suffixes:
            permutations.add(f"{sub_part}{suffix}.{'.'.join(parts[1:])}")
        
        # Subdomain insertions
        for insert in ['api', 'internal', 'external', 'service']:
            permutations.add(f"{insert}.{sub}")
    
    return permutations

def scan_target(target_domain, max_workers=MAX_WORKERS):
    """Professional scanning workflow"""
    print(f"[*] Generating sources for {target_domain}...")
    sources = generate_sources(target_domain)
    print(f"[+] Generated {len(sources)} sources for scanning")
    
    print(f"[*] Starting passive enumeration...")
    passive_subs = passive_enumeration(target_domain)
    print(f"[+] Found {len(passive_subs)} subdomains via passive recon")
    
    print(f"[*] Starting active enumeration...")
    all_subs = set(passive_subs)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(find_subdomains, target_domain, url): url
            for url in sources
        }
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                subs = future.result()
                if subs:
                    all_subs.update(subs)
            except Exception:
                pass
    
    print(f"[*] Generating permutations...")
    permutations = permutation_engine(all_subs)
    print(f"[+] Generated {len(permutations)} permutations")
    
    # Validate permutations via DNS
    valid_permutations = set()
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    resolver.lifetime = 1
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_sub = {
            executor.submit(resolver.resolve, sub, 'A'): sub
            for sub in permutations
        }
        
        for future in as_completed(future_to_sub):
            sub = future_to_sub[future]
            try:
                future.result()
                valid_permutations.add(sub)
            except:
                pass
    
    print(f"[+] Validated {len(valid_permutations)} new subdomains from permutations")
    all_subs.update(valid_permutations)
    
    return sorted(all_subs)

def save_results(subdomains, output_file):
    """Save results to text file"""
    with open(output_file, 'w') as f:
        f.write("\n".join(subdomains))
    
    print(f"[+] Results saved to {output_file}")
    print(f"[+] Found {len(subdomains)} unique subdomains")

def main():
    # ================== UPDATED ARGPARSE SETUP ================== #
    parser = argparse.ArgumentParser(
        description='Professional Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Basic scan:
    python NULL200OK.py -d example.com
  
  Full scan with custom output:
    python NULL200OK.py -d company.com -o results.txt -t 20
  
  Scan with custom wordlist:
    python NULL200OK.py -d org.net -w subdomains.txt
  
  Fast scan with reduced threads:
    python NULL200OK.py -d target.io -t 8'''
    )
    
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    parser.add_argument('-o', '--output', help='Output file name', default='')
    parser.add_argument('-w', '--wordlist', help='Custom subdomain wordlist', default='')
    parser.add_argument('-t', '--threads', type=int, help='Thread count (default: 12)', default=12)
    
    args = parser.parse_args()
    
    # Set output filename
    output_file = args.output or f"subdomains_{args.domain}.txt"
    
    # Load custom wordlist if provided
    global COMMON_SUBS
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist) as f:
            COMMON_SUBS = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(COMMON_SUBS)} words from custom wordlist")
    
    # ================== UPDATED LEGAL WARNING ================== #
    print("\n" + "="*60)
    print(f"Scanning target: {args.domain}")
    print("="*60)
    print("LEGAL WARNING: This tool must only be used for authorized security testing!")
    print("Unauthorized scanning of networks/systems is ILLEGAL and may result in criminal charges.")
    print("The creator assumes NO LIABILITY for misuse of this tool.")
    print("="*60)
    print("NULL200OK Subdomain Scanner v1.0 | github.com/IBO-ATTACKS/NULL200OK")
    print("="*60 + "\n")
    
    # Start scan with thread count
    start_time = time.time()
    subdomains = scan_target(args.domain, max_workers=args.threads)
    duration = time.time() - start_time
    
    # Save results
    save_results(subdomains, output_file)
    print(f"[*] Scan completed in {duration:.2f} seconds")

if __name__ == "__main__":

    main()
