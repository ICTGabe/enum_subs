import csv
import requests
import time
import argparse
import json
import os
import sys
from urllib.parse import urlparse

# Configuration for Filescan.io API
FILESCAN_API_KEY = "API_KEY"
FILESCAN_BASE_URL = "https://www.filescan.io/api"
MAX_ATTEMPTS = 30
POLL_INTERVAL = 10

# Suspicious Indicators Configuration
SUSPICIOUS_KEYWORDS = ['login', 'secure', 'verify', 'account', 'update', 'bank', 'admin', 'portal', 'oauth']
SHORTENERS = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do']
MALICIOUS_TLDS = ['.xyz', '.top', '.gq', '.ml', '.cf', '.tk', '.icu', '.pw', '.club']

def check_domain(domain):
    """Check domain status with enhanced security checks"""
    security_flags = []
    
    # Pre-check domain for suspicious characteristics
    domain_lower = domain.lower()
    
    # 1. Check for suspicious keywords in domain
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in domain_lower:
            security_flags.append(f"SUSPICIOUS_KEYWORD:{keyword}")
    
    # 2. Check for URL shorteners
    for shortener in SHORTENERS:
        if shortener in domain_lower:
            security_flags.append(f"URL_SHORTENER:{shortener}")
    
    # 3. Check for malicious TLDs
    for tld in MALICIOUS_TLDS:
        if domain_lower.endswith(tld):
            security_flags.append(f"MALICIOUS_TLD:{tld}")
    
    try:
        # Normalize URL to include scheme if missing
        if not urlparse(domain).scheme:
            domain = "https://" + domain
            
        response = requests.get(
            domain,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Security Domain Scanner)"},
            allow_redirects=True
        )
        
        # Response-based security checks
        
        # 1. Detect Cloudflare Error 1101
        if "1101" in response.text:
            security_flags.append("CF_ERROR_1101")
        
        # 2. Check for common malicious patterns
        malicious_indicators = [
            "phishing", "malware", "exploit", "iframe",
            "c99.php", "r57.php", "eval(", "base64_decode"
        ]
        
        for indicator in malicious_indicators:
            if indicator in response.text.lower():
                security_flags.append(f"SUSPICIOUS_CONTENT:{indicator.upper()}")
        
        # 3. Check for suspicious headers
        suspicious_headers = {
            "server": ["cloudflare", "nginx", "apache"],
            "x-powered-by": ["php", "asp.net"]
        }
        
        for header, safe_values in suspicious_headers.items():
            if header in response.headers:
                header_value = response.headers[header].lower()
                if not any(safe in header_value for safe in safe_values):
                    security_flags.append(f"SUSPICIOUS_HEADER:{header.upper()}")
        
        # 4. Special check for workers.dev domains
        if "workers.dev" in domain:
            workers_checks = [
                ("worker-script", "WORKER_SCRIPT_HEADER"),
                ("cf-ray", "CF_RAY_HEADER"),
                ("server", "cloudflare")
            ]
            
            for header, flag in workers_checks:
                if header in response.headers:
                    security_flags.append(flag)
        
        if security_flags:
            status = "UP (Security Flags)"
        elif response.status_code == 200:
            status = "UP (Healthy)"
        else:
            status = f"UP (HTTP {response.status_code})"
            
        return status, response.status_code, response.text[:500] + "...", security_flags
            
    except requests.exceptions.RequestException as e:
        return "DOWN", None, str(e), security_flags  # Return any pre-request flags

def submit_url_scan(url, private=False, no_sharing=False):
    """Submit URL for scanning with privacy options and enhanced scan options"""
    headers = {"X-Api-Key": FILESCAN_API_KEY}
    endpoint = f"{FILESCAN_BASE_URL}/scan/url"
    
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    scan_options = {
        "osint": True,
        "extended_osint": True,
        "extracted_files_osint": True,
        "visualization": True,
        "files_download": True,
        "resolve_domains": True,
        "input_file_yara": True,
        "extracted_files_yara": True,
        "whois": True,
        "ips_meta": True,
        "images_ocr": True,
        "certificates": True,
        "url_analysis": True,
        "extract_strings": True,
        "ocr_qr": True,
        "phishing_detection": True,
        "rapid_mode": False,
        "early_termination": False
    }
    
    form_data = {
        "url": url,
        "filename": f"scan_{int(time.time())}.url",
        "tags": "enhanced-detailed-scan",
        "private": "true" if private else "false",
        "no_sharing": "true" if no_sharing else "false",
        "scan_options": json.dumps(scan_options)
    }
    
    try:
        response = requests.post(endpoint, headers=headers, data=form_data)
        response.raise_for_status()
        return response.json().get('flow_id')
    except Exception as e:
        print(f"Submission error: {str(e)}")
        return None

def poll_scan_results(flow_id):
    """Poll scan results until completion or timeout"""
    headers = {"X-Api-Key": FILESCAN_API_KEY}
    endpoint = f"{FILESCAN_BASE_URL}/scan/{flow_id}/report"
    report_url = f"https://www.filescan.io/uploads/{flow_id}"
    
    attempts = 0
    while attempts < MAX_ATTEMPTS:
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            if data.get('allFinished'):
                return data, report_url
                
            time.sleep(POLL_INTERVAL)
            attempts += 1
            print(f"Polling... Attempt {attempts}/{MAX_ATTEMPTS}")
                
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error: {str(e)}")
            break
        except Exception as e:
            print(f"Polling error: {str(e)}")
            break
    
    print("\nMax polling attempts reached")
    print(f"Manual check: {report_url}")
    return None, report_url

def get_scan_verdict(data):
    """Determine the highest threat level from scan results"""
    max_level = 0
    for report in data.get('reports', {}).values():
        level = report.get('finalVerdict', {}).get('threatLevel', 0)
        if level > max_level:
            max_level = level
    
    if max_level == 0:
        return "BENIGN (Safe)"
    elif max_level < 0.3:
        return f"SUSPICIOUS - LOW (Level {max_level})"
    elif max_level < 0.7:
        return f"SUSPICIOUS - MEDIUM (Level {max_level})"
    elif max_level < 0.9:
        return f"SUSPICIOUS - HIGH (Level {max_level})"
    else:
        return f"MALICIOUS (Level {max_level})"

def run_url_scan(domain):
    """Run full URL scan and return results"""
    print(f"\n{'='*50}")
    print(f"Starting deep scan for: {domain}")
    print(f"{'='*50}")
    
    flow_id = submit_url_scan(domain)
    if not flow_id:
        return "Scan failed to start", "N/A", "N/A"
    
    print(f"Scan submitted. Flow ID: {flow_id}")
    result, report_url = poll_scan_results(flow_id)
    
    if result:
        verdict = get_scan_verdict(result)
        threat_level = verdict.split("(")[-1].split(")")[0].strip()
        return verdict, threat_level, report_url
    else:
        return "Scan incomplete", "N/A", report_url

def prompt_for_scan(domain, flags):
    """Prompt user to run Filescan.io scan for a suspicious domain"""
    print(f"\n{'!'*50}")
    print(f"⚠️  SUSPICIOUS DOMAIN DETECTED: {domain}")
    print(f"🔍 Security Flags: {', '.join(flags)}")
    response = input(f"🚀 Run Filescan.io deep scan for {domain}? (y/n): ").strip().lower()
    return response == 'y'

def main():
    # Prompt for input file if not provided as argument
    input_file = input("Enter path to input CSV file: ").strip()
    if not os.path.isfile(input_file):
        print(f"Error: File not found - {input_file}")
        sys.exit(1)
        
    # Generate output file name
    base_name = os.path.splitext(os.path.basename(input_file))[0]
    output_file = f"{base_name}_security_report.csv"
    
    # Read input CSV and extract domains
    domains_to_check = set()
    rows = []
    
    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('dns.question.name', '').strip()
            if domain:
                # Remove trailing dot if present
                domain = domain.rstrip('.')
                domains_to_check.add(domain)
                rows.append(row)
    
    # Check domains and store results
    results = {}
    print(f"\nChecking {len(domains_to_check)} domains for security indicators...\n")
    print(f"{'Domain':60} | {'Status':25} | {'HTTP Code':10} | {'Security Flags'}")
    print("-" * 120)
    
    for domain in domains_to_check:
        status, code, details, security_flags = check_domain(domain)
        http_code = str(code) if code else "N/A"
        flags_str = ", ".join(security_flags) if security_flags else "None"
        
        print(f"{domain:60} | {status:25} | {http_code:10} | {flags_str}")
        
        # Store results with additional fields for scanning
        results[domain] = {
            'status': status,
            'http_code': code,
            'details': details,
            'security_flags': security_flags,
            'flag_count': len(security_flags),
            'scan_verdict': "Not scanned",
            'threat_level': "N/A",
            'scan_report': "N/A"
        }
        
        # Prompt for deep scan if suspicious indicators found
        if security_flags and prompt_for_scan(domain, security_flags):
            verdict, threat_level, report_url = run_url_scan(domain)
            results[domain]['scan_verdict'] = verdict
            results[domain]['threat_level'] = threat_level
            results[domain]['scan_report'] = report_url
        
        time.sleep(1)  # Prevent rate-limiting
    
    # Write output CSV with security information
    with open(output_file, 'w', newline='', encoding='utf-8') as f_out:
        # Preserve original fields and add security columns
        fieldnames = list(rows[0].keys()) + [
            'Status', 'HTTP_Code', 'Security_Flags', 'Flag_Count',
            'Scan_Verdict', 'Threat_Level', 'Scan_Report'
        ]
        
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in rows:
            domain = row['dns.question.name'].strip().rstrip('.')
            if domain in results:
                data = results[domain]
                row['Status'] = data['status']
                row['HTTP_Code'] = data['http_code'] if data['http_code'] is not None else 'N/A'
                row['Security_Flags'] = ", ".join(data['security_flags'])
                row['Flag_Count'] = data['flag_count']
                row['Scan_Verdict'] = data['scan_verdict']
                row['Threat_Level'] = data['threat_level']
                row['Scan_Report'] = data['scan_report']
            writer.writerow(row)
    
    print(f"\n✅ Security report generated: {output_file}")
    print(f"Total domains checked: {len(domains_to_check)}")
    scanned_count = sum(1 for d in results.values() if d['scan_verdict'] != "Not scanned")
    print(f"Domains deep-scanned: {scanned_count}")

if __name__ == "__main__":
    main()