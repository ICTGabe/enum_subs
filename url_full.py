import csv
import requests
import time
from urllib.parse import urlparse

def check_domain(domain):
    try:
        # Normalize URL to include scheme if missing
        if not urlparse(domain).scheme:
            domain = "https://" + domain
            
        response = requests.get(
            domain,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Domain Check Script)"}
        )
        
        # Detect Cloudflare Error 1101
        if "1101" in response.text:
            return "UP (Cloudflare Error 1101)", response.status_code, response.text[:500] + "..."
        else:
            return "UP (Healthy)", response.status_code, response.text[:500] + "..."
            
    except requests.exceptions.RequestException as e:
        return "DOWN", None, str(e)

if __name__ == "__main__":
    input_file = "dns_data.csv"
    output_file = "domain_status_report.csv"
    
    # Read input CSV and extract domains
    domains_to_check = set()
    rows = []
    
    with open(input_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            domain = row.get('dns.question.name', '').strip()
            if domain:
                # Remove trailing dot if present (common in DNS records)
                domain = domain.rstrip('.')
                domains_to_check.add(domain)
                rows.append(row)
    
    # Check domains and store results
    results = {}
    print(f"\nChecking {len(domains_to_check)} domains...\n")
    print(f"{'Domain':60} | {'Status':25} | {'HTTP Code':10} | Details")
    print("-" * 120)
    
    for domain in domains_to_check:
        status, code, details = check_domain(domain)
        results[domain] = (status, code, details)
        http_code = str(code) if code else "N/A"
        print(f"{domain:60} | {status:25} | {http_code:10} | {details}")
        time.sleep(1)  # Prevent rate-limiting
    
    # Write output CSV with status information
    with open(output_file, 'w', newline='') as f_out:
        fieldnames = list(rows[0].keys()) + ['Status', 'HTTP_Code', 'Details']
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in rows:
            domain = row['dns.question.name'].strip().rstrip('.')
            if domain in results:
                status, code, details = results[domain]
                row['Status'] = status
                row['HTTP_Code'] = code if code is not None else 'N/A'
                row['Details'] = details
            writer.writerow(row)
    
    print(f"\n✅ Report generated: {output_file}")
    print(f"Total domains checked: {len(domains_to_check)}")
    print(f"Total records processed: {len(rows)}")