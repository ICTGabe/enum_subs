import requests
import time
from urllib.parse import urlparse

def check_domain(url):
    try:
        # Normalize URL to include scheme if missing
        if not urlparse(url).scheme:
            url = "https://" + url
            
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Cloudflare Domain Check)"}
        )
        
        # Detect Cloudflare Error 1101
        if "1101" in response.text:
            return "UP (Cloudflare Error 1101)", response.status_code, response.text[:500] + "..."
        else:
            return "UP (Healthy)", response.status_code, response.text[:500] + "..."
            
    except requests.exceptions.RequestException as e:
        return "DOWN", None, str(e)

if __name__ == "__main__":
    # Read domains from file
    with open("domains.txt", "r") as f:
        domains = [line.strip() for line in f.readlines()]
    
    print(f"{'Domain':60} | {'Status':25} | {'HTTP Code':10} | Details")
    print("-" * 120)
    
    for domain in domains:
        status, code, details = check_domain(domain)
        http_code = str(code) if code else "N/A"
        print(f"{domain:60} | {status:25} | {http_code:10} | {details}")
        time.sleep(1)  # Prevent rate-limiting