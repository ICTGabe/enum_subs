import requests
import time
import logging
from urllib.parse import urlparse

def setup_logger():
    logger = logging.getLogger('url_checker')
    logger.setLevel(logging.INFO)
    
    # File handler
    fh = logging.FileHandler('url_checks.log')
    fh.setLevel(logging.INFO)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    
    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger

def check_domain(url, logger):
    try:
        # Normalize URL
        if not urlparse(url).scheme:
            url = "https://" + url
            
        logger.info(f"Checking: {url}")
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (Cloudflare Domain Check)"}
        )
        
        # Detect Cloudflare Error 1101
        if "1101" in response.text:
            status = "UP (Cloudflare Error 1101)"
            logger.warning(f"Cloudflare 1101 error detected on {url}")
        else:
            status = "UP (Healthy)"
        
        return status, response.status_code, response.text[:500] + "..."
            
    except requests.exceptions.RequestException as e:
        logger.error(f"Connection error for {url}: {str(e)}")
        return "DOWN", None, str(e)
    except Exception as e:
        logger.error(f"Unexpected error for {url}: {str(e)}")
        return "ERROR", None, str(e)

if __name__ == "__main__":
    logger = setup_logger()
    logger.info("Starting URL checks")
    
    try:
        # Read domains from file
        with open("domains.txt", "r") as f:
            domains = [line.strip() for line in f.readlines()]
        
        logger.info(f"Loaded {len(domains)} domains for checking")
        
        # Results table
        results = []
        results.append(f"{'Domain':60} | {'Status':25} | {'HTTP Code':10} | Details")
        results.append("-" * 120)
        
        for domain in domains:
            status, code, details = check_domain(domain, logger)
            http_code = str(code) if code else "N/A"
            results.append(f"{domain:60} | {status:25} | {http_code:10} | {details}")
            time.sleep(1)  # Prevent rate-limiting
        
        # Save results
        with open("check_results.txt", "w") as f:
            f.write("\n".join(results))
            
        logger.info("Check completed. Results saved to check_results.txt")
        
        # Print summary to console
        print("\nCheck Results Summary:")
        print("\n".join(results))
        
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)