import csv
import os

def process_domains(input_file, output_file, log_file):
    # Initialize logging
    log_lines = ["Starting domain processing..."]
    log_lines.append(f"Input file: {input_file}")
    
    # Check if input file exists
    if not os.path.exists(input_file):
        error_msg = f"Error: Input file '{input_file}' not found."
        log_lines.append(error_msg)
        with open(log_file, 'w') as f:
            f.write("\n".join(log_lines))
        print("\n".join(log_lines))
        return

    # Read and process domains
    unique_domains = set()
    raw_domains = []
    invalid_count = 0
    duplicate_count = 0

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            
            # Skip header row if exists
            if any("dns.question.name" in header for header in next(reader)):
                log_lines.append("Skipping header row")
            
            for row in reader:
                if not row or not row[0]:
                    continue
                    
                domain = row[0].strip().lower()
                raw_domains.append(domain)
                
                # Skip invalid entries
                if domain in ['', '-', 'dns.question.name']:
                    invalid_count += 1
                    continue
                
                # Add to unique domains (set automatically handles duplicates)
                if domain in unique_domains:
                    duplicate_count += 1
                unique_domains.add(domain)
        
        # Prepare results
        log_lines.append(f"Total domains processed: {len(raw_domains)}")
        log_lines.append(f"Invalid entries skipped: {invalid_count}")
        log_lines.append(f"Duplicate domains skipped: {duplicate_count}")
        log_lines.append(f"Unique domains found: {len(unique_domains)}")
        log_lines.append("\nUnique domains:")
        log_lines.extend(sorted(unique_domains))
        
        # Write output files
        with open(output_file, 'w') as f:
            f.write("\n".join(sorted(unique_domains)))
        
        with open(log_file, 'w') as f:
            f.write("\n".join(log_lines))
        
        # Print log to console
        print("\n".join(log_lines))
        print(f"\nResults saved to {output_file} and {log_file}")

    except Exception as e:
        error_msg = f"Error processing file: {str(e)}"
        log_lines.append(error_msg)
        with open(log_file, 'w') as f:
            f.write("\n".join(log_lines))
        print("\n".join(log_lines))

if __name__ == "__main__":
    input_csv = "Untitled discover search.csv"
    output_txt = "domains.txt"
    log_txt = "processing_log.txt"
    
    process_domains(input_csv, output_txt, log_txt)