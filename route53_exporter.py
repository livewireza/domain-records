import os
import csv
import subprocess
import sys
import re

# --- Configuration ---
DOMAINS_FILE = 'domains.txt'
# --- End Configuration ---

def run_dig_command(domain, record_type, short_output=False):
    """
    Executes a dig command and returns its stdout.
    """
    command = ['dig', record_type, domain]
    if short_output:
        command.append('+short')

    try:
        # Run dig command, capture stdout and stderr
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False # Do not raise an exception for non-zero exit codes immediately
        )
        if result.returncode != 0:
            print(f"  Warning: dig command failed for {record_type} {domain}. Error: {result.stderr.strip()}")
            return ""
        return result.stdout
    except FileNotFoundError:
        print("Error: 'dig' command not found. Please ensure dig is installed and in your PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"  Error running dig command for {record_type} {domain}: {e}")
        return ""

def parse_a_records(domain, dig_output):
    """
    Parses dig A +short output and returns a list of records.
    """
    records = []
    # Each line is an IP address
    for line in dig_output.strip().split('\n'):
        if line and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line): # Basic IP validation
            # For +short, TTL is not directly available, so we'll use a placeholder or omit
            # However, for consistency with MX, we'll try to get it from full dig if needed,
            # but for +short, it's typically just the value.
            # Let's assume a default TTL or leave empty for +short if not doing full dig.
            # For this simplified version, we'll just get the IP.
            records.append({'Name': domain, 'Type': 'A', 'Value': line, 'TTL': 'N/A'})
    return records

def parse_mx_records(domain, dig_output):
    """
    Parses full dig MX output and returns a list of records.
    """
    records = []
    # Regex to find lines in the ANSWER SECTION for MX records
    # Example: example.com.            3599    IN      MX      10 mail.example.com.
    mx_pattern = re.compile(r'^\s*{}\.\s+(\d+)\s+IN\s+MX\s+(\d+)\s+(.+?)\.?\s*$'.format(re.escape(domain)))

    for line in dig_output.split('\n'):
        match = mx_pattern.match(line)
        if match:
            ttl = match.group(1)
            preference = match.group(2)
            hostname = match.group(3)
            value = f"{preference} {hostname}"
            records.append({'Name': domain, 'Type': 'MX', 'Value': value, 'TTL': ttl})
    return records

def main():
    """
    Main function to orchestrate the record export for each domain using dig.
    """
    print("Starting DNS record export using dig for specified domains.")

    # Read domains from domains.txt
    domains_to_export = []
    if os.path.exists(DOMAINS_FILE):
        with open(DOMAINS_FILE, 'r') as f:
            domains_to_export = [line.strip() for line in f if line.strip()]
        print(f"Read {len(domains_to_export)} domains from {DOMAINS_FILE}")
    else:
        print(f"Error: {DOMAINS_FILE} not found. Please create it with one domain per line.")
        sys.exit(1)

    if not domains_to_export:
        print("No domains found in domains.txt. Exiting.")
        sys.exit(0)

    exported_files = []

    for domain in domains_to_export:
        # Sanitize domain name for filename (replace dots with underscores for safety)
        safe_domain_name = domain.replace('.', '_')
        output_csv_file = f"{safe_domain_name}-records.csv"
        exported_files.append(output_csv_file)

        print(f"\nProcessing domain: {domain}")
        all_records_for_domain = []

        # --- Dig A records ---
        print(f"  Querying A records for {domain}...")
        a_output = run_dig_command(domain, 'A', short_output=True)
        if a_output:
            a_records = parse_a_records(domain, a_output)
            all_records_for_domain.extend(a_records)
            print(f"  Found {len(a_records)} A records.")
        else:
            print(f"  No A records found or dig failed for {domain}.")

        # --- Dig MX records ---
        print(f"  Querying MX records for {domain}...")
        mx_output = run_dig_command(domain, 'MX', short_output=False) # MX needs full output for preference/hostname
        if mx_output:
            mx_records = parse_mx_records(domain, mx_output)
            all_records_for_domain.extend(mx_records)
            print(f"  Found {len(mx_records)} MX records.")
        else:
            print(f"  No MX records found or dig failed for {domain}.")

        # Write records to CSV
        if all_records_for_domain:
            print(f"  Writing records to {output_csv_file}...")
            with open(output_csv_file, 'w', newline='', encoding='utf-8') as csvfile:
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(['Name', 'Type', 'Value', 'TTL']) # Updated CSV header
                for record in all_records_for_domain:
                    csv_writer.writerow([record['Name'], record['Type'], record['Value'], record['TTL']])
            print(f"  Records exported for {domain} to {output_csv_file}")
        else:
            print(f"  No A or MX records found for {domain} to export.")

    print("\nExport complete.")
    if exported_files:
        print("Generated files:")
        for f in exported_files:
            print(f"- {f}")
    else:
        print("No files were generated.")

if __name__ == "__main__":
    main()
