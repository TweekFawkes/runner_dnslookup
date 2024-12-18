import os
import subprocess
import sys

# Get the current working directory from environment
current_dir = os.getenv('PWD', os.getcwd())
requirements_path = os.path.join(current_dir, 'requirements.txt')

# Install required packages from requirements.txt
# try:
#     subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements_path])
# except subprocess.CalledProcessError as e:
#     print(f"Error installing requirements: {e}")
#     sys.exit(1)

import argparse
from urllib.parse import urlparse
import socket
import dns.resolver

def extract_domain_and_port(input_str):
    # Parse URL if given a full URL
    parsed = urlparse(input_str if '://' in input_str else f'http://{input_str}')
    domain = parsed.netloc or parsed.path
    
    # Split domain and port if port exists
    if ':' in domain:
        domain, port = domain.split(':')
        port = int(port)
    else:
        port = None
        
    return domain.strip('/'), port

def resolve_domain(domain):
    try:
        # Get all IP addresses associated with the domain
        ip_addresses = socket.getaddrinfo(domain, None)
        # Extract unique IP addresses (removing duplicates and considering only IPv4 and IPv6)
        unique_ips = set(addr[4][0] for addr in ip_addresses)
        return list(unique_ips)
    except socket.gaierror:
        return []

def lookup_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = []
            for rdata in answers:
                if record_type == 'MX':
                    records[record_type].append(f"{rdata.exchange} (priority: {rdata.preference})")
                elif record_type == 'SOA':
                    records[record_type].append(
                        f"primary NS: {rdata.mname}, responsible: {rdata.rname}, "
                        f"serial: {rdata.serial}, refresh: {rdata.refresh}, "
                        f"retry: {rdata.retry}, expire: {rdata.expire}, "
                        f"minimum TTL: {rdata.minimum}"
                    )
                else:
                    records[record_type].append(str(rdata))
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"\n[!] Domain {domain} does not exist")
            return None
        except Exception as e:
            print(f"\n[!] Error looking up {record_type} records: {str(e)}")
            continue
    
    return records

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--domain_name', required=True, help='Domain name to check')
    args = parser.parse_args()

    domain, port = extract_domain_and_port(args.domain_name)
    print(f"\n[*] Checking domain: {domain}")

    # Resolve IP addresses
    ip_addresses = resolve_domain(domain)
    if ip_addresses:
        print("\n[*] Resolved IP addresses:")
        for ip in ip_addresses:
            print(f"    - {ip}")
    else:
        print("\n[!] Could not resolve any IP addresses")

    # Look up DNS records
    print("\n[*] Looking up DNS records...")
    dns_records = lookup_dns_records(domain)
    if dns_records:
        for record_type, records in dns_records.items():
            if records:
                print(f"\n[+] {record_type} Records:")
                for record in records:
                    print(f"    - {record}")

if __name__ == "__main__":
    main()
