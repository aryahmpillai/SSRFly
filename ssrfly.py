#!/usr/bin/env python3
"""
SSRFly - A high-speed, low false-positive SSRF vulnerability testing tool
"""

import os
import sys
import argparse
import time
import logging
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
from urllib.parse import urlparse

from scanner import SSRFScanner
from utils import print_banner, validate_url, load_urls_from_file, print_result

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='SSRFly - A high-speed SSRF vulnerability testing tool',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--url', help='Single URL to test for SSRF vulnerabilities')
    group.add_argument('-f', '--file', help='File containing URLs to test (one per line)')
    
    parser.add_argument('-t', '--threads', type=int, default=10, 
                      help='Number of threads to use (default: 10)')
    parser.add_argument('-o', '--output', help='File to save results')
    parser.add_argument('-v', '--verbose', action='store_true', 
                      help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=10,
                      help='Request timeout in seconds (default: 10)')
    
    return parser.parse_args()

def setup_logging(verbose):
    """Configure logging based on verbosity level."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

def scan_url(url, timeout):
    """Scan a single URL for SSRF vulnerabilities."""
    try:
        scanner = SSRFScanner(url, timeout)
        result = scanner.scan()
        print_result(url, result)
        return result
    except Exception as e:
        logging.error(f"Error scanning {url}: {e}")
        return {
            "url": url,
            "vulnerable": False,
            "error": str(e),
            "vulnerabilities": []
        }

def main():
    """Main function."""
    args = parse_arguments()
    setup_logging(args.verbose)
    print_banner()
    
    start_time = time.time()
    urls_to_scan = []
    results = []
    
    if args.url:
        if validate_url(args.url):
            urls_to_scan.append(args.url)
        else:
            logging.error(f"Invalid URL: {args.url}")
            sys.exit(1)
    elif args.file:
        try:
            urls_to_scan = load_urls_from_file(args.file)
            if not urls_to_scan:
                logging.error(f"No valid URLs found in the file: {args.file}")
                sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading URLs from file: {e}")
            sys.exit(1)
    
    total_urls = len(urls_to_scan)
    print(f"{Fore.CYAN}[*] Starting scan on {total_urls} URL(s) with {args.threads} threads")
    
    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(scan_url, url, args.timeout) for url in urls_to_scan]
        for future in futures:
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logging.error(f"Error processing result: {e}")
    
    # Print summary
    end_time = time.time()
    vulnerable_count = sum(1 for r in results if r.get('vulnerable', False))
    
    print("\n" + "="*60)
    print(f"{Fore.CYAN}[*] Scan Summary:")
    print(f"{Fore.CYAN}[*] Total URLs scanned: {total_urls}")
    print(f"{Fore.GREEN if vulnerable_count == 0 else Fore.RED}[*] Vulnerable URLs found: {vulnerable_count}")
    print(f"{Fore.CYAN}[*] Scan duration: {end_time - start_time:.2f} seconds")
    print("="*60)
    
    # Save results to file if output is specified
    if args.output and results:
        try:
            with open(args.output, 'w') as f:
                for result in results:
                    if result.get('vulnerable', False):
                        f.write(f"URL: {result['url']}\n")
                        f.write("Vulnerabilities:\n")
                        for vuln in result.get('vulnerabilities', []):
                            f.write(f"  - Parameter: {vuln['parameter']}\n")
                            f.write(f"    Vector: {vuln['vector']}\n")
                            f.write(f"    Evidence: {vuln['evidence']}\n")
                        f.write("\n")
            print(f"{Fore.CYAN}[*] Results saved to {args.output}")
        except Exception as e:
            logging.error(f"Error saving results to file: {e}")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unhandled exception: {e}")
        sys.exit(1)
