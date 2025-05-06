"""
Utility functions for SSRFly
"""

import os
import re
import sys
import logging
from urllib.parse import urlparse
from colorama import Fore, Style

def print_banner():
    """Print the SSRFly ASCII art banner."""
    banner = """
  ██████   ██████  ██████  ███████ ██      ██    ██ 
  ██      ██      ██   ██ ██      ██       ██  ██  
  ███████  █████  ██████  █████   ██        ████   
       ██      ██ ██   ██ ██      ██         ██    
  ███████ ███████ ██   ██ ██      ███████    ██    
                                                    
      🚀 High-Speed SSRF Vulnerability Scanner 🚀    
          Created with <3 by aryahmpillai       
    """
    print(f"{Fore.CYAN}{banner}{Style.RESET_ALL}")
    print("="*60)
    print()

def validate_url(url):
    """
    Validate if the given string is a properly formatted URL.
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if URL is valid, False otherwise
    """
    if not url:
        return False
    
    # Add http:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def load_urls_from_file(filepath):
    """
    Load URLs from a file, one URL per line.
    
    Args:
        filepath (str): Path to the file
        
    Returns:
        list: List of valid URLs
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    with open(filepath, 'r') as f:
        lines = f.readlines()
    
    urls = []
    for line in lines:
        url = line.strip()
        if url and not url.startswith('#'):  # Skip empty lines and comments
            # Add http:// if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            if validate_url(url):
                urls.append(url)
            else:
                logging.warning(f"Skipping invalid URL: {url}")
    
    return urls

def print_result(url, result):
    """
    Print the scan result for a URL.
    
    Args:
        url (str): The URL that was scanned
        result (dict): Scan result dictionary
    """
    vulnerable = result.get('vulnerable', False)
    vulnerabilities = result.get('vulnerabilities', [])
    
    if vulnerable:
        print(f"\n{Fore.RED}[VULNERABLE] {url}{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            param = vuln.get('parameter', 'N/A')
            vector = vuln.get('vector', 'N/A')
            evidence = vuln.get('evidence', 'N/A')
            
            print(f"  {Fore.YELLOW}Parameter:{Style.RESET_ALL} {param}")
            print(f"  {Fore.YELLOW}Vector:{Style.RESET_ALL} {vector}")
            print(f"  {Fore.YELLOW}Evidence:{Style.RESET_ALL} {evidence}")
            print()
    else:
        error = result.get('error')
        if error:
            print(f"{Fore.YELLOW}[ERROR] {url} - {error}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[SAFE] {url}{Style.RESET_ALL}")

def extract_urls_from_response(response_text):
    """
    Extract URLs from a response text.
    
    Args:
        response_text (str): HTTP response text
    
    Returns:
        list: List of URLs found in the response
    """
    # Simple regex pattern to find URLs
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    return url_pattern.findall(response_text)

def is_ip_internal(ip):
    """
    Check if an IP address is internal.
    
    Args:
        ip (str): IP address to check
    
    Returns:
        bool: True if internal, False otherwise
    """
    if not ip:
        return False
        
    # Check for localhost
    if ip == "localhost" or ip == "127.0.0.1" or ip == "::1":
        return True
        
    # Check for private IP ranges
    private_ranges = [
        re.compile(r'^10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
        re.compile(r'^192\.168\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
        re.compile(r'^169\.254\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
        re.compile(r'^127\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'),
        re.compile(r'^0\.0\.0\.0$'),
        re.compile(r'^::1$'),
        re.compile(r'^[fF][cCdD]00:'),
        re.compile(r'^[fF][eE]80:')
    ]
    
    return any(pattern.match(ip) for pattern in private_ranges)
