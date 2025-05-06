"""
Request handling module for SSRFly
"""

import logging
import time
import random
import requests
from urllib.parse import urlparse, urljoin
from requests.exceptions import RequestException, Timeout
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Requester:
    """
    Class for handling HTTP requests with customizable options.
    """
    
    def __init__(self, timeout=10, max_retries=2, delay=0):
        """
        Initialize the Requester with custom options.
        
        Args:
            timeout (int): Request timeout in seconds
            max_retries (int): Maximum number of retries for failed requests
            delay (float): Delay between requests in seconds
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.session = requests.Session()
        
        # Set default headers to mimic a browser
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        })
    
    def get(self, url, params=None, headers=None, allow_redirects=True, verify=False):
        """
        Send a GET request to the specified URL.
        
        Args:
            url (str): URL to send the GET request to
            params (dict, optional): URL parameters
            headers (dict, optional): Additional HTTP headers
            allow_redirects (bool): Whether to follow redirects
            verify (bool): Whether to verify SSL certificates
            
        Returns:
            requests.Response or None: Response object or None if request failed
        """
        return self._send_request('GET', url, params=params, headers=headers, 
                                allow_redirects=allow_redirects, verify=verify)
    
    def post(self, url, data=None, json=None, headers=None, allow_redirects=True, verify=False):
        """
        Send a POST request to the specified URL.
        
        Args:
            url (str): URL to send the POST request to
            data (dict, optional): Form data
            json (dict, optional): JSON data
            headers (dict, optional): Additional HTTP headers
            allow_redirects (bool): Whether to follow redirects
            verify (bool): Whether to verify SSL certificates
            
        Returns:
            requests.Response or None: Response object or None if request failed
        """
        return self._send_request('POST', url, data=data, json=json, headers=headers, 
                                allow_redirects=allow_redirects, verify=verify)
    
    def _send_request(self, method, url, **kwargs):
        """
        Send an HTTP request with retry logic.
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            url (str): URL to send the request to
            **kwargs: Additional arguments to pass to requests
            
        Returns:
            requests.Response or None: Response object or None if all retries failed
        """
        merged_headers = {}
        if kwargs.get('headers'):
            merged_headers.update(kwargs['headers'])
            kwargs['headers'] = merged_headers
        
        retries = 0
        while retries <= self.max_retries:
            try:
                # Add a small delay if this is a retry
                if retries > 0 and self.delay:
                    time.sleep(self.delay + random.uniform(0, 0.5))
                
                logging.debug(f"Sending {method} request to {url}")
                response = self.session.request(
                    method, url, timeout=self.timeout, **kwargs
                )
                
                logging.debug(f"Received response from {url}: {response.status_code}")
                return response
                
            except Timeout:
                logging.debug(f"Request to {url} timed out (retry {retries}/{self.max_retries})")
                retries += 1
                
            except RequestException as e:
                logging.debug(f"Request to {url} failed: {e} (retry {retries}/{self.max_retries})")
                retries += 1
                
            except Exception as e:
                logging.debug(f"Unexpected error for {url}: {e} (retry {retries}/{self.max_retries})")
                retries += 1
        
        logging.warning(f"All retries failed for {url}")
        return None
    
    def get_request_host(self, url):
        """
        Extract the host from a URL.
        
        Args:
            url (str): URL to extract host from
            
        Returns:
            str: Host of the URL
        """
        parsed_url = urlparse(url)
        return parsed_url.netloc
    
    def is_same_origin(self, url1, url2):
        """
        Check if two URLs have the same origin.
        
        Args:
            url1 (str): First URL
            url2 (str): Second URL
            
        Returns:
            bool: True if URLs have the same origin, False otherwise
        """
        parsed_url1 = urlparse(url1)
        parsed_url2 = urlparse(url2)
        
        origin1 = f"{parsed_url1.scheme}://{parsed_url1.netloc}"
        origin2 = f"{parsed_url2.scheme}://{parsed_url2.netloc}"
        
        return origin1.lower() == origin2.lower()
    
    def close(self):
        """Close the requests session."""
        self.session.close()
