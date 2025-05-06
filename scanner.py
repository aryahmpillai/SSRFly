"""
SSRF vulnerability scanner implementation for SSRFly
"""

import logging
import re
import random
import string
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin
import socket
import ipaddress

from payloads import SSRFPayloads
from requester import Requester
from utils import extract_urls_from_response, is_ip_internal

class SSRFScanner:
    """
    Scanner class to detect SSRF vulnerabilities in web applications.
    """
    
    def __init__(self, target_url, timeout=10):
        """
        Initialize the SSRF scanner.
        
        Args:
            target_url (str): URL to scan for SSRF vulnerabilities
            timeout (int): Request timeout in seconds
        """
        self.target_url = target_url
        self.requester = Requester(timeout=timeout)
        self.payloads = SSRFPayloads()
        self.injectable_params = {}
        self.scan_results = {
            "url": target_url,
            "vulnerable": False,
            "vulnerabilities": []
        }
    
    def scan(self):
        """
        Execute a full SSRF scan on the target URL.
        
        Returns:
            dict: Scan results containing vulnerability information
        """
        try:
            logging.info(f"Starting SSRF scan on {self.target_url}")
            
            # First, analyze the URL structure to find possible injection points
            self._analyze_url_structure()
            
            # Get baseline response
            baseline_response = self._get_baseline_response()
            if not baseline_response:
                logging.error(f"Failed to get baseline response from {self.target_url}")
                self.scan_results['error'] = "Failed to establish baseline connection"
                return self.scan_results
            
            # Detect potential SSRF via URL parameter manipulation
            self._scan_url_parameters(baseline_response)
            
            # If form is found, test form submissions
            self._scan_forms(baseline_response)
            
            # Check for blind SSRF - would need a callback server in a real implementation
            # self._scan_for_blind_ssrf()
            
            return self.scan_results
            
        except Exception as e:
            logging.error(f"Error during SSRF scan: {e}")
            self.scan_results['error'] = str(e)
            return self.scan_results
        finally:
            self.requester.close()
    
    def _analyze_url_structure(self):
        """Analyze the URL structure to identify potential injection points."""
        parsed_url = urlparse(self.target_url)
        
        # Extract parameters from query string
        query_params = parse_qs(parsed_url.query)
        
        # Look for parameters that might be vulnerable to SSRF
        potential_ssrf_params = [
            'url', 'uri', 'path', 'src', 'href', 'data', 'redirect',
            'redirect_to', 'redirect_uri', 'return', 'return_to', 'next',
            'link', 'links', 'goto', 'target', 'destination', 'domain',
            'callback', 'return_url', 'load', 'page', 'file', 'reference',
            'site', 'html', 'endpoint', 'server', 'host', 'api'
        ]
        
        # Identify potential SSRF parameters
        for param, values in query_params.items():
            # Check if parameter name suggests URL processing
            if any(ssrf_param in param.lower() for ssrf_param in potential_ssrf_params):
                self.injectable_params[param] = values[0]
                logging.debug(f"Potential SSRF parameter identified: {param}={values[0]}")
            
            # Check if parameter value resembles a URL
            elif any(value.startswith(('http://', 'https://', 'ftp://', 'file://')) for value in values):
                self.injectable_params[param] = values[0]
                logging.debug(f"Parameter with URL-like value: {param}={values[0]}")
        
        # If no parameters found, use all parameters for testing
        if not self.injectable_params and query_params:
            self.injectable_params = {param: values[0] for param, values in query_params.items()}
            logging.debug(f"No specific SSRF parameters found, using all query parameters: {self.injectable_params}")
        
        logging.info(f"Identified {len(self.injectable_params)} potential injectable parameters")
    
    def _get_baseline_response(self):
        """
        Get baseline response for comparison during scanning.
        
        Returns:
            requests.Response or None: Baseline response or None if request failed
        """
        try:
            logging.debug(f"Getting baseline response from {self.target_url}")
            response = self.requester.get(self.target_url, allow_redirects=True, verify=False)
            
            if response and response.status_code < 500:
                logging.debug(f"Baseline response received: {response.status_code} {len(response.content)} bytes")
                return response
            
            logging.warning(f"Baseline response has error status code: {response.status_code if response else 'None'}")
            return None
            
        except Exception as e:
            logging.error(f"Error getting baseline response: {e}")
            return None
    
    def _scan_url_parameters(self, baseline_response):
        """
        Scan URL parameters for SSRF vulnerabilities.
        
        Args:
            baseline_response (requests.Response): Baseline response for comparison
        """
        if not self.injectable_params:
            logging.info("No URL parameters to test")
            return
        
        logging.info(f"Testing {len(self.injectable_params)} URL parameters for SSRF")
        
        parsed_url = urlparse(self.target_url)
        
        # Select a subset of payloads for efficiency
        test_payloads = SSRFPayloads.get_all_payloads()
        random.shuffle(test_payloads)
        test_payloads = test_payloads[:min(50, len(test_payloads))]  # Limit to 50 payloads for efficiency
        
        for param, original_value in self.injectable_params.items():
            logging.debug(f"Testing parameter: {param}")
            
            for payload in test_payloads:
                # Create a new query string with the payload
                query_params = parse_qs(parsed_url.query)
                query_params[param] = [payload]
                
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))
                
                try:
                    response = self.requester.get(test_url, allow_redirects=True, verify=False)
                    
                    if response and self._analyze_ssrf_response(response, baseline_response, payload):
                        self._register_vulnerability(param, payload, response.text[:100])
                        # Skip remaining payloads for this parameter after finding a vulnerability
                        break
                        
                except Exception as e:
                    logging.debug(f"Error testing payload for param {param}: {e}")
    
    def _scan_forms(self, baseline_response):
        """
        Scan HTML forms for SSRF vulnerabilities.
        
        Args:
            baseline_response (requests.Response): Baseline response containing HTML
        """
        # Simple form detection via regex (a real implementation would use a proper HTML parser)
        forms = re.findall(r'<form[^>]*>(.*?)</form>', baseline_response.text, re.DOTALL | re.IGNORECASE)
        
        if not forms:
            logging.info("No forms found to test")
            return
        
        logging.info(f"Found {len(forms)} forms to test")
        
        for i, form in enumerate(forms):
            action_match = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']+)["\']', form, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else self.target_url
            method = method_match.group(1) if method_match else 'GET'
            
            # Make action URL absolute if it's relative
            if action.startswith('/'):
                parsed_url = urlparse(self.target_url)
                action = f"{parsed_url.scheme}://{parsed_url.netloc}{action}"
            elif not action.startswith(('http://', 'https://')):
                action = urljoin(self.target_url, action)
            
            # Extract form fields
            input_fields = re.findall(r'<input[^>]*>', form, re.IGNORECASE)
            textarea_fields = re.findall(r'<textarea[^>]*>(.*?)</textarea>', form, re.IGNORECASE | re.DOTALL)
            select_fields = re.findall(r'<select[^>]*>(.*?)</select>', form, re.IGNORECASE | re.DOTALL)
            
            form_fields = {}
            potential_ssrf_fields = []
            
            # Process input fields
            for input_field in input_fields:
                name_match = re.search(r'name=["\']([^"\']+)["\']', input_field, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']+)["\']', input_field, re.IGNORECASE)
                input_type = re.search(r'type=["\']([^"\']+)["\']', input_field, re.IGNORECASE)
                
                if name_match:
                    field_name = name_match.group(1)
                    field_value = value_match.group(1) if value_match else ''
                    field_type = input_type.group(1).lower() if input_type else 'text'
                    
                    # Skip submit, button, reset inputs
                    if field_type in ['submit', 'button', 'reset', 'image']:
                        continue
                    
                    form_fields[field_name] = field_value
                    
                    # Check if field name suggests URL processing
                    url_related_fields = ['url', 'uri', 'link', 'href', 'src', 'domain', 'website']
                    if any(url_field in field_name.lower() for url_field in url_related_fields):
                        potential_ssrf_fields.append(field_name)
            
            # Process textarea fields
            for textarea in textarea_fields:
                name_match = re.search(r'name=["\']([^"\']+)["\']', textarea, re.IGNORECASE)
                if name_match:
                    field_name = name_match.group(1)
                    form_fields[field_name] = ''
            
            # Process select fields (just extract the name, not the options)
            for select in select_fields:
                name_match = re.search(r'name=["\']([^"\']+)["\']', select, re.IGNORECASE)
                if name_match:
                    field_name = name_match.group(1)
                    form_fields[field_name] = ''
            
            # If no URL-related fields found, test all fields
            if not potential_ssrf_fields and form_fields:
                potential_ssrf_fields = list(form_fields.keys())
            
            # Test fields with SSRF payloads
            if potential_ssrf_fields:
                test_payloads = SSRFPayloads.get_all_payloads()[:20]  # Limit payloads for efficiency
                
                for field_name in potential_ssrf_fields:
                    original_value = form_fields.get(field_name, '')
                    
                    for payload in test_payloads:
                        test_form_data = form_fields.copy()
                        test_form_data[field_name] = payload
                        
                        try:
                            if method.upper() == 'POST':
                                response = self.requester.post(action, data=test_form_data, allow_redirects=True, verify=False)
                            else:
                                response = self.requester.get(action, params=test_form_data, allow_redirects=True, verify=False)
                            
                            if response and self._analyze_ssrf_response(response, baseline_response, payload):
                                self._register_vulnerability(field_name, payload, response.text[:100], form_index=i)
                                break
                                
                        except Exception as e:
                            logging.debug(f"Error testing form payload: {e}")
    
    def _analyze_ssrf_response(self, response, baseline_response, payload):
        """
        Analyze response for SSRF vulnerability indicators.
        
        Args:
            response (requests.Response): Response to analyze
            baseline_response (requests.Response): Baseline response for comparison
            payload (str): The payload that was used
            
        Returns:
            bool: True if response indicates SSRF vulnerability, False otherwise
        """
        if not response:
            return False
        
        # Check for common SSRF indicators in the response
        for indicator in SSRFPayloads.get_ssrf_indicators():
            if indicator in response.text and indicator not in baseline_response.text:
                logging.info(f"SSRF indicator '{indicator}' found in response")
                return True
        
        # Check for status code anomalies
        if baseline_response.status_code != response.status_code:
            if response.status_code in [200, 302, 301] and "127.0.0.1" in payload:
                logging.info(f"Status code changed from {baseline_response.status_code} to {response.status_code} with payload")
                return True
        
        # Check if response size is significantly different (might indicate payload execution)
        baseline_size = len(baseline_response.content)
        response_size = len(response.content)
        size_diff_percent = abs(baseline_size - response_size) / max(baseline_size, 1) * 100
        
        if size_diff_percent > 50:  # If size differs by more than 50%
            logging.info(f"Response size changed significantly: {baseline_size} -> {response_size} bytes")
            return True
        
        # Check for redirect to internal hosts
        if response.history:
            for redirect in response.history:
                redirect_url = redirect.headers.get('Location', '')
                if redirect_url:
                    redirect_host = urlparse(redirect_url).netloc
                    try:
                        ip = socket.gethostbyname(redirect_host)
                        if is_ip_internal(ip):
                            logging.info(f"Detected redirect to internal IP: {ip}")
                            return True
                    except:
                        pass
        
        # Extract URLs from response and check if they are internal
        extracted_urls = extract_urls_from_response(response.text)
        for url in extracted_urls:
            if url not in baseline_response.text:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        try:
                            ip = socket.gethostbyname(parsed.netloc)
                            if is_ip_internal(ip):
                                logging.info(f"Internal IP {ip} found in response via URL {url}")
                                return True
                        except:
                            pass
                except:
                    pass
        
        return False
    
    def _register_vulnerability(self, param, payload, evidence, form_index=None):
        """
        Register a vulnerability finding.
        
        Args:
            param (str): Parameter name where vulnerability was found
            payload (str): Payload that triggered the vulnerability
            evidence (str): Evidence from the response
            form_index (int, optional): Index of the form if vulnerability was in a form
        """
        vulnerability = {
            "parameter": param,
            "vector": payload,
            "evidence": evidence,
            "form_index": form_index
        }
        
        self.scan_results["vulnerable"] = True
        self.scan_results["vulnerabilities"].append(vulnerability)
        
        source = "URL parameter" if form_index is None else f"Form #{form_index+1}"
        logging.warning(f"SSRF vulnerability found in {source}, parameter: {param}, payload: {payload}")
