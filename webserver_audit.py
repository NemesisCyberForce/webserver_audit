# By NFC Mr.Chess
import argparse
import requests
import socket
import ssl
from urllib.parse import urlparse
from colorama import Fore, init

# Initialize colorama
init(autoreset=True)

def print_status(message, color=Fore.WHITE):
    print(f"{color}[*] {message}")

def print_vulnerability(message):
    print(f"{Fore.RED}[!] VULNERABLE: {message}")

def print_success(message):
    print(f"{Fore.GREEN}[+] {message}")

def directory_traversal_check(url):
    test_paths = [
        "../../../../etc/passwd",
        "../etc/passwd",
        "%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd"
    ]
    
    for path in test_paths:
        test_url = f"{url}?file={path}"
        try:
            response = requests.get(test_url, timeout=5)
            if "root:" in response.text:
                print_vulnerability(f"Possible directory traversal vulnerability found at {test_url}")
                return
        except Exception as e:
            continue
    print_success("No obvious directory traversal vulnerabilities found")

def xss_check(url):
    test_payload = "<script>alert('XSS')</script>"
    test_url = f"{url}?search={test_payload}"
    
    try:
        response = requests.get(test_url, timeout=5)
        if test_payload in response.text:
            print_vulnerability(f"Possible XSS vulnerability found at {test_url}")
            return
    except Exception as e:
        pass
    print_success("No obvious reflected XSS vulnerabilities found")

def sql_injection_check(url):
    test_payloads = ["'", "1' OR '1'='1", "%27%20OR%201%3D1--"]
    
    for payload in test_payloads:
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if "error in your SQL syntax" in response.text.lower():
                print_vulnerability(f"Possible SQL injection vulnerability found at {test_url}")
                return
        except Exception as e:
            continue
    print_success("No obvious SQL injection vulnerabilities found")

def port_scanner(target, ports):
    parsed_url = urlparse(target)
    host = parsed_url.hostname
    
    print_status(f"Scanning ports on {host}")
    open_ports = []
    
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                    print_status(f"Port {port} is open", Fore.YELLOW)
        except Exception as e:
            continue
    
    if open_ports:
        print_vulnerability(f"Open ports found: {', '.join(map(str, open_ports))}")
    else:
        print_success("No unexpected open ports found")

def check_http_headers(url):
    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "X-XSS-Protection"
    ]
    
    try:
        response = requests.head(url, timeout=5)
        missing_headers = []
        
        for header in security_headers:
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers:
            print_vulnerability(f"Missing security headers: {', '.join(missing_headers)}")
        else:
            print_success("All important security headers present")
            
    except Exception as e:
        print_status(f"Error checking headers: {str(e)}", Fore.YELLOW)

def check_ssl_tls(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https":
        return
    
    host = parsed_url.hostname
    port = 443
    
    context = ssl.create_default_context()
    
    try:
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                
                # Check certificate expiration
                ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'
                expires = datetime.datetime.strptime(cert['notAfter'], ssl_date_fmt)
                if expires < datetime.datetime.now():
                    print_vulnerability("SSL certificate has expired")
                
                # Check protocol version
                if ssock.version() in ['TLSv1', 'TLSv1.1']:
                    print_vulnerability(f"Using insecure TLS version: {ssock.version()}")
                
    except Exception as e:
        print_status(f"SSL/TLS Error: {str(e)}", Fore.YELLOW)

def main():
    parser = argparse.ArgumentParser(description="Web Server Penetration Testing Tool")
    parser.add_argument("target", help="Target URL (e.g., http://example.com)")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[80, 443, 8080],
                        help="Ports to scan (default: 80, 443, 8080)")
    parser.add_argument("-f", "--full", action="store_true",
                        help="Perform full security assessment")
    
    args = parser.parse_args()
    
    if args.full:
        print_status("Performing full security assessment")
        directory_traversal_check(args.target)
        xss_check(args.target)
        sql_injection_check(args.target)
        port_scanner(args.target, args.ports)
        check_http_headers(args.target)
        check_ssl_tls(args.target)
    else:
        print_status("Running basic vulnerability checks")
        directory_traversal_check(args.target)
        xss_check(args.target)
        sql_injection_check(args.target)

if __name__ == "__main__":
    main()
