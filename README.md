# webserver_audit 
#### Security Scanner for you AI_tools

### Version Note

- Light Version (scanner.py): A simple and fast security scan with basic features such as Directory Traversal, XSS, SQL Injection, and Port Scanning. Ideal for quick tests.
- Advanced Version (v2.py): Includes additional features like API security checks, directory brute-forcing, CSRF scanning, and much more. This version is optimized for more comprehensive security assessments and modern scenarios.

This tool includes the following features:
- Directory Traversal Check
- XSS Vulnerability Check
- SQL Injection Check
- Port Scanning
- HTTP Security Headers Check
- SSL/TLS Configuration Check

- Install required dependencies:
```bash
pip install requests colorama
```

Run

```
python scanner.py  http://example.com
```

Run full assessment (including port scan and SSL check):
```bash
python scanner.py  https://example.com --full
```


##########





1. **API Security Checks** (`--api` flag):
- Insecure HTTP methods detection
- Excessive data exposure testing
- Basic rate limiting checks
- Parameter manipulation tests

2. **Brute-force Detection** (`--brute` flag):
- Common directory/file enumeration
- Custom wordlist support
- Response code analysis
- Common config file detection

3. **CSRF Vulnerability Checking** (`--csrf` flag):
- Missing CSRF token detection
- CORS misconfiguration checks
- SameSite cookie attribute verification
- Form action analysis

Usage Examples:

1. Full AI API security audit:
```bash
python scanner.py https://ai-app.com/api --full --wordlist api_words.txt
```

2. Targeted checks:
```bash
python scanner.py https://ai-app.com/api --api --csrf
```

3. Custom directory brute-forcing:
```bash
python scanner.py https://ai-app.com --brute --wordlist custom_words.txt
```

Important Enhancements for AI Applications:

1. **API Security**:
- Add JWT validation checks with `python-jose` library
- Implement OAuth token testing
- Add GraphQL introspection checks

2. **Brute-force Protection**:
- Add rate-limiting detection
- Implement intelligent throttling
- Add common AI model path detection (e.g., `/models`, `/inference`)

3. **CSRF/CORS**:
- Add pre-flight request testing
- Implement state-changing operation verification
- Add WebSocket CSRF checks

Required Dependencies:
```bash
pip install requests colorama beautifulsoup4
```

Key Security Considerations for AI Apps:

1. **Model Protection**:
- Add checks for unprotected model endpoints
- Test for training data leakage
- Verify model version access controls

2. **Data Sanitization**:
- Implement input validation checks
- Add output encoding verification
- Test for prompt injection vulnerabilities

3. **API Authentication**:
- Add JWT/cookie validation checks
- Test for missing authentication headers
- Verify scope-based access controls

This enhanced tool provides crucial checks for modern AI applications, focusing on API endpoints and web service security fundamentals. Always test in staging environments first and consider adding:

- Session management checks
- Webhook verification
- File upload validation
- Third-party dependency auditing

Remember to regularly update your wordlists and vulnerability patterns to keep pace with emerging AI-specific security challenges.

## Warning

This repository contains tools for basic security checks of webservers. **Unauthorized use of these tools is strictly prohibited.** They are intended solely for educational purposes and for use in authorized environments. 

By using these tools, you agree to take full responsibility for ensuring that your activities comply with applicable laws and regulations. Misusing these tools for malicious purposes may result in severe legal consequences.

Always obtain proper authorization before performing any security assessments.

## Credits 
[Mr.Chess](https://github.com/volkansah)
