# webserver_audit
This is a basic demonstration tool - real-world penetration testing requires more comprehensive checks!

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
python webserver_audit.py http://example.com
```

Run full assessment (including port scan and SSL check):
```bash
python webserver_audit.py https://example.com --full
```
