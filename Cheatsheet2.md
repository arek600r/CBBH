# CBBH Cheatsheet

## 1. HTTP Basics
- HTTP methods: GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD
- Status codes:
  - 1xx: Informational
  - 2xx: Success (200 OK, 201 Created, 204 No Content)
  - 3xx: Redirection (301, 302, 307)
  - 4xx: Client Error (400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found)
  - 5xx: Server Error (500, 502, 503)
- Common headers: Host, User-Agent, Cookie, Authorization, Referer, Content-Type, Content-Length
- Cookies (Set-Cookie, HttpOnly, Secure, SameSite)

## 2. Burp Suite
- Proxy: Intercept requests, send to Repeater, Intruder, Decoder, Comparer.
- Repeater: Manual request manipulation.
- Intruder: Automated fuzzing/brute-force (positions: §).
- Target: View site map and endpoints.
- Decoder: Encode/decode data (Base64, URL, etc).

## 3. Information Gathering
- Enumerate subdomains: `amass`, `assetfinder`, `subfinder`
- Find endpoints:
  - robots.txt, sitemap.xml, JS files (with regex)
  - Dirsearch, Feroxbuster, ffuf, gobuster

## 4. Authentication
- Guess login fields (`admin:admin`, `admin:password`)
- Bypass methods: Case sensitivity, whitespace, SQLi, No Auth required
- Token analysis: JWT (header.payload.signature, base64), session cookies

## 5. File Upload
- Check for file type restrictions, magic bytes
- Common bypass: upload web shell (PHP: `GIF89a; <?php ... ?>`)
- File extension tricks: double extensions (shell.php.jpg), null byte (shell.php%00.jpg)

## 6. IDOR (Insecure Direct Object Reference)
- Change user/account/resource IDs in URLs, POST body, cookies
- Test sequential, random, UUID references

## 7. XSS
- Types: Reflected, Stored, DOM-based
- Basic payload: `<script>alert(1)</script>`
- Bypasses:
  - `<img src=x onerror=alert(1)>`
  - Use single/double quotes, event handlers
- Context: HTML, URL, JS, Attribute, CSS

## 8. CSRF
- Identify forms without CSRF tokens
- Craft CSRF PoC: auto-submitting forms (`<form>`, JS)
- Custom headers can prevent CSRF by requiring XMLHttpRequest

## 9. SSRF
- Parameters like `url=`, `path=`, `redirect=`
- Internal access: `http://localhost:8080`, `http://127.0.0.1`
- Protocol smuggling: `file://`, `gopher://`

## 10. SSTI
- Templates: Jinja2 (`{{7*7}}`), Twig, Velocity, etc
- Identify by injecting template syntax and seeing evaluation

## 11. Command Injection
- Payloads: `; whoami`, `&& whoami`, `| id`
- Use out-of-band (OOB) detection if command output isn’t visible

## 12. SQL Injection
- Basic test: `' or 1=1--`
- Enumerate: `' UNION SELECT NULL, NULL--`
- Error-based, blind, time-based (e.g. `SLEEP(5)`)
- Tools: sqlmap

## 13. XXE (XML External Entity)
- Payload:
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>
```
    Exploit file read, SSRF via XML parsers

## 14. Path Traversal

    Payloads: ../../../../etc/passwd
    URL encoding: %2e%2e/

## 15. Local File Inclusion (LFI)

    Test: ?file=../../../../etc/passwd
    Null byte: %00
    Log poisoning

## 16. Open Redirect

    Parameter: redirect=, url=
    Test with https://evil.com

## 17. Security Headers

    X-Frame-Options, X-XSS-Protection, Content-Security-Policy (CSP), Strict-Transport-Security

## 18. Password Reset Issues

    Insecure reset tokens, predictable URLs, no invalidation of previous tokens

## 19. Tools & Quick Commands

    Get IPs: nslookup, dig
    Enumerate: nmap -A target, whatweb target
    Fuzz: ffuf -u http://site/FUZZ -w wordlist.txt
    Download: curl -O URL, wget URL
    Proxy: use Burp Suite or export http_proxy=http://127.0.0.1:8080

## 20. Reporting & Responsible Disclosure

    Minimal valid PoC with explanation
    Clearly describe impact, affected endpoint, and how to reproduce
