# Server-Side Attacks – CBBH Core Cheat Sheet

---

## **Client-Side vs Server-Side**
- **Client-side:** Impacts users (e.g., XSS, CSRF), exploits the browser.
- **Server-side:** Impacts the **server** directly (e.g., SSRF, SSTI, SSI, XSLT), can lead to RCE, data leaks, lateral movement.

---

## 1. **Server-Side Request Forgery (SSRF)**
- **What is it?** App makes HTTP requests using user input without validation.
- **What can you do?**
    - Access internal web services (`127.0.0.1`, `localhost`, `169.254.169.254` for cloud metadata).
    - Bypass firewall restrictions.
    - Exfiltrate data or scan internal network.
- **Test:** Try URLs like:
    - `http://localhost/`, `http://127.0.0.1/`, `http://<internal-ip>/`, `file:///etc/passwd`
    - OOB: Use your **Burp Collaborator/interact.sh** domain.
- **Obfuscations:** `127.1`, IPv6, DNS rebinding, URL encoding, etc.

---

## 2. **Server-Side Template Injection (SSTI)**
- **What is it?** User input is processed by a server-side template engine.
- **What can you do?**
    - Inject template expressions to dump variables, execute code.
- **Test:** 
    - Common payloads:
        - `{{7*7}}`, `${7*7}`, `#{7*7}`, `{{config}}`, `${T(java.lang.Runtime).getRuntime().exec('id')}`
    - **Echo?**—Template engine is vulnerable.
    - Try different syntax to discover backend (`Jinja2`, `Twig`, `Velocity`, `Freemarker`, etc.).
- **Goal:** Achieve code execution or data access via template injection.

---

## 3. **Server-Side Includes (SSI) Injection**
- **What is it?** App includes/merges code/content based on user input in `<!--#...-->` directives.
- **What can you do?**
    - Inject SSI payloads for file read, code exec, env disclosure.
- **Test:** Upload files or send values like:
    - `<!--#exec cmd="id"-->`, `<!--#include file="/etc/passwd"-->`
    - See if output rendered unprocessed.

---

## 4. **XSLT Injection**
- **What is it?** App transforms XML using XSLT stylesheets which can be modified via user input.
- **What can you do?**
    - Inject XSLT functions for file read, SSRF, or code exec.
- **Test:** Upload/submit XSLT with:
    - `<xsl:value-of select="document('/etc/passwd')"/>`
    - XSLT allows out-of-band data/payloads in advanced cases.

---

## **Quick Checklist**
- Always send test payloads to input fields, upload forms, and API params suspected to hit backend logic.
- Fuzz for known string patterns (`{{7*7}}`, `<!--#exec-->`, etc.).
- If blind, watch for delays, OOB (out-of-band) interactions, or error messages for clues.
- Log every server response and look for new/different behaviors.

---

**Preparation Tips:**
- Preload common exploit payloads for SSRF, SSTI, SSI, and XSLT.
- Automate OOB discoveries with Burp & Collaborator/interact.sh.
- Know at least 2-3 payload patterns for each attack class for fast application.

---

**References:**
- [PayloadsAllTheThings - Server Side](https://github.com/swisskyrepo/PayloadsAllTheThings#server-side)
- [HackTricks - SSRF, SSTI, SSI, XSLT](https://book.hacktricks.xyz/)