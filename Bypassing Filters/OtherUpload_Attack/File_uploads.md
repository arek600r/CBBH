# Limited File Uploads

Certain file types, like SVG, HTML, XML, and even some image and document files, may allow us to introduce new vulnerabilities to the web application by uploading malicious versions of these files.

# File Upload – XSS, XXE, DoS Cheat Sheet

---

## 1. **Stored XSS via File Upload**
- **HTML files**: Upload with embedded `<script>` or `<img onerror=...>` for persistent XSS. If the app serves uploaded HTML, code will execute on victims.
- **Image metadata**: Inject XSS payloads using `exiftool`:
    ```
    exiftool -Comment='"><img src=1 onerror=alert(1)>' image.jpg
    ```
    - If the app displays image metadata, XSS will trigger.
- **MIME-type tricks**: Rename image to `.html` or change content-type to `text/html` to run JS.
- **SVG files**: SVGs support embedded JS:
    ```xml
    <svg><script>alert(1)</script></svg>
    ```
    - When rendered, XSS will trigger.

---

## 2. **XXE via File Upload**
- **SVG/Other XML-supporting files**: Add XXE payload to leak files:
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg>&xxe;</svg>
    ```
    - Viewing the file leaks sensitive content.
- **Read PHP code (for whitebox)**:
    ```xml
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
    <svg>&xxe;</svg>
    ```
    - Decode base64 from app’s response to get source code.
- **Other files**: DOCX, PPTX, PDF also have XML inside—XXE possible if the backend parses them!

---

## 3. **SSRF via File Upload/XXE**
- XXE can be used to force backend to fetch internal resources via entities.
- Good for internal port scans or extracting data from private endpoints.

---

## 4. **Denial of Service (DoS) via Upload**
- **XXE bombs**: Billion Laughs or similar can use resources and crash the server.
- **Decompression bombs**: Malicious ZIP archives containing recursively nested ZIPs.
- **Pixel floods**: Create images with enormous dimensions in the file header, e.g. (65535x65535 px) but minimal actual data—can crash web image processors.
- **Huge files**: Upload extremely large files to fill up disk/quota or crash parsing libraries.
- **Directory traversal uploads**: `../../.../etc/passwd` as filename may cause system issues if not sanitized.

---

## **Quick Actions**
- Always try uploading HTML, SVG, and modified metadata images for XSS/XXE.
- For each uploaded file, check:
    - How it is served? (raw, rendered)
    - Can you access it, and trigger JS/XXE?
- If upload fails, try MIME/type/extension tricks.
- Monitor app behavior with large/complex files for DoS potential.

---

**Tip:** Automate metadata and SVG payload generation, keep a payload bank, and always test all file-related attack surfaces!

---
---

# Other File Upload Attacks – CBBH Practical Notes

---

## 1. **Payload Injection in File Name**
- **Command Injection:** Use payloads like `test$(id).jpg`, ``test`id`.jpg``, `test.jpg|id`, or `test.jpg&&whoami` for RCE when files are handled by OS commands.
    - **Test:** Did you trigger unintended command execution?
- **XSS in File Name:** `<script>alert(1)</script>.jpg` – If the filename is reflected, XSS may trigger.
- **SQL Injection:** `test';SELECT+sleep(5);--.jpg` – If filename reaches unsafe SQL queries.

---

## 2. **Finding the Upload Directory**
- **Fuzz Common Paths:** Use tools like `ffuf` or `gobuster` to find directories: `/uploads/`, `/files/`, `/images/`, etc.
- **LFI/XXE:** Use inclusion or XML disclosure to read source and locate the real path and naming scheme.
- **Error Disclosure:** 
  - Re-upload a file with same name/large name/invalid chars/reserved names to trigger error messages revealing full upload path.
  - Examples: overly long filenames, special chars, DOS names.
    - E.g., Windows reserved: `CON.jpg`, `LPT1.pdf`, `NUL.png`.
    - Might see error: "Cannot write to .../uploads/CON.jpg"

---

## 3. **Windows-Specific Techniques**
- **Reserved Characters:** Try `<`, `>`, `|`, `*`, `?` — if unsanitized, may cause revealing error or unexpected behavior.
- **Reserved Names:** Upload files named `CON`, `PRN`, `AUX`, `COM1`, `LPT1`, etc. to generate errors or maybe overwrite important files.
- **8.3 Short Names:** Use tildes, e.g., `HAC~1.TXT`, `WEB~1.CONF` to overwrite real files if backend creates short/legacy names.

---

## 4. **Triggering Error-Based Information Disclosure**
- **Filename collision:** Upload same file twice/rapidly/parallel.
- **Long name or invalid char:** Crash/overflow buffer and cause the backend to leak real file path.
- **Script:** Oskryptuj batch error upload attempts with weird names/chars to automate info disclosure tests.

---

## 5. **Abusing Automatic Processing**
- **Chained attacks:** Does the app process/convert/resize/scan uploads?
    - **ffmpeg**: XXE in malformed AVI/video files.
    - **ImageMagick (ImageTragick):** Exploit image processors with polyglots (`img.jpg;COMMAND` payload).
    - **Antivirus or other scanners:** Try EICAR string or malformed payloads.
- **Advanced:** Review used libraries in response headers or error strings, search for known CVEs.

---

## 6. **General Pro Tips**
- Always try payloads in both content and filename.
- Try with/without extensions, with valid/invalid mimetype, and combined/obfuscated forms.
- Script/fuzz everything: file names, parameters, paths, compression levels.
- Log & compare all error responses for info disclosure clues.
- For **CBBH exam**, always check for:
    - Path disclosure in errors
    - Unquoted use of filename (command injection)
    - Reflection (filename XSS)
    - Windows quirks (reserved/8.3/invalid chars)
    - Automatic processing chains (identify tools, fingerprint conversions, test polyglots)
- Keep ready lists of: weird filenames, reserved names, file type variations, and polyglots.

---

**Reference:**  
PayloadsAllTheThings: [Upload Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Upload%20Injections)

---

**Automation Tip:**  
Pre-script file batch uploads with Burp/ffuf/curl using combinations of:
- Filename-based payloads
- Metadata injections
- Different file types (image, docx, svg, zip, video, etc.)
to maximize finding hidden exploitation surfaces.
