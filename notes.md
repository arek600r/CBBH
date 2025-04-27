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

