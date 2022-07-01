## **HackTheBox Cheatsheet**
### Table of Contents
- Enumeration
  - [Nmap](#nmap)
  - [AutoRecon](#autorecon)
  - [dig](#dig)
  - [dnsrecon](#dnsrecon)
  - ffuf
  - dirb
  - gobuster
  - dirsearch
  - sqlmap
  - WPScan
  - nikto
  - metasploit (auxiliary)
  - enum4linux
  - ldapsearch
  - smbclient
  - LinPEAS
  - WinPEAS
  - pspy
- Brute-force (Cracking)
  - JohnTheRipper
  - hashcat
  - Hydra
  - patator
- Reverse Shell
  - revshell.com
  - Python
  - PHP
  - netcat
  - bash
  - socat
  - metasploit (payload)
- File Transfer
  - wget
  - curl
  - netcat
  - openssl
  - powershell
  - powershell (Invoke-WebRequest)
  - certutil
- Port Forwarding
  - ssh
  - chisel
  - shootback (python)
  - gost
  - goproxy
### Contents
#### Nmap
TODO
#### AutoRecon
AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.\
Source: https://github.com/Tib3rius/AutoRecon
```
autorecon <IP> -o <output> # Save output to file
```
#### dig
dig is a flexible tool for interrogating DNS name servers.\
Source: https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns
```
# Zone Transfer
dig axfr @<IP>
dig axfr @<IP> <DOMAIN>
# More Info
dig ANY @<IP> <DOMAIN>     # Any information
dig A @<IP> <DOMAIN>       # Regular DNS request
dig AAAA @<IP> <DOMAIN>    # IPv6 DNS request
dig TXT @<IP> <DOMAIN>     # Information
dig MX @<IP> <DOMAIN>      # Emails related
dig NS @<IP> <DOMAIN>      # DNS that resolves that name
dig -x 192.168.0.2 @<IP>   # Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<IP> # Reverse IPv6 lookup
```
#### dnsrecon
DNSRecon is a Python script that provides the ability to perform: Check all NS Records for Zone Transfers. Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).\
Source: https://github.com/darkoperator/dnsrecon
```
dnsrecon -d <DOMAIN> -a -n <IP>                       # Zone Transfer
dnsrecon -D <SUBDOMAIN_WORDLIST> -d <DOMAIN> -n <IP>  # Brute-force subdomains
```
