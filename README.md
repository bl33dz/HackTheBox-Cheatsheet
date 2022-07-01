## **HackTheBox Cheatsheet**
### Table of Contents
- Enumeration
  - [Nmap](#nmap)
  - [AutoRecon](#autorecon)
  - [dig](#dig)
  - [DNSRecon](#dnsrecon)
  - [ffuf](#ffuf)
  - [dirb](#dirb)
  - [Gobuster](#gobuster)
  - [dirsearch](#dirsearch)
  - [sqlmap](#sqlmap)
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
#### DNSRecon
DNSRecon is a Python script that provides the ability to perform: Check all NS Records for Zone Transfers. Enumerate General DNS Records for a given Domain (MX, SOA, NS, A, AAAA, SPF and TXT).\
Source: https://github.com/darkoperator/dnsrecon
```
dnsrecon -d <DOMAIN> -a -n <IP>                       # Zone Transfer
dnsrecon -D <WORDLIST> -d <DOMAIN> -n <IP>  # Brute-force subdomains
```
#### ffuf
A fast web fuzzer written in Go.\
Source: https://github.com/ffuf/ffuf
```
ffuf -w <WORDLIST> -u http://<IP/DOMAIN>/FUZZ                      # Directory discovery
ffuf -w <WORDLIST> -u http://<IP/DOMAIN>/ -H 'Host: FUZZ' -fs 4242 # Vhost discovery (-fs is default vhost response size)
ffuf -w <WORDLIST> -u http://<IP/DOMAIN>/index.php?FUZZ=1 -fs 4242 # GET parameter discovery
```
#### dirb
DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects. It basically works by launching a dictionary based attack against a web server and analyzing the responses.\
Source: http://dirb.sourceforge.net/
```
dirb http://<IP/DOMAIN>/ <WORDLIST>
```
#### Gobuster
Gobuster is a tool used to brute-force URIs including directories and files as well as DNS subdomains.\
Source: https://github.com/OJ/gobuster
```
gobuster dir -u https://<IP/DOMAIN> -w <WORDLIST>  # dir mode
gobuster dns -d <DOMAIN> -w <WORDLIST>             # dns mode
gobuster vhost -u http://<DOMAIN> -w <WORDLIST>    # vhost mode
```
#### dirsearch
An advanced command-line tool designed to brute force directories and files in webservers.\
Source: https://github.com/maurosoria/dirsearch
```
./dirsearch.py -u http://<IP/DOMAIN>                              # default
./dirsearch.py -e php,html,js -u http://<IP/DOMAIN>               # custom extension
./dirsearch.py -e php,html,js -u http://<IP/DOMAIN> -w <WORDLIST> # custom wordlist & extension
```
#### sqlmap
sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers.\
Source: https://sqlmap.org/
```
sqlmap -u '<URL>' --dbs                                              # get a list of databases
sqlmap -u '<URL>' -D <DATABASE> --tables                             # get a list of tables on database
sqlmap -u '<URL>' -D <DATABASE> -T <TABLE> --columns                 # get a list of columns on table
sqlmap -u '<URL>' -D <DATABASE> -T <TABLE> -C <column,column> --dump # get contents of specified columns
```
