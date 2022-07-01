## **HackTheBox Cheatsheet**
My personal HackTheBox Cheatsheet from any sources.
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
  - [WPScan](#wpscan)
  - [Nikto](#nikto)
  - [Metasploit (Auxiliary)](#metasploit-auxiliary)
  - [Enum4Linux](#enum4linux)
  - [LinPEAS](#linpeas)
  - [WinPEAS](#winpeas)
  - [pspy](#pspy)
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
  - Metasploit (Payload)
- File Transfer
  - wget
  - curl
  - netcat
  - openssl
  - PowerShell
  - PowerShell (Invoke-WebRequest)
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
sqlmap -u <URL> --dbs                                              # get a list of databases
sqlmap -u <URL> -D <DATABASE> --tables                             # get a list of tables on database
sqlmap -u <URL> -D <DATABASE> -T <TABLE> --columns                 # get a list of columns on table
sqlmap -u <URL> -D <DATABASE> -T <TABLE> -C <column,column> --dump # get contents of specified columns
```
```
sqlmap -u <URL> --os-shell                                        # get shell to run command on target
sqlmap -u <URL> --file=<FILE>                                     # read file on target
sqlmap -u <URL> --file-write=<LOCALFILE> --file-dest=<REMOTEPATH> # write file on target
sqlmap -u <URL> --sql-query=<SQLQUERY>                            # execute sql query
```
#### WPScan
WPScan scans remote WordPress installations to find security issues.\
Source: https://github.com/wpscanteam/wpscan
```
wpscan --url http://<IP/DOMAIN>/ # default scan (more info: wpscan -h/-hh)
```
#### Nikto
Nikto is a pluggable web server and CGI scanner written in Perl, using rfp’s LibWhisker to perform fast security or informational checks.\
Source: https://github.com/sullo/nikto
```
nikto -host http://<IP/DOMAIN>/
```
#### Metasploit Auxiliary
The Metasploit Framework includes hundreds of auxiliary modules that perform scanning, fuzzing, sniffing, and much more. Although these modules will not give you a shell, they are extremely valuable when conducting a penetration test.\
Source: https://www.offensive-security.com/metasploit-unleashed/auxiliary-module-reference/
```
# Example Usage
msf > use auxiliary/scanner/smb/smb_version
msf auxiliary(smb_version) > show options
Module options:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS                      yes       The target address range or CIDR identifier
   SMBDomain  WORKGROUP        no        The Windows domain to use for authentication
   SMBPass                     no        The password for the specified username
   SMBUser                     no        The username to authenticate as
   THREADS    1                yes       The number of concurrent threads

msf auxiliary(smb_version) > set RHOSTS <IP/IPs>
RHOSTS => <IP/IPs>
msf auxiliary(smb_version) > run
```
#### Enum4Linux
A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts.\
Source: https://github.com/CiscoCXSecurity/enum4linux
```
enum4linux <IP/DOMAIN>
```
#### LinPEAS
LinPEAS is a script that search for possible paths to escalate privileges on Linux/Unix*/MacOS hosts.\
Source: https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
```
remote:~$ ./linpeas.sh
```
#### WinPEAS
Check the Local Windows Privilege Escalation.\
Source: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
```
C:\Windows\Temp> .\winpeas.exe
```
#### pspy
pspy is a command line tool designed to snoop on processes without need for root permissions.\
Source: https://github.com/DominicBreuker/pspy
```
remote:~$ ./pspy64
```
