# Module 2: Footprinting


### Enumeration Principles


![enum-method3](https://github.com/user-attachments/assets/d9df750a-a2d8-4040-abef-7f3286e97d8f)


### Domain Information


**Find Subdomains:** https://crt.sh/

**Certificate Transparancy:** RFC-6962 states that all digital certs issued by a CA must be logged as to detect false or malicious certs. Websites like the one above store this information for the public to query. Below are some commands to query domain certs.
```
curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
# Curl webpage and output as JSON


curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u
# Curl webpage and sort by uniqure sub domains


for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
# Search file for addresses with public IPs acessible from the internet

```

**Shodan:** We can plug this new information into shodan and
```
for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done

for i in $(cat ip-addresses.txt);do shodan host $i;done
# clip host and send ips to shodan via terminal "shodan" command

```

**Dig**
```
dig any [domain address]
# Interrogate DNS name servers

```

**Records**
```
A: Subdomains

MX: Mail Server Records

NS: Name Servers that are used to resolve the FQDN to IP addresses

TXT:Verification Keys
```


### Cloud Resources


**Google Dorking:** intext: and inurl:

**Domain Glass:** https://domain.glass/

**GrayHatWarfare:** https://buckets.grayhatwarfare.com/


### FTP


**TFTP Commands:** connect, get, put, quit, status, verbose, debug

**vsFTPd - "ftpusers":** Specifies what users are not permitted to use the FTP service

**vsFTPd Dangerous Settinga**
1. anonymous_enable=YES
2. anon_upload_enable=YES
3. anon_mkdir_write_enable=YES
4. no_anon_password=YES 	Do not ask anonymous for password?
5. anon_root=/home/username/ftp
6. write_enable=YES 	Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE?

**NMAP FTP Service**
```
# search for NSE scripts on your system

find / -type f -name ftp* 2>/dev/null | grep scripts

# Scan

sudo nmap -sV -p21 -sC -A 10.129.14.136

# Show scripts running

sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace

# If you need to connect to ftp server without ftp

nc -nv 10.129.14.136 21
telnet 10.129.14.136 21

#Run with openSSL if the ftp server you are connecting to is running with TLS/SSL
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```


### SMB


SMB handles file access across different computers. Samba allows SMB to communicate w UNIX. SMB typically operates on ports 137, 138, 139, while CIFS operates on 445.
NETBios was developed by IBM as an API that would lay the foundation for devices to connect and share data with eachother.

**Dangerous Settings**
1. browseable = yes 	Allow listing available shares in the current share?
2. read only = no 	Forbid the creation and modification of files?
3. writable = yes 	Allow users to create and modify files?
4. guest ok = yes 	Allow connecting to the service without using a password?
5. enable privileges = yes 	Honor privileges assigned to specific SID?
6. create mask = 0777 	What permissions must be assigned to the newly created files?
7. directory mask = 0777 	What permissions must be assigned to the newly created directories?
8. logon script = script.sh 	What script needs to be executed on the user's login?
9. magic script = script.sh 	Which script should be executed when the script gets closed?
10. magic output = script.out 	Where the output of the magic script needs to be stored?

**SMB Client Commands**
```
# List dirs using anon

smbclient -N -L //10.129.14.128


```

**Scan SMB**
```
# Version scan and default script scan, specify ports

sudo nmap 10.129.14.128 -sV -sC -p139,445
```

**RPC-Client**
Nmap has trouble collecting information from SMB services so you can use tools like RPC-Client as a means of manually inspecting them. This is a tool that is designed to perfom MS-RPC functions. An RPC is a remote procedure call which is a way of. Below are a list of commands we can use to interact with the SMB service via RPCClient
1. srvinfo -	Server information.
2. enumdomains -	Enumerate all domains that are deployed in the network.
3. querydominfo -	Provides domain, server, and user information of deployed domains.
4. netshareenumall -	Enumerates all available shares.
5. netsharegetinfo <share> - Provides information about a specific share.
6. enumdomusers -	Enumerates all domain users.
7. queryuser <RID> - Provides information about a specific user.

**rpcclient commands**
```
# Brute force queryuser RIDs 0 - 4095 (0x000 - 0xFFF).

for i in $(seq 0 1100); do rpcclient -N -U "" [ip] -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

# You can also use samrdump.py for this type of information gathering


#SMBmap, CrackMapExec, and enum4linux-ng are other tools to collect this same information
smbmap -H [ip]
crackmapexec smb [ip] --shares -u '' -p ''
```

### Network File System (NFS)


**NFS:** Based on Open Network Computing Remote Procedure Call (ONC-RPC/SUN-RPC) protocol exposed on TCP and UDP ports 111 and 2049

**Configure NFS:** NFS can be configured at /etc/exorts. Below are the options you can use.
1. rw - Read and write permissions.
2. ro - Read only permissions.
3. sync - Synchronous data transfer. (A bit slower)
4. async - Asynchronous data transfer. (A bit faster)
5. secure - Ports above 1024 will not be used.
6. insecure - Ports above 1024 will be used.
7. no_subtree_check - This option disables the checking of subdirectory trees.
8. root_squash 	- Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents root from accessing files on an NFS mount.
9. nohide
10. no_root_squash

**Scan**
```
# Basic service enum

sudo nmap -sV -sC [ip] -p 111,2049

# rpcinfo nse script

sudo nmap -sV --script nfs* [ip] -p 111,2049
```

**Mounting share:** Once you find a share you can mount it and view it with the following commands
```
# List shares you can mount

showmount -e 10.129.14.128

# Create dir and mount drive to that dir

mkdir target-NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
cd target-NFS
```

<br>

### DNS (Domain Name System) (Port 53)


<br>

**DNS Records:**
1. A - Returns an IPv4 address of the requested domain as a result.
2. AAAA - Returns an IPv6 address of the requested domain.
3. MX -	Returns the responsible mail servers as a result.
4. NS -	Returns the DNS servers (nameservers) of the domain.
5. TXT - This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam.
6. CNAME - This record serves as an alias for another domain name. If you want the domain www.hackthebox.eu to point to the same IP as hackthebox.eu, you would create an A record for hackthebox.eu and a
7. CNAME - record for www.hackthebox.eu.
8. PTR - The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.
9. SOA - Provides information about the corresponding DNS zone and email address of the administrative contact.

<br>

**Dig:** DNS Lookup Utility
```
dig soa nsa.gov
```

<br>

**DNS Configuration Files**
1. Local DNS config files
    1. Under the Linux Bind9 this file is named.conf/etc/bind/named.conf.local

3. Zone Files
    1. Text file that describes the DNS zone with the BIND file format.
    2. "BIND (Berkeley Internet Name Domain) is a free, open-source software package that translates domain names into IP addresses"
    3. Must be 1 SOA record, and at least one NS record.

5. Reverse Name Resolution Files
    1.  Needed in order for the IP address to be resolved by the FQDN

<br>

**Dangerous Settings**\
BIND9 CVE details: https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64
|Option | Description |
| --- | --- |
|allow-query | Defines which hosts are allowed to send requests to the DNS server |
|allow-recursion | Defines which hosts are allowed to send recursive requests to the DNS server |
|allow-transfer | Defines which hosts are allowed to receive zone transfers from the DNS server |
|zone-statistics | Collects statistical data of zones |


<br>

**Footprinting DNS**
```
# dig to find info on DNS server, NS finds the name servers, and @ specifies the ip of the server

dig ns [domain] @[ip]

# Potential to find the DNS servers version by using the chaos or "CH" request and searching for the TXT record

dig CH TXT [domain] [ip]

# Use ANY option to view all record

dig any [domain] [ip]

# Zone transfers

dig axfr [domain] [ip]
```

**Bruteforcing DNS**
```
# for subDomain in $(cat ~/secLists/Discovery/DNS/subdomains-top1million-110000.txt); do dig $sub.[domain] @[ip] | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

# DNSenum is also an option

dnsenum --dnsserver [ip] --enum -p 0 -s0 -o [fileName.txt] -f [secLists loction] [domain]
```

<br>

### SMTP


**SMTP Default Configuration**
```
cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"
```
**SMTP Commands**
1. AUTH PLAIN
2. HELO
3. MAIL FROM
4. RCPT TO
5. DATA
6. RSET
7. VRFY
8. EXPN: Client checks if mailbox is available
9. NOOP
10. QUIT

**Connect to SMTP Service**
```
telnet [ip] [port]

# Use VRFY to enumerate all users on service

VRFY root

#List of all SMTP server responses
https://serversmtp.com/smtp-error/
```

**Footprinting**
```
#nmap - nse script is smtp-commands and smtp-open-relay
sudo nmap [ip] -sC -sV -p 25
```
<br>

### IMAP 143/993 &  POP3 110/995


**IMAP Commands**
1. LOGIN username password
2. LIST "" *
3. CREATE "INBOX"
4. DELETE "INBOX"
5. RENAME
6. LSUB
7. SELECT INBOX / UNSELECT
8. FETCH, CLOSE, LOGOUT

**POP3 Commands**
1. USER username
2. PASS password
3. STAT, LIST
4. RETR id, DELE
5. CAPA, RSET, QUIT

**Footprinting**
```
sudo nmap [ip] -sV -p110,143,993,995 -sC

# If you know a users password you can curl email. Using -v can show you how the connection
# was established and

curl -k https://[ip] --user user:p4ssw0rd

# Use openssl to interact with the IMAP OR POP service

openssl s_client -connect [ip]:pop3s
openssl s_client -connect [ip]:IMAP
```


### SNMP


**Default Configuration**
```
cat /etc/snmp/snmpd.conf | grep -v "#" | sed -r '/^\s*$/d'
```


**Dangerous Settings**
1. rwuser auth
2. rqcommunity <community string> <ip>

**Footprinting**
```
# Tools: snmpwalk, onesixtyone, braa

# SNMPWALK - Find OIDs

snmpwalk -v2c -c public [ip]

# onesixtyone - find community string

onesixtyone -c [wordlist] [ip]

# use tools such as crunch to create custom word lists

#Combine the found community string with BRAA to brute-force OIDs
braa [community string]@[ip]1.3.6.*

```

<br>

### MySQL (3306)


**LAMP/LEMP**: Web servers conprised of the following
1. Linux, Apache, MySQL, PHP
2. Linux, Nginx, MySQL, PHP

**Footprinting**
```
sudo nmap [ip] -sV -sC -p 3306 --script mysql*

# Common MySQL Commands

1. mysql -u [user] -p [password] -h [ip]
2. show databases;
3. use database;
4. show tables;
5. show columns from table;
6. select * from table
7. select * from table where column = "string"
```
<br>

### MSSQL (Microsoft SQL) (1433)


**SSMS**: SQL Server Management Studio to manage MSSQL

**Tools to access MSSQL databases:**
1. mssql-cli
2. SQL server powershell
3. HeidiSQL
4. SQL Pro
5. mssqlclient.py

**Footprinting**
```
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 [ip]

# also you can use the Metasploit aux scanner named mssql_ping to gather some more information

# Connect to the service using the following command

 python3 mssqlclient.py username@host -windows-auth
```


### Oracle TNS


**Client Server**: server side uses listener.ora and client uses tnsnames.ora

**Tools to interact with Oracle service -- Script**
```
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```

```
# Verify odat install (Oracle Database Attacking Tool)

./odat.py -h
```


**Footprinting**
```
sudo nmap [ip] -p1521 -sV --open -oN nmap.txt

# Brute Force (nmap, hydra, odat)

sudo nmap [ip] -p1521 -sV --open --script oracle-sid-brute

#odat
./odat.py all -s [ip] > odat.txt

# connect to service

sqlplus user/pass@[ip]/XE

# Execute the following if you run into "sqlplus: error while loading"

sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```
<br>

## IPMI (Intelligent Platform Management Inferface) Port 623


**IPMI**: Allows for management of system hardware independantly of OS or BIOS. you can check up on temp, fan speeds, logs, even if the system is powered off. It is nearly equivilent to having physical access to the system.

**Footprinting**
```
sudo nmap -sU --script ipmi-version -p 623 [webaddress]

# metasploit module

aux/scanner/ipmi/ipmi_version

# Default passwords

  Dell: root calvin
  HP iLO: Administrator [randomized 8-character string consisting of numbers and uppercase letters]
  Supermicro: ADMIN ADMIN

# In the event of an HP iLO using a factory default password

hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u

# To retrieve IPMI hashes use the following MSF module

scanner/ipmi/ipmi_dumphashes
```
<br>

## Linux Remote Management Protocols


**SSH - Port 22**
```
# footprinting

sshaudit

# Change Auth Method

ssh -v cry0l1t3@[ip] -o PreferredAuthentications=password
```

**Rsync - Port 873**
```
# Remote copy tool


#Foortprinting
sudo nmap [ip] -sV -p 873

# Netcat

nc -nv [ip] 873

# Enumerate dirs

sudo rsync -av --list-only rsync://[ip]/[dir]
```

**R-Services - Port 512, 513,514**
```
# Suite of tolls that enable remote management over TCP/IP
# Unencrypted, MiTM

# Guide to R-Serivces command

https://csbygb.gitbook.io/pentips/networking-protocols-and-network-pentest/rservices

# Footprinting

sudo nmap [ip] -sV -p 512,513,514

# Commands

rwho, rlogin, rusers, rcp, rsh, rexec, rlogin, rstat, ruptime,
```

<br>


## Windows Remote Management Protocols


**RDP - 3389**
```
# Footprinting

sudo nmap [ip] -sC -sV -p3389 --script rdp*

# Perl script that can identify security settings of RDP

rdp-sec-check.pl
git clone https://github.com/CiscoCXSecurity/rdp-sec-check.git && cd rdp-sec-check
./rdp-sec-check.pl [ip]

# Connect from linux to RDP servers using

xfreerdp, rdesktop, remmina

# xfreerdp example connection

xfreerdp /u:username /p:"password" /v:[ip]
```

**WinRM - 5985(HTTP) 5986(HTTPS)**
```
# Windows Remote Management

# Windows remote shell is similar and can execute arbitrary commands on the remote system

# Footprinting

sudo nmap [ip] -sV -sC -p 5985,5986 --disable-arp-ping -n

# Powershell tool Test-WsMan can show remote servers that can be reached by WinRM

# On linux, evil-winr

sudo evil-winrm -i [ip] -u username -p password
```

**WMI - Windows Management Instrumentation - 135**
```
# If you can get access to WMI you can change almost any setting on the system

# Footprinting with wmiexec.py

../wmiexe.py username:password@[ip] "hostname"
```

## Additional Notes & Tips

- 💡 `theHarvester` supports multiple public sources; include `-b hackerone` for bug data.
- 🛰️ Remember passive DNS can reveal historical hosts that no longer resolve.
- 🛠️ Automate repeated OSINT searches with the `amass enum -passive` mode.
