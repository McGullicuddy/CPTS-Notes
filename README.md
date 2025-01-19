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





