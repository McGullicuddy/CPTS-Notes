# CPTS-Notes
Notes from my CPTS "Penetration Tester" Path

<br/><br/><br/><br/>

# Module 1: Penetration Testing Process

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
smbclient -U bob \\\\10.129.42.253\\users
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
There are many ways to do this, do the research. 

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


