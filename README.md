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

