
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
