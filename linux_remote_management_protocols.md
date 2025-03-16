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

