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
