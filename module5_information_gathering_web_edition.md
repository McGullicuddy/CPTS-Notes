## Information Gathering: Web Edition 

<br> 

### Introduction 
```
# Collecting Information about a targets Website / Web Application 
1. Idenfity Assest (Web Pages, Sub Domains, IPs)
2. Hidden Information (Backup Files, Config Files, Internal Documentation)
3. Attack Surface (Vulnerabilities)
4. Gather Intel (Personnel, emails, behaviour)
```

<br>

### WHOIS 
```
# Whosi is a giant database that maps domains to their owners
# Can help to identify Personnel, Network infrastructure, and Network Changes
# Tool like WhoisFreaks, tracks changes 

# Use Cases 
1. Look up sus email and help to determine the reputation of its sender
2. Lookup domain of a C2 server that malware is reaching out to 
3. Threat Intel report, gather info the target (take down history)
```


<br>

### DNS 
```
# Records
  A: Maps hostname to IPv4
  AAAA: Maps hostname to IPv6
  CNAME: Creates an alias for a hostname pointing to another host 
  MX: Mail Server hostname
  NS: Name servers hostnames 
  TXT: Text record storing arbitrary information 
  SOA: Administrative information 
  SRV: Hostname and port for specific services 
  PTR: Map ip to hostname (Reverse Lookup)

  IN / CH / HS: Specifies the internet protocol being using (Internet, Chaosnet, Hesiod)

# DNS Tools 
1. dig
2. Lookup
3. host 
4. dnsenum
5. fierce 
6. dnsrecon 
7. theHarvester
```
<br>

### Subdomains 
```
# Subdomains are represented by A records

# CNAME records might be used as well to create subdomain aliases

# Brute Force DNS 
1. dnsenum 
2. fierce
3. dnsrecon
4. amass 
5. assetfinder
6. puredns 
7. gobuster 
8. ffuf 

# Passive enumeration methods
1. Certificate Transparancy Logs 
2. SSL/TLS Certificates
3. Search Engines ("site:")

# dnsenum 
dnsenum --enum [domain] -f ~/seclists/Discovery/DNS/subdomains-top1million-110000.txt -r

# Zone Transfers is a copy of a domain and its subdomains to another NS as a means of     redundancy.
dig axfr [DNS Server] [domain]

```

<br>

### Virtual Hosts
```
# Discovery Tools: gobuster, feroxbuster, ffuf
gobuster vhost -u http://[ip] -w [wlist] --append-domain

# With gobuster -k will ignore ssl/tls cert errors 
```

<br>

### Certificate Transparancy Logs 
```
# TLS/SSL are required to maintain trust across the internet. Digital certificates are need to verfiy identity. Certificate Transparancy Logs are public ledgers of these issued certificates. 

# Searching CT Logs 
  1. crt.sh
  2. Censys 

# crt.sh API using Curl
curl -s "https://crt.sh/?q=[domain]&output=json" | jq -r '.[]
 | select(.name_value | contains("[sub doamin]")) | .name_value' | sort -u
```



<br>

### Fingerprinting 
```
# Gather information about the tech used to power a targets device

# Fingerprinting Techniques 
  1. Banner Grabbing
  2. HTTP Headers 
  3. Custom Responses 
  4. Page Content 

# Tools 
  1. Wappanalyzer 
  2. BuiltWith 
  3. Whatweb 
  4. Nmap
  5. Netcraft 
  6. wafw00f

# Banner Grabbing 
# I flag fetches only http headers 
  curl -I [domain]

# wafw00f
  wafw00f [domain]

# Nikto (-b is niktos software identification modules)
  nikto -h [domain] -Tuning -b 
```


<br>

### Crawling 
```
# Tools
  1. Burp Spider 
  2. ZAP
  3. Scrapy 
  4. Apache Nutch 
```

<br>

### Automating Recon 
```
# Recon Frameworks 
  1. FinalRecon: py based recon 
  2. Recon-ng 
  3. theHarvester 
  4. SpiderFoot
  5. OSINT Framework 
```
