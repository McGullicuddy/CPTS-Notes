# Module 2: NMAP

### Host Discovery


nmap one liner to discover  active hosts in a subnet
```
sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5

# -sn specifies to not scan ports
# -oA ouputs the file in 3 mjaor formats you can use just -o here. This important as we can later use this list of hosts to run a scan later on
# You can specify an IP range by using this syntax (10.129.2.18-20) or specify multiple IPs by just listing them out
# This scanning tech uses ping, and will only work if the firewalls infront of the network allow for pings
# Use the --packet-trace to show all packets and the -PE flag to ensure that the ping requests are sent.
# --reason will display the reason for that result
# --disable-arp-ping
# -n to disable dns resolution

```
**Note:** Linux typically has a ttl aroudn 64 and Windows around 128

<br>

### Hosts and Port Scanning


1. By default nmap scans the top 1000 ports using the SYN scan "-sS" (SYN scan is only default when nmap is run as root due to socket permissions). When run without root the "-sT" TCP scan is the default.
2. "--top-ports" will scan the 10 most commonly used ports

**Check for OPEN TCP ports**
```
sudo nmap --open -p- host -T5
# T5 make go brooooooom

```

**Trace Packets**
```
sudo nmap host -p 21 --packet-trace -Pn -n --disable-arp-ping
```

**TCP Connect Scan:** Use the -sT flag to envoke a full TCP handshake against a port to see if it is open or not. Port is open if the scan receives a SYN-ACK and closed if it receives a RST. This scan is very loud, but also a good option when accuracy is the goal or when the situation calls for a more polite and mutal scan of the network, as to not disrupt or destroy and services.

**SYN Scan:** The SYN scan is more stealthy as it does not complete a full handshake and will be less likely to trigger log collection.

**Discover UDP Ports**
```
sudo nmap host -F -sU

# -sU for UDP ports
# -F for top 100 ports
# Due to nmap only sending out empty datagrams to the select UDP ports we will likely not get any responses


sudo nmap host -sU -Pn -n --disable-arp-ping --packet-trace -p 100 --reason
```

**-sV:** Get additonal available information about the service running on open ports

<br>


### Saving the Results


**Types of ouput formats:**
```
-oN == normal output

-oG == grepable format

-oX == XML format

-oA == all formats at once


Convert XML format to HTML to view in your browser for an easy to read summary
$ xsltproc target.xml -o target.html
```

<br>


### Service Enumeration


**Full Port Scan**
```
sudo nmap host -p- -sV

# Full range port scans can take some time, user SPACE BAR to have nmap show you the progress of the scan
# You can also use the option --stat-every=5s to have nmap update you in intervals

```

<br>

### Scripting


**Scan Example**
```
sudo nmap 10.129.2.28 -p 80 -sV --script vuln

# https://nmap.org/nsedoc/scripts/

```


<br>

### Scanning Performance


**Timeouts:** Set the time that nmap will wait until it receives a response from the target. Smaller numbers will speed up your scan. Default value is 100ms.
```
--min-RTT-timeout
```
\
**Retry Rate:** Set number of times nmap will try to resend a packet.
```
--max-retries 0
```
\
**Rate:** Specify the amount of packets to send at a time. Useful when you have permission and know the bandwidth / dont care about the target...
```
--min-rate 300
```

\

**Timing:** Specify how agressive you want the scan to be. There are presets for all of the other settings.
```
-T 0 / -T paranoid
-T 1 / -T sneaky
-T 2 / -T polite
-T 3 / -T normal
-T 4 / -T aggressive
-T 5 / -T insane

Exact figure can be found here: https://nmap.org/book/performance-timing-templates.html
```


<br>

### Firewall IDS IPS Evasion


** -sA v -sS:** sA can make it harder for firewalls and IDS/IPS to detect scans since it only sends ACK flags. Since the firewall cannot determine where the packet was created, it allows it through.

<br>

**Decoy and RND**
```
sudo nmap [ip] -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5

# -D has nmap generate random IP addresses and insert them into the packet header. These packets are sent along side your ip and make it hard for the router to detemine what to block.

# RND specify the number of address to generate (Your ip will have an index from 0-4)

```

**Testing firewall rule and OS Detection:**
```
sudo nmap [ip] -n -Pn -p445 -O

sudo nmap [ip] -n -Pn -p 445 -O -S [ip] -e tun0
```

**DNS Proxying:**
```
--dns-server
# Specify DNS servers with


--source-port
# Specify source port

```

## Additional Notes & Tips

- 💡 Use `nmap --reason` to see why a port state was decided (e.g., filtered).
- 🔬 Combine `-sV` with `--script vulners` for version detection plus CVE lookup.
- 🛠️ Try running a scan while capturing packets in Wireshark to visualize the handshake.
