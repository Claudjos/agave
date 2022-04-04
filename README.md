# Agave

Agave aims to provide "primitives" to speed up the development of "proof of concept" and "capture the flag" security related scripts concerning networking. Efficiency and best practice are not the main goal, ease of reuse is.

It started as a collection of scripts shared to show some knowledge of networking to potential recruiters. Now is migrating towards a library to build customizable tools to combine together to enact more complex scenarios. Yet general purpose scripts are still included as they are both an "how to" guide of the library, and "primitives" themselves.

The main motivation behind the development of the project comes from the curiosity to learn more about network protocols and vulnerabilities. Agave is a byproduct of learning-by-doing.

## Usage of the CLI scripts

##### Requirements

To use raw socket:
- Linux (POSIX?)
- CAP_NET_RAW capability or SUDO privileges

Preferred system configuration:
```
# Enable IPv4 forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/conf/*/forwarding
# Prevents ICMPv4 redirect messages
echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects
```

### NIC

Retrieve network interfaces information.
```
python3 -m agave.nic.interfaces [interface]
python3 -m agave.nic.interfaces
python3 -m agave.nic.interfaces wlan0
```

### ARP

Retrieving link layer address(es). This allows host discovery as well by resolving addresses for subnets. Note that some host/switch might leak informations about other networks they are connected to. An interface name must me specified when no interface on the system is in the same network of the subnet being scanned.
```
python3 -m agave.arp.resolve <IP|subnet> [interface]
python3 -m agave.arp.resolve 192.168.0.1
python3 -m agave.arp.resolve 192.168.1.0/4
python3 -m agave.arp.resolve 192.168.2.1/32	eth0
python3 -m agave.arp.resolve 192.168.3.0/24	wlan0
```

Listening for incoming messages to discover hosts and interaction between them.
```
python3 -m agave.arp.listen
```

ARP Spoofing. The script replies to ARP requests with spoofed messages in order to redirect traffic for the target subnet to your host. The optional victim argument restricts spoofing to some hosts. With the option -f gratuitous spoofed replies are sent periodically to the victim.
```
python3 -m agave.arp.spoof <target> [victim] [-f]
python3 -m agave.arp.spoof 192.168.1.4
python3 -m agave.arp.spoof 192.168.1.4/2 192.168.1.1/32
python3 -m agave.arp.spoof 192.168.1.10/32 192.168.1.0/24 -f
```

Man in the middle using unsolicited spoofed ARP replies.
```
python3 -m agave.arp.mitm <interface> <alice> <bob>
python3 -m agave.arp.mitm eth0 192.168.1.1 192.168.1.5
```

### ICMPv4

Hosts discovery by sending echo requests.
```
python3 -m agave.icmp.discover <subnet>
python3 -m agave.icmp.discover 192.168.1.0/24
```
Redirecting traffic. Check the [source code](agave/icmp/redirect.py) for more details.
```
python3 -m agave.icmp.redirect <target> <attacker> <victim> <gateway> [delta] [trigger]
```
Example:
*victim* reaches a *target* host (Google DNS) through the router *gateway*. With an ICMP redirect message is possible to redirect the traffic to use another router (the *attacker*) instead.
```
python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1
```

### IRDP

Solicit routers advertise messages.
```
python3 -m agave.irdp.solicit
```
Advertise a list of routers.
```
python3 -m agave.irdp.advertise <preference> <router> [...[<preference> <router>]]
python3 -m agave.irdp.advertise 100 192.168.1.10
python3 -m agave.irdp.advertise 100 192.168.1.10 50 192.168.1.20
```
