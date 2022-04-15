# Agave

Agave aims to provide "primitives" to speed up the development of "proof of concept" and "capture the flag" security related scripts concerning networking. Efficiency and best practice are not the main goal, ease of reuse is.

It started as a collection of scripts shared to show some knowledge of networking to potential recruiters. Now is migrating towards a library to build customizable tools to combine together to enact more complex scenarios. Yet general purpose scripts are still included as they are both an "how to" guide of the library, and "primitives" themselves.

The main motivation behind the development of the project comes from the curiosity to learn more about network protocols and vulnerabilities. Agave is a byproduct of learning-by-doing.

## Note/TODOs
At the moment the main goal is to add new models for protocols to the package *core*.
For each protocol I'm adding some PoC scripts, but I don't know what to do with them yet.

## Examples

#### Working with PCAP Next Generation
```
from agave.utils.pcapng import StreamLoader, StreamDumper
from agave.core.pcapng import LINKTYPE_ETHERNET

with StreamDumper.from_file("test.pcapng") as dumper:
	dumper.start_section()
	dumper.add_interface("eth0", linktype=LINKTYPE_ETHERNET, snaplen=4096)
	dumper.edump("eth0", b'\x00.....', comment="Test!")
	...

with StreamLoader.from_file("test.pcapng") as loader:
	for interface, data in loader.stream_section():
		print(interface, data)
		...

```

## Usage of the PoC scripts

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
python3 -m agave.utils.interfaces [interface]
python3 -m agave.utils.interfaces
python3 -m agave.utils.interfaces wlan0
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

Translating MAC address into IPv4 address. Note that RARP protocol is obsolete.
```
python3 -m agave.arp.reverse <mac> <interface>
python3 -m agave.arp.reverse aa:bb:cc:00:11:22 eth0
```

ARP Spoofing. The script replies to ARP requests with spoofed messages in order to redirect traffic for the target subnet to your host. The optional victim argument restricts spoofing to some hosts. With the option -f gratuitous spoofed replies are sent periodically to the victim.
```
python3 -m agave.arp.spoof <target> [victim] [-f]
python3 -m agave.arp.spoof 192.168.1.4
python3 -m agave.arp.spoof 192.168.1.4/2 192.168.1.1/32
python3 -m agave.arp.spoof 192.168.1.10/32 192.168.1.0/24 -f
```

MITM. Man in the middle using ARP spoofing. With the option -f gratuitous spoofed replies are sent periodically to the victim.
```
python3 -m agave.arp.mitm <alice> <bob> [-f]
python3 -m agave.arp.mitm 192.168.1.1 192.168.1.5
python3 -m agave.arp.mitm 192.168.1.1 192.168.1.5 -f
```

### ICMPv4

Ping sweep. Discovers hosts in a subnet by sending echo requests. Using the option -m is possible to obtain a list of host for which neither a reply or destination unreachable message was received.
```
python3 -m agave.icmp.ping <subnet> [-m]
python3 -m agave.icmp.ping 192.168.1.0/24
python3 -m agave.icmp.ping 192.168.1.1/24 -m
```

Obtaining a network mask. Note that these ICMP messages are deprecated, and might not be supported anymore.
```
python3 -m agave.icmp.mask <ip>
python3 -m agave.icmp.mask 192.168.1.1
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

Listing routers available on the network. 
```
python3 -m agave.irdp.solicit
```
Advertising a list of routers.
```
python3 -m agave.irdp.advertise <preference> <router> [...[<preference> <router>]]
python3 -m agave.irdp.advertise 100 192.168.1.10
python3 -m agave.irdp.advertise 100 192.168.1.10 50 192.168.1.20
```

### ICMPv6
Ping sweep.
```
python3 -m agave.icmpv6.ping <ip|subnet> [-m]
python3 -m agave.icmpv6.ping fe80::7ef9:33ff:feaa:bbcc
```

### NDP
Retrieving link layer address(es).
```
python3 -m agave.ndp.resolve <ip|subnet> [interface]
python3 -m agave.ndp.resolve fe80::7ef9:33ff:feaa:bbcc/128
```

Listing routers available on the network. 
```
python3 -m agave.ndp.routers <interface>
python3 -m agave.ndp.routers eth0
```

Advertising an interfaces as default router.
```
python3 -m agave.ndp.advertise <interface> [[prefix], ...]
python3 -m agave.ndp.advertise eth0
python3 -m agave.ndp.advertise eth0 2001:4860:4860::8888/128
```
