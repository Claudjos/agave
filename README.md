# Agave

Agave aims to provide "primitives" to speed up the development of "proof of work" and "capture the flag" security related scripts concerning networking. Efficiency and best practice are not the main goal, ease of reuse is.

It started as a collection of scripts shared to show some knowledge of networking to potential recruiters. Now is migrating towards a library to build customizable tools to combine together to enact more complex scenarios. Yet general purpose scripts are still included as they are both an "how to" guide of the library, and "primitives" themselves.

The main motivation behind the development of the project comes from the curiosity to learn more about network protocols and vulnerabilities. Agave is a byproduct of learning-by-doing.

## Usage of the CLI scripts

##### Raw socket requirements:
- Linux (POSIX?)
- CAP_NET_RAW capability or SUDO privileges

### NIC

Retrieve network interfaces information.
```
python3 -m agave.nic.interfaces [interface]
python3 -m agave.nic.interfaces
python3 -m agave.nic.interfaces wlan0
```

### ARP

Retrieve link layer address.
```
python3 -m agave.arp.resolve <IP>
python3 -m agave.arp.resolve 192.168.1.1
```
Discover hosts in a subnet by sending ARP requests. Note that some host/switch might leak information about other subnets they are connected to.
```
python3 -m agave.arp.discover <interface> [subnet]
python3 -m agave.arp.rdiscover <interface> [subnet]	# Slower version
python3 -m agave.arp.discover wlan0					# Search all the subnet
python3 -m agave.arp.discover wlan0 192.168.1.0/24	# Different subnet, or portion of it
```
Listening for incoming messages to discover hosts and interaction between them.
```
python3 -m agave.arp.listen
```
Man in the middle using unsolicited spoofed ARP replies.
```
python3 -m agave.arp.mitm <interface> <alice> <bob>
python3 -m agave.arp.mitm eth0 192.168.1.1 192.168.1.5
```
If working, you'll be able to sniff the traffic exchanged by the victims. In order to allow the victims to keep communicate with each other, you need to enable IP forwarding. Disable forwarding might be used to prevent communications.
```
# Set to 0 to stop forwarding
sudo sysctl net.ipv4.ip_forward=1
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
# Enable forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/conf/*/forwarding
# Prevent your system from redirecting the victim back to the right router
echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects
# Send ICMP redirect
python3 -m agave.icmp.redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1
```

### IRDP

Solicit routers advertise messages.
```
python3 -m agave.irdp.solicit
```
Advertise a list of routers
```
python3 -m agave.irdp.advertise {preference} {router_1_ip} ... {router_n_ip}
python3 -m agave.irdp.advertise 100 192.168.1.10
python3 -m agave.irdp.advertise 100 192.168.1.10 192.168.1.20
```
