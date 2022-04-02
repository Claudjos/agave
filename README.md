# Agave

Agave aims to provide "primitives" to speed up the development of "proof of work" and "capture the flag" security related scripts concerning networking. Efficiency and best practice are not the main goal, ease of reuse is.

It started as a collection of scripts shared to show some knowledge of networking to potential recruiters. Now is migrating towards a library to build customizable tools to combine together to enact more complex scenarios. Yet general purpose scripts are still included as they are both an "how to" guide of the library, and "primitives" themselves.

The main motivation behind the development of the project comes from the curiosity to learn more about network protocols and vulnerabilities. Agave is a byproduct of learning-by-doing.

## Usage of the CLI scripts
These scripts use raw socket, thus Linux and SUDO privileges are required to run them.

### NIC
```
# List all network interfaces.
python3 -m agave.nic.interfaces

# Print info for a network interface.
python3 -m agave.nic.interfaces <interface>
python3 -m agave.nic.interfaces wlan0
```

### ARP
```
# Resolve a MAC.
python3 -m agave.arp.resolve <IP>
python3 -m agave.arp.resolve 192.168.1.1

# Hosts discovery.
python3 -m agave.arp.discover <interface> [subnet]
python3 -m agave.arp.rdiscover <interface> [subnet]	# Slower version
python3 -m agave.arp.discover wlan0					# Search all the subnet
python3 -m agave.arp.discover wlan0 192.168.1.0/24	# Different subnet, or portion of it

# Listen incoming messages to discover hosts, and interaction between them.
python3 -m agave.arp.listen

# Man in the middle.
python3 -m agave.arp.mitm <interface> <alice> <bob>
python3 -m agave.arp.mitm eth0 192.168.1.1 192.168.1.5
```

##### Note on the Man in the middle
If working, you'll be able to sniff the traffic exchanged by the victims. In order to allow the victims to keep communicate with each other, you need to enable IP forwarding. Disable forwarding might be used to prevent communications.
```
# Set to 0 to stop forwarding
sudo sysctl net.ipv4.ip_forward=1
```
If working, you'll be able to see the poisoned entry in the ARP table. You'll probably notice two entries with the same MAC address. On Linux, you can check it with:
```
arp
```

### ICMP

#### Hosts discovery
```
python3 -m agave icmp discovery {subnet}
python3 -m agave icmp discovery 192.168.1.0/24
```

#### Host redirect
```
python3 -m agave icmp redirect {target} {attacker} {victim} {gateway}
```
Example: redirects 192.168.0.3's (victim) messages for Google server DNS (target) to 192.168.0.2 (attacker). 192.168.0.1 is the router the victim is gonna use to reach the target.
```
python3 -m agave icmp redirect 8.8.8.8 192.168.0.2 192.168.0.3 192.168.0.1
```
The command above is enough to get a couple of messages from the victim. But your system will not forward the messages to their destination, and will tell the victim to use another router to reach the destination instead. So you'll need also to:
```
# Enable forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/conf/*/forwarding
# Prevent your system from redirecting the victim back to the right router
echo 0 | sudo tee /proc/sys/net/ipv4/conf/*/send_redirects
```

### IRDP
I've never tried this one, I saw it and decided to implement it. I just know the messages format is correct (or at least it is for Wireshark).

#### Solicitation
You need to use a sniffer to listen for replies.
```
python3 -m agave.irdp.solicit
```

#### Advertise
General command to advertise a list of routers.
```
python3 -m agave.irdp.advertise {preference} {router_1_ip} ... {router_n_ip}
```
Example:
```
python3 -m agave.irdp.advertise 100 192.168.1.10 192.168.1.20
```
