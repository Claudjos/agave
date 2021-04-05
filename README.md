# Agave

## About
Collection of scripts working with raw socket. Written for self education on common protocols of link and network layers. Transportation and application layers protocols, and their vulnerabilities, will be examined in a different repository.

Efficiency and best practices are out of the scope of this repository. This are "learn by doing" scripts gathered together.

## Disclaimer
The author is not responsible for the use of this software. This code is shared for educational purpose.

## Requirements
- Linux, for these scripts use raw socket.
- SUDO privileges, for the very same reason.

## Usage

### ARP

#### Passive hosts discovery
Listen for ARP messages, collecting data on the host in the network.
```
python3 -m agave arp listen
```

#### Active hosts discovery
Sends ARP requests to all the IP addresses in a given subnet to solicit replies in order to discover hosts.
```
# Start listening for messages
python3 -m agave arp listen
# Change terminal
python3 -m agave arp solicit {interface} {subnet} {your_ip} {your_mac}
# Example with arguments
python3 -m agave arp solicit wlp3s0 192.168.1.0/24 192.168.1.100 aa:bb:cc:11:22:33
```

#### Man in the middle
Sends ARP messages in order to achieve a man in the middle attack.
```
# Assuming we want to intercept Bob and Alice
python3 -m agave arp mitm {interface} {your_ip} {alice_mac} {alice_ip} {bob_mac} {bob_ip}
# Example with arguments
python3 -m agave arp mitm wlp3s0 aa:bb:cc:11:22:33 aa:bb:cc:44:55:66 192.168.1.10 aa:bb:cc:77:88:99 192.168.1.1
```
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


## TODOs
- IRDP spoofing
- MAC flooding
- port stealing
- move the package frame in its own repository (?)
