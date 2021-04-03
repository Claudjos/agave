# Agave

## About
Collection of scripts working with raw socket. Written for self education.

## Requirements
- Linux, for these scripts use raw socket.
- SUDO privileges, for the very same reason.

## Usage

### ARP

#### Passively scan network
Listen for ARP messages, collecting data on the host in the network.
```
python3 -m agave arp listen
```

#### Actively scan network
Sends ARP request to all the IP addresses in a given subnet to discover hosts.
```
# Start listening for messages
python3 -m agave arp listen
# Change terminal
python3 -m agave arp solicit {interface} {subnet} {your_ip} {your_mac}
python3 -m agave arp solicit wlp3s0 192.168.1.0/24 192.168.1.100 aa:bb:cc:11:22:33
```

## TODOs
- ARP mitm
- ICMP mitm
- ICMP scanner
- DNS mitm