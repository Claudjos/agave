from agave.frames import ethernet, arp
from agave.frames.core import Buffer
from ipaddress import ip_address, ip_network, IPv4Address
import socket
import time


def hosts(subnet, me: IPv4Address):
	for address in ip_network(subnet).hosts():
		if address != me:
			yield address
	return


def all_packet(subnet, sender_mac, sender_ipv4, broadcast, repeat=1):
	for _ in range(0, repeat):
		for address in hosts(subnet, sender_ipv4):
			yield arp.ARP.who_has(sender_mac, sender_ipv4, broadcast, address)
	return


def main(argv):
	if len(argv) < 4:
		print("Too few parameters")
	else:
		print("Sending ARP requests...")
		solicit(argv[0], argv[1], argv[2], argv[3])


def solicit(iface: str, subnet: str, ipv4: str, mac: str, send_interval = 0.01, repeat_solicit = 3):
	interface = (iface, 1)
	sender_mac = ethernet.str_to_mac(mac)
	sender_ipv4 = ip_address(ipv4)
	broadcast = b'\xff\xff\xff\xff\xff\xff'
	rawsocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
	for data in all_packet(subnet, sender_mac, sender_ipv4, broadcast, repeat_solicit):
		rawsocket.sendto(data, interface)
		time.sleep(send_interval)
